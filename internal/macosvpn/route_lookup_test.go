package macosvpn

import (
	"bytes"
	"context"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

const routeLookupFixture = `   route to: 10.2.3.4
destination: 10.0.0.0
       mask: 255.0.0.0
    gateway: 10.1.2.1
  interface: ppp7
      flags: <UP,GATEWAY,DONE,STATIC>
 recvpipe sendpipe ssthresh rtt,msec rttvar hopcount mtu expire
 0 0 0 0 0 0 1400 0
`

func TestRouteLookupParsesExplicitDestination(t *testing.T) {
	ip := netip.MustParseAddr("10.2.3.4")
	r, e := parseRouteLookup([]byte(routeLookupFixture), ip)
	if e != nil || r.Destination != ip || r.MatchedPrefix.String() != "10.0.0.0/8" || r.InterfaceName != "ppp7" || r.MTU != 1400 || r.InterfaceIndex != 0 {
		t.Fatal("目的路由结果错误")
	}
	// Locked metrics and a signed expiry are part of Apple's numeric format.
	s := strings.Replace(routeLookupFixture, "1400 0", "1400L -1", 1)
	if _, e := parseRouteLookup([]byte(s), ip); e != nil {
		t.Fatal(e)
	}
}
func TestRouteLookupIPv6DefaultAndDirectHost(t *testing.T) {
	s := `route to: 2001:db8::1234
destination: default
mask: ::
gateway: fe80::1%ppp7
interface: ppp7
flags: <UP,GATEWAY,DONE>
recvpipe sendpipe ssthresh rtt,msec rttvar hopcount mtu expire
0 0 0 0 0 0 1400 0
`
	r, e := parseRouteLookup([]byte(s), netip.MustParseAddr("2001:db8::1234"))
	if e != nil || r.MatchedPrefix.String() != "::/0" || r.Gateway.Zone() != "ppp7" {
		t.Fatal("IPv6解析错误")
	}
	s = strings.Replace(s, "destination: default\nmask: ::\ngateway: fe80::1%ppp7", "destination: 2001:db8::1234", 1)
	s = strings.Replace(s, "UP,GATEWAY,DONE", "UP,HOST,DONE", 1)
	if _, e := parseRouteLookup([]byte(s), netip.MustParseAddr("2001:db8::1234")); e != nil {
		t.Fatal(e)
	}
}
func TestRouteLookupRejectsIncompleteOrAmbiguousOutput(t *testing.T) {
	cases := []string{"", strings.Repeat("x", maxRouteLookupBytes+1), "route: writing to routing socket: not in table\n", strings.Replace(routeLookupFixture, "route to: 10.2.3.4", "route to: 10.2.3.5", 1), strings.Replace(routeLookupFixture, "mask: 255.0.0.0", "mask: 255.0.255.0", 1), strings.Replace(routeLookupFixture, "destination: 10.0.0.0", "destination: 11.0.0.0", 1), strings.Replace(routeLookupFixture, "gateway: 10.1.2.1", "gateway: target.example.test", 1), strings.Replace(routeLookupFixture, "interface: ppp7", "interface: ppp7\ninterface: en0", 1), strings.Replace(routeLookupFixture, "UP,GATEWAY,DONE,STATIC", "UP,GATEWAY,UNKNOWN", 1), strings.Replace(routeLookupFixture, "UP,GATEWAY,DONE,STATIC", "UP,UP,GATEWAY", 1), strings.Replace(routeLookupFixture, "1400 0", "1400", 1), routeLookupFixture + "unexpected: tail\n", strings.Replace(routeLookupFixture, "ppp7", "ppp7\x00", 1), strings.Replace(routeLookupFixture, "mask: 255.0.0.0\n", "", 1), strings.Replace(routeLookupFixture, "GATEWAY,", "", 1)}
	for i, s := range cases {
		if _, e := parseRouteLookup([]byte(s), netip.MustParseAddr("10.2.3.4")); e == nil {
			t.Fatalf("未拒绝样本%d", i)
		}
	}
}
func TestRouteLookupArgumentsAreFixedNumericAndUnscoped(t *testing.T) {
	for _, ip := range []netip.Addr{{}, netip.IPv4Unspecified(), netip.IPv6Unspecified(), netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("fe80::1%en0"), netip.MustParseAddr("fe80::1"), netip.MustParseAddr("224.0.0.1")} {
		if _, e := routeArgs(ip); e == nil {
			t.Fatal("接受含糊地址")
		}
	}
	a, e := routeArgs(netip.MustParseAddr("192.0.2.1"))
	if e != nil || !reflect.DeepEqual(a, []string{"-n", "get", "-inet", "192.0.2.1"}) {
		t.Fatal("命令参数可变")
	}
	a, e = routeArgs(netip.MustParseAddr("2001:db8::1"))
	if e != nil || !reflect.DeepEqual(a, []string{"-n", "get", "-inet6", "2001:db8::1"}) {
		t.Fatal("IPv6参数可变")
	}
}
func TestRouteLookupOutputBoundCannotBeBypassed(t *testing.T) {
	var b boundedRouteOutput
	_, e := io.Copy(&b, struct{ io.Reader }{bytes.NewReader(make([]byte, maxRouteLookupBytes+1))})
	if e == nil || !b.overflow || b.buffer.Len() > maxRouteLookupBytes {
		t.Fatal("输出上限被绕过")
	}
	if _, ok := any(&b).(io.ReaderFrom); ok {
		t.Fatal("暴露无界ReaderFrom")
	}
	var stderr routeStderr
	_, _ = stderr.Write([]byte("warning"))
	if !stderr.written {
		t.Fatal("忽略警告")
	}
}
func routeVerifyGeneration() GenerationEvidence {
	return GenerationEvidence{42, InterfaceEvidence{"service-id", "ppp7", 8, []netip.Addr{netip.MustParseAddr("10.1.2.3")}}}
}
func TestVerifyDestinationRoutesBindsIPv4AndIPv6WithoutWholePolicyClaim(t *testing.T) {
	ips := []netip.Addr{netip.MustParseAddr("10.2.3.4"), netip.MustParseAddr("2001:db8::1")}
	g := routeVerifyGeneration()
	calls := 0
	r, e := verifyDestinationRoutes(context.Background(), g, ips, func(_ context.Context, ip netip.Addr) (DestinationRouteObservation, error) {
		calls++
		return DestinationRouteObservation{Destination: ip, MatchedPrefix: netip.PrefixFrom(ip, ip.BitLen()), InterfaceName: "ppp7", InterfaceIndex: 8, Flags: 1}, nil
	})
	if e != nil || calls != 2 || !r.AllDestinationsMatch || r.CompletePolicyVerified {
		t.Fatal("未正确限定证明范围")
	}
	g.Interface.IPv4Addresses[0] = netip.MustParseAddr("192.0.2.1")
	if r.Generation.Interface.IPv4Addresses[0] == g.Interface.IPv4Addresses[0] {
		t.Fatal("代际别名")
	}
}
func TestVerifyDestinationRoutesRejectsBypassAndBadBatchBeforeCalls(t *testing.T) {
	ip := netip.MustParseAddr("10.2.3.4")
	for _, kind := range []string{"wrong-interface", "wrong-index", "reject", "blackhole", "condemned", "local", "down", "wrong-target", "wrong-prefix", "error"} {
		_, e := verifyDestinationRoutes(context.Background(), routeVerifyGeneration(), []netip.Addr{ip}, func(context.Context, netip.Addr) (DestinationRouteObservation, error) {
			r := DestinationRouteObservation{Destination: ip, MatchedPrefix: netip.MustParsePrefix("10.0.0.0/8"), InterfaceName: "ppp7", InterfaceIndex: 8, Flags: 1}
			switch kind {
			case "wrong-interface":
				r.InterfaceName = "en0"
			case "wrong-index":
				r.InterfaceIndex = 9
			case "reject":
				r.Flags |= 8
			case "blackhole":
				r.Flags |= 4096
			case "condemned":
				r.Flags |= 33554432
			case "local":
				r.Flags |= 2097152
			case "down":
				r.Flags = 0
			case "wrong-target":
				r.Destination = netip.MustParseAddr("10.2.3.5")
			case "wrong-prefix":
				r.MatchedPrefix = netip.MustParsePrefix("192.0.2.0/24")
			case "error":
				return r, ErrRouteLookup
			}
			return r, nil
		})
		if e == nil {
			t.Fatalf("未拒绝%s", kind)
		}
	}
	for _, batch := range [][]netip.Addr{nil, {ip, ip}, {ip, {}}, make([]netip.Addr, 17)} {
		if _, e := verifyDestinationRoutes(context.Background(), routeVerifyGeneration(), batch, func(context.Context, netip.Addr) (DestinationRouteObservation, error) {
			t.Fatal("校验前调用系统")
			return DestinationRouteObservation{}, nil
		}); e == nil {
			t.Fatal("接受坏批次")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := verifyDestinationRoutes(ctx, routeVerifyGeneration(), []netip.Addr{ip}, nil); e == nil {
		t.Fatal("取消未阻止执行")
	}
}
