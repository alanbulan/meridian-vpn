package macosvpn

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"runtime"
	"testing"
)

func TestRouteReadbackUnsupportedAndCancelled(t *testing.T) {
	if _, err := ReadKernelRoutes(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadKernelRoutes(ctx); err != context.Canceled {
		t.Fatal("cancelled read was not rejected")
	}
	if runtime.GOOS != "darwin" {
		if out, err := ReadKernelRoutes(context.Background()); err != ErrRouteReadback || out.Records != nil {
			t.Fatal("non-Darwin fabricated route evidence")
		}
	}
}

func TestRouteReadbackBoundedSysctl(t *testing.T) {
	for _, kind := range []string{"valid", "empty", "too-big", "probe-error", "read-error", "length-growth", "cancel-before", "cancel-after-probe", "cancel-after-read", "panic"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "cancel-before" {
				cancel()
			}
			calls := 0
			out, err := boundedRouteRIB(ctx, func(old []byte, length *uintptr) error {
				calls++
				if calls == 1 {
					if old != nil || *length != 0 {
						t.Fatal("probe was not read-only size query")
					}
					*length = 16
					switch kind {
					case "empty":
						*length = 0
					case "too-big":
						*length = MaxKernelRouteBytes + 1
					case "probe-error":
						return errors.New("private native detail")
					case "cancel-after-probe":
						cancel()
					case "panic":
						panic("private panic")
					}
					return nil
				}
				if calls != 2 || len(old) != 16 || *length != 16 {
					t.Fatal("unbounded retry/allocation")
				}
				copy(old, "captured")
				*length = 8
				switch kind {
				case "read-error":
					return errors.New("partial output")
				case "length-growth":
					*length = 17
				case "cancel-after-read":
					cancel()
				}
				return nil
			})
			if kind == "valid" {
				if err != nil || string(out) != "captured" || calls != 2 {
					t.Fatal("valid capture failed", err)
				}
			} else if kind == "empty" {
				if err != nil || len(out) != 0 || calls != 1 {
					t.Fatal("empty capture failed")
				}
			} else if err == nil || out != nil {
				t.Fatal("failure returned partial evidence")
			}
			if calls > 2 {
				t.Fatal("retried native read")
			}
		})
	}
	if _, err := boundedRouteRIB(nil, nil); err == nil {
		t.Fatal("nil boundary accepted")
	}
}

func routeTestSockaddr(ip string) []byte {
	a := netip.MustParseAddr(ip)
	if a.Is4() {
		b := make([]byte, 16)
		b[0], b[1] = 16, 2
		copy(b[4:8], a.AsSlice())
		return b
	}
	b := make([]byte, 28)
	b[0], b[1] = 28, 30
	copy(b[8:24], a.AsSlice())
	return b
}
func routeTestFrame(dst, gateway, mask []byte, flags uint32) []byte {
	n := 92 + len(dst) + len(gateway) + len(mask)
	b := make([]byte, n)
	binary.LittleEndian.PutUint16(b[:2], uint16(n))
	b[2], b[3] = 5, 4
	binary.LittleEndian.PutUint16(b[4:6], 7)
	binary.LittleEndian.PutUint32(b[8:12], flags)
	attrs := uint32(3)
	if mask != nil {
		attrs |= 4
	}
	binary.LittleEndian.PutUint32(b[12:16], attrs)
	off := 92
	for _, a := range [][]byte{dst, gateway, mask} {
		copy(b[off:], a)
		off += len(a)
	}
	return b
}

func TestRouteReadbackStrictFrames(t *testing.T) {
	base := routeTestFrame(routeTestSockaddr("10.0.0.0"), routeTestSockaddr("10.0.0.1"), routeTestSockaddr("255.0.0.0"), 3)
	for _, kind := range []string{"valid", "use-counter", "trailing", "short-header", "short-frame", "unknown-version", "unknown-type", "errno", "unknown-attr", "missing-gateway", "bad-destination", "bad-gateway", "short-sockaddr", "zero-dst", "short-mask", "empty-mask"} {
		t.Run(kind, func(t *testing.T) {
			b := append([]byte(nil), base...)
			switch kind {
			case "use-counter":
				binary.LittleEndian.PutUint32(b[28:32], 123)
			case "trailing":
				b = append(b, 0)
			case "short-header":
				b = b[:91]
			case "short-frame":
				b = b[:len(b)-1]
			case "unknown-version":
				b[2] = 99
			case "unknown-type":
				b[3] = 1
			case "errno":
				b[24] = 1
			case "unknown-attr":
				b[13] = 1
			case "missing-gateway":
				b[12] &= ^byte(2)
			case "bad-destination":
				b[93] = 18
			case "bad-gateway":
				b[109] = 30
			case "short-sockaddr":
				b[92] = 255
			case "zero-dst":
				b[92] = 0
			case "short-mask":
				b = routeTestFrame(routeTestSockaddr("10.0.0.0"), routeTestSockaddr("10.0.0.1"), []byte{8, 0, 0, 0, 255, 0, 0, 0}, 3)
			case "empty-mask":
				b = routeTestFrame(routeTestSockaddr("0.0.0.0"), routeTestSockaddr("10.0.0.1"), []byte{0, 0, 0, 0}, 3)
			}
			n, err := validateDarwinRouteFrames(b)
			valid := kind == "valid" || kind == "use-counter" || kind == "short-mask" || kind == "empty-mask"
			if valid && (err != nil || n != 1) || !valid && err == nil {
				t.Fatalf("validation mismatch: %d %v", n, err)
			}
		})
	}
	if n, err := validateDarwinRouteFrames(nil); err != nil || n != 0 {
		t.Fatal("empty RIB")
	}
	if _, err := validateDarwinRouteFrames(make([]byte, MaxKernelRouteBytes+1)); err == nil {
		t.Fatal("byte bound")
	}
	tooMany := make([]byte, 0, len(base)*(MaxKernelRouteRecords+1))
	for i := 0; i <= MaxKernelRouteRecords; i++ {
		tooMany = append(tooMany, base...)
	}
	if _, err := validateDarwinRouteFrames(tooMany); err == nil {
		t.Fatal("record bound")
	}
}

func TestRouteReadbackNormalize(t *testing.T) {
	for _, v := range []struct {
		dst, mask, gw, want string
		flags               uint32
		link                bool
		zone                uint32
	}{
		{"0.0.0.0", "0.0.0.0", "192.0.2.1", "0.0.0.0/0", 3, false, 0},
		{"10.0.0.0", "255.0.0.0", "", "10.0.0.0/8", 1, true, 0},
		{"192.0.2.1", "", "192.0.2.1", "192.0.2.1/32", 5, false, 0},
		{"::", "::", "fe80::1", "::/0", 0x1000003, false, 7},
		{"2001:db8::", "ffff:ffff:ffff:ffff::", "", "2001:db8::/64", 1, true, 0},
		{"::1", "", "::1", "::1/128", 0x100c, false, 0},
	} {
		in := kernelRouteInput{destination: netip.MustParseAddr(v.dst), flags: v.flags, index: 7, linkGateway: v.link, gatewayZone: v.zone}
		if v.mask != "" {
			in.mask = netip.MustParseAddr(v.mask)
		}
		if v.gw != "" {
			in.gateway = netip.MustParseAddr(v.gw)
		}
		r, err := normalizeKernelRoute(in)
		if err != nil || r.Prefix.String() != v.want || r.Flags != v.flags || r.GatewayZoneIndex != v.zone {
			t.Fatalf("bad normalized route: %+v %v", r, err)
		}
		if v.flags&0x1000000 != 0 && r.ScopeInterfaceIndex != 7 {
			t.Fatal("scope lost")
		}
	}
	base := kernelRouteInput{destination: netip.MustParseAddr("10.0.0.0"), mask: netip.MustParseAddr("255.0.0.0"), gateway: netip.MustParseAddr("10.0.0.1"), index: 7, flags: 3}
	for _, kind := range []string{"missing-mask", "noncontiguous", "host-mask", "host-bits", "family", "mapped", "zero-index", "negative-link-index", "v4-zone", "link-with-ip"} {
		t.Run(kind, func(t *testing.T) {
			in := base
			switch kind {
			case "missing-mask":
				in.mask = netip.Addr{}
			case "noncontiguous":
				in.mask = netip.MustParseAddr("255.0.255.0")
			case "host-mask":
				in.flags |= 4
			case "host-bits":
				in.destination = netip.MustParseAddr("10.2.0.0")
			case "family":
				in.gateway = netip.MustParseAddr("::1")
			case "mapped":
				in.destination = netip.MustParseAddr("::ffff:10.0.0.0")
			case "zero-index":
				in.index = 0
			case "negative-link-index":
				in.linkGateway = true
				in.gateway = netip.Addr{}
				in.linkIndex = -1
			case "v4-zone":
				in.gatewayZone = 7
			case "link-with-ip":
				in.linkGateway = true
			}
			if _, err := normalizeKernelRoute(in); err == nil {
				t.Fatal("ambiguous route accepted")
			}
		})
	}
}
