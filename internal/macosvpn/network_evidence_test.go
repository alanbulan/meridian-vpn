package macosvpn

import (
	"context"
	"net/netip"
	"testing"
)

func networkEvidenceFixture() (KernelRouteReadback, DNSReadback) {
	return KernelRouteReadback{Records: []KernelRouteRecord{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Gateway: netip.MustParseAddr("10.1.1.1"), InterfaceIndex: 8, Flags: 1}}, Bytes: 128}, DNSReadback{Resolvers: []DNSResolverRecord{{Scope: "default", Nameservers: []netip.Addr{netip.MustParseAddr("10.0.0.53")}}}}
}
func TestNetworkReadbackTwoSamplesAndNoCleanupOverclaim(t *testing.T) {
	r, d := networkEvidenceFixture()
	reads := 0
	s, err := readNetworkPolicySnapshot(context.Background(), func(context.Context) (KernelRouteReadback, error) { reads++; return r, nil }, func(context.Context) (DNSReadback, error) { return d, nil })
	if err != nil || reads != 2 {
		t.Fatal("没有稳定独立读回")
	}
	result, err := CompareNetworkRestoration(s, s)
	if err != nil || !result.RepresentedRouteAndResolverStateEqual || result.CompleteCleanupVerified {
		t.Fatal("错误恢复声明")
	}
}
func TestNetworkReadbackDriftRejected(t *testing.T) {
	r, d := networkEvidenceFixture()
	calls := 0
	_, err := readNetworkPolicySnapshot(context.Background(), func(context.Context) (KernelRouteReadback, error) {
		calls++
		if calls == 2 {
			r.Records[0].InterfaceIndex++
		}
		return r, nil
	}, func(context.Context) (DNSReadback, error) { return d, nil })
	if err != ErrPolicyReadback {
		t.Fatal("观测漂移未拒绝")
	}
}
func TestNetworkEvidenceDoesNotTrustCallerFingerprint(t *testing.T) {
	r, d := networkEvidenceFixture()
	s, err := readNetworkPolicySnapshot(context.Background(), func(context.Context) (KernelRouteReadback, error) { return r, nil }, func(context.Context) (DNSReadback, error) { return d, nil })
	if err != nil {
		t.Fatal(err)
	}
	s.Routes.Records[0].InterfaceIndex++
	if _, err = CompareNetworkRestoration(s, s); err != ErrPolicyReadback {
		t.Fatal("快照修改未识别")
	}
}
func TestNetworkReadbackCancelledBeforeRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := readNetworkPolicySnapshot(ctx, func(context.Context) (KernelRouteReadback, error) {
		t.Fatal("取消仍读取")
		return KernelRouteReadback{}, nil
	}, func(context.Context) (DNSReadback, error) { t.Fatal("取消仍读取"); return DNSReadback{}, nil })
	if err != ErrPolicyReadback {
		t.Fatal(err)
	}
}
