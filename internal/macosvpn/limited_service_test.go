package macosvpn

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mygo-vpn/internal/core"
)

func limitedFixture(t *testing.T) (*ExistingCoreAdapter, *fakeExistingOps, *limitedServiceVerification) {
	_, ops, selection := existingFixture(t)
	verification := &limitedServiceVerification{enabled: true, targets: []netip.Addr{netip.MustParseAddr("10.2.3.4")}, inspect: ops.inspect, interfaces: func() ([]net.Interface, error) { return nil, nil }, routes: func(context.Context) (KernelRouteReadback, error) { return KernelRouteReadback{}, nil }, lookup: func(_ context.Context, ip netip.Addr) (DestinationRouteObservation, error) {
		return DestinationRouteObservation{Destination: ip, MatchedPrefix: netip.MustParsePrefix("10.0.0.0/8"), InterfaceName: "ppp7", InterfaceIndex: 8, Flags: 1}, nil
	}}
	a := newLimitedExistingCoreAdapter(selection, existingConsent(), verification)
	a.poll = time.Hour
	a.stopTimeout = time.Second
	return a, ops, verification
}
func TestLimitedModeRequiresTargetsAndEachConsent(t *testing.T) {
	for _, targets := range [][]netip.Addr{nil, {}, {netip.MustParseAddr("127.0.0.1")}, {netip.MustParseAddr("10.2.3.4"), netip.MustParseAddr("10.2.3.4")}} {
		a, ops, v := limitedFixture(t)
		v.targets = targets
		if a.Capability().Available {
			t.Fatal("无效目标使模式可用")
		}
		if _, err := a.Start(context.Background(), a.profile, nil); err == nil || ops.starts.Load() != 0 {
			t.Fatal("无目标仍连接")
		}
	}
	for _, consent := range []ExistingServiceConsent{{}, {false, true, true, true}, {true, false, true, true}, {true, true, false, true}, {true, true, true, false}} {
		a, ops, _ := limitedFixture(t)
		a.consent = consent
		if _, err := a.Start(context.Background(), a.profile, nil); err == nil || ops.starts.Load() != 0 {
			t.Fatal("缺少一次性同意仍连接")
		}
	}
}
func TestLimitedModeProfileIsDetachedAndExplicit(t *testing.T) {
	a, ops, _ := limitedFixture(t)
	p, err := a.LimitedProfile()
	if err != nil || p.Protocol != core.ProtocolMacOSSystemL2TP || p.SystemService.ServiceID != "service-id" || a.VerificationScope() != core.SystemServiceTargetRoutes {
		t.Fatal("范围或配置未绑定")
	}
	if err := core.ValidateProfile(p); err != nil {
		t.Fatal(err)
	}
	p.SystemService.Targets[0] = "192.0.2.1"
	if _, err := a.Start(context.Background(), p, nil); err == nil || ops.starts.Load() != 0 {
		t.Fatal("修改目标未使绑定失效")
	}
	strict := NewExistingCoreAdapter(a.selection, a.consent, testNetworkPolicy())
	if strict.Capability().Available || strict.VerificationScope() != "" {
		t.Fatal("严格模式被暗中启用")
	}
}
func TestLimitedReadyRequiresFreshGenerationBracketingRoutes(t *testing.T) {
	a, ops, v := limitedFixture(t)
	var mu sync.Mutex
	var events []string
	mark := func(s string) { mu.Lock(); events = append(events, s); mu.Unlock() }
	ops.observation = func(_ context.Context, _ existingNativeSession, id string) (ServiceInspection, error) {
		mark("generation")
		return ServiceInspection{Configuration: cloneConfiguration(ops.config), Status: Connected, Generation: &GenerationEvidence{42, InterfaceEvidence{id, "ppp7", 8, []netip.Addr{netip.MustParseAddr("10.1.2.3")}}}}, nil
	}
	base := v.lookup
	v.lookup = func(ctx context.Context, ip netip.Addr) (DestinationRouteObservation, error) {
		mark("route")
		return base(ctx, ip)
	}
	session, err := a.Start(context.Background(), a.profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := awaitCoreResult(t, session.Ready()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]string(nil), events...)
	mu.Unlock()
	if !reflect.DeepEqual(got, []string{"generation", "generation", "route", "generation"}) {
		t.Fatalf("就绪未夹住新鲜代际：%v", got)
	}
	if session.(core.ScopedVerification).VerificationScope() != core.SystemServiceTargetRoutes {
		t.Fatal("会话缺少有限范围")
	}
	if err := session.Stop(); err != nil {
		t.Fatal(err)
	}
}
func TestLimitedGenerationDriftAfterRouteNeverReady(t *testing.T) {
	a, ops, _ := limitedFixture(t)
	calls := 0
	ops.observation = func(_ context.Context, _ existingNativeSession, id string) (ServiceInspection, error) {
		calls++
		stamp := int64(42)
		if calls >= 3 {
			stamp = 43
		}
		return ServiceInspection{Configuration: cloneConfiguration(ops.config), Status: Connected, Generation: &GenerationEvidence{stamp, InterfaceEvidence{id, "ppp7", 8, []netip.Addr{netip.MustParseAddr("10.1.2.3")}}}}, nil
	}
	s, err := a.Start(context.Background(), a.profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := awaitCoreResult(t, s.Ready()); err == nil {
		t.Fatal("代际漂移仍就绪")
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if ops.session.stops.Load() != 1 {
		t.Fatal("未撤销自身兴趣或重复撤销")
	}
}
func TestLimitedRouteLossStopsSession(t *testing.T) {
	a, ops, v := limitedFixture(t)
	a.poll = time.Millisecond
	var failed atomic.Bool
	base := v.lookup
	v.lookup = func(ctx context.Context, ip netip.Addr) (DestinationRouteObservation, error) {
		r, e := base(ctx, ip)
		if failed.Load() {
			r.InterfaceName = "en0"
		}
		return r, e
	}
	s, err := a.Start(context.Background(), a.profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := awaitCoreResult(t, s.Ready()); err != nil {
		t.Fatal(err)
	}
	failed.Store(true)
	if err := awaitCoreResult(t, s.Done()); err == nil {
		t.Fatal("指定路由旁路未终止")
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if ops.session.stops.Load() != 1 {
		t.Fatal("错误清理次数")
	}
}
func TestLimitedCleanupRefusesInterfaceReuseAndRemainingRoutes(t *testing.T) {
	for _, kind := range []string{"same-name", "same-index", "route", "gateway-index", "scope", "zone", "service-active", "changed-config", "read-error"} {
		t.Run(kind, func(t *testing.T) {
			a, ops, v := limitedFixture(t)
			var dirty atomic.Bool
			dirty.Store(true)
			v.interfaces = func() ([]net.Interface, error) {
				if dirty.Load() {
					switch kind {
					case "same-name":
						return []net.Interface{{Index: 99, Name: "ppp7"}}, nil
					case "same-index":
						return []net.Interface{{Index: 8, Name: "other0"}}, nil
					case "read-error":
						return nil, errors.New("injected")
					}
				}
				return nil, nil
			}
			v.routes = func(context.Context) (KernelRouteReadback, error) {
				if dirty.Load() {
					r := KernelRouteRecord{Prefix: netip.MustParsePrefix("10.0.0.0/8"), InterfaceIndex: 99}
					switch kind {
					case "route":
						r.InterfaceIndex = 8
					case "gateway-index":
						r.GatewayInterfaceIndex = 8
					case "scope":
						r.ScopeInterfaceIndex = 8
					case "zone":
						r.GatewayZoneIndex = 8
					default:
						return KernelRouteReadback{}, nil
					}
					return KernelRouteReadback{Records: []KernelRouteRecord{r}}, nil
				}
				return KernelRouteReadback{}, nil
			}
			v.inspect = func(ctx context.Context, id string) (ServiceInspection, error) {
				r, e := ops.inspect(ctx, id)
				if dirty.Load() {
					if kind == "service-active" {
						r.Status = Connected
					}
					if kind == "changed-config" {
						r.Configuration.Gateway = "changed.example.test"
					}
				}
				return r, e
			}
			s, err := a.Start(context.Background(), a.profile, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := awaitCoreResult(t, s.Ready()); err != nil {
				t.Fatal(err)
			}
			if err := s.Stop(); err == nil {
				t.Fatal("有限清理未确认却成功")
			}
			dirty.Store(false)
			if err := s.Stop(); err != nil {
				t.Fatal(err)
			}
			if ops.session.stops.Load() != 1 {
				t.Fatal("清理重试重复释放兴趣")
			}
		})
	}
}

func TestLimitedCleanupRechecksServiceAfterRouteRead(t *testing.T) {
	for _, kind := range []string{"reconnect", "config-change", "second-pass-reconnect"} {
		t.Run(kind, func(t *testing.T) {
			a, ops, v := limitedFixture(t)
			var routeCalls atomic.Int32
			v.routes = func(context.Context) (KernelRouteReadback, error) {
				routeCalls.Add(1)
				return KernelRouteReadback{}, nil
			}
			v.inspect = func(ctx context.Context, id string) (ServiceInspection, error) {
				r, e := ops.inspect(ctx, id)
				threshold := int32(1)
				if kind == "second-pass-reconnect" {
					threshold = 2
				}
				if routeCalls.Load() >= threshold {
					if kind == "config-change" {
						r.Configuration.Gateway = "new.example.test"
					} else {
						r.Status = Connected
					}
				}
				return r, e
			}
			s, err := a.Start(context.Background(), a.profile, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := awaitCoreResult(t, s.Ready()); err != nil {
				t.Fatal(err)
			}
			if err := s.Stop(); err == nil {
				t.Fatal("路由检查期间服务变化被报告清理完成")
			}
			if routeCalls.Load() == 0 {
				t.Fatal("未覆盖路由读取后的变化")
			}
		})
	}
}
