package macosvpn

import (
	"context"
	"errors"
	"mygo-vpn/internal/core"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakePolicyVerifier struct {
	enabled                         bool
	captureFn                       func(context.Context) (policyBaseline, error)
	activeFn                        func(context.Context) error
	restoreFn                       func(context.Context) error
	captures, activeCalls, restores atomic.Int32
}

func (f *fakePolicyVerifier) available() bool { return f.enabled }
func (f *fakePolicyVerifier) capture(ctx context.Context, _ ExistingNetworkPolicy) (policyBaseline, error) {
	f.captures.Add(1)
	if f.captureFn != nil {
		return f.captureFn(ctx)
	}
	return policyBaseline{1}, nil
}
func (f *fakePolicyVerifier) active(ctx context.Context, _ policyBaseline, _ GenerationEvidence, _ ExistingNetworkPolicy) error {
	f.activeCalls.Add(1)
	if f.activeFn != nil {
		return f.activeFn(ctx)
	}
	return nil
}
func (f *fakePolicyVerifier) restored(ctx context.Context, _ policyBaseline, _ *GenerationEvidence, _ ExistingNetworkPolicy) error {
	f.restores.Add(1)
	if f.restoreFn != nil {
		return f.restoreFn(ctx)
	}
	return nil
}
func testNetworkPolicy() ExistingNetworkPolicy {
	return ExistingNetworkPolicy{IPv4Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, DNSDomains: []string{"corp.example.test"}, DNSServers: []netip.Addr{netip.MustParseAddr("10.0.0.53")}, IPv6Mode: "blocked"}
}
func coreBridgeFixture(t *testing.T) (*ExistingCoreAdapter, *fakeExistingOps, *fakePolicyVerifier) {
	t.Helper()
	controller, ops, selection := existingFixture(t)
	v := &fakePolicyVerifier{enabled: true}
	a := newExistingCoreAdapter(controller, selection, existingConsent(), testNetworkPolicy(), v)
	a.poll = time.Millisecond
	a.stopTimeout = time.Second
	return a, ops, v
}
func awaitCoreResult(t *testing.T, c <-chan error) error {
	t.Helper()
	select {
	case e := <-c:
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("会话结果未及时返回")
		return nil
	}
}
func TestCoreNativeVerifierUnavailableBeforeActivation(t *testing.T) {
	controller, ops, s := existingFixture(t)
	a := NewExistingCoreAdapter(s, existingConsent(), testNetworkPolicy())
	if a.Capability().Available {
		t.Fatal("不完整原生验证被启用")
	}
	if _, e := a.Start(context.Background(), a.profile, nil); e == nil || ops.starts.Load() != 0 || controller.current != nil {
		t.Fatal("策略缺失仍激活")
	}
}
func TestCoreAllPolicyProofsBeforeReadyAndCleanupBeforeStop(t *testing.T) {
	a, ops, v := coreBridgeFixture(t)
	s, e := a.Start(context.Background(), a.profile, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = awaitCoreResult(t, s.Ready()); e != nil {
		t.Fatal(e)
	}
	if v.captures.Load() != 1 || v.activeCalls.Load() < 1 {
		t.Fatal("未取得独立策略证明")
	}
	if e = s.Stop(); e != nil {
		t.Fatal(e)
	}
	if e = awaitCoreResult(t, s.Done()); e != nil {
		t.Fatal(e)
	}
	if v.restores.Load() != 1 || ops.session.stops.Load() != 1 {
		t.Fatal("清理未验证")
	}
	select {
	case <-s.Ready():
		t.Fatal("重复Ready")
	default:
	}
	if _, e = a.Start(context.Background(), a.profile, nil); e == nil {
		t.Fatal("重复使用选择授权")
	}
}
func TestCoreRejectSecretsAndUnboundProfile(t *testing.T) {
	a, ops, _ := coreBridgeFixture(t)
	if _, e := a.Start(context.Background(), a.profile, []byte("not-system-mode")); e == nil {
		t.Fatal("忽略传入密码")
	}
	p := a.profile
	p.Protocol = "l2tp"
	if _, e := a.Start(context.Background(), p, nil); e == nil || ops.starts.Load() != 0 {
		t.Fatal("普通L2TP被套入系统模式")
	}
}
func TestCoreCaptureFailureNeverActivates(t *testing.T) {
	a, ops, v := coreBridgeFixture(t)
	v.captureFn = func(context.Context) (policyBaseline, error) { return policyBaseline{}, errors.New("private baseline") }
	s, e := a.Start(context.Background(), a.profile, nil)
	if e != nil {
		t.Fatal(e)
	}
	if awaitCoreResult(t, s.Ready()) == nil || awaitCoreResult(t, s.Done()) == nil {
		t.Fatal("基线失败仍Ready")
	}
	if e = s.Stop(); e != nil || ops.starts.Load() != 0 || ops.session.stops.Load() != 0 {
		t.Fatal("基线失败触达系统")
	}
}
func TestCorePolicyFailureStopsWithoutReady(t *testing.T) {
	a, ops, v := coreBridgeFixture(t)
	v.activeFn = func(context.Context) error { return errors.New("private routing failure") }
	s, e := a.Start(context.Background(), a.profile, nil)
	if e != nil {
		t.Fatal(e)
	}
	if awaitCoreResult(t, s.Ready()) == nil || awaitCoreResult(t, s.Done()) == nil {
		t.Fatal("策略失败仍Ready")
	}
	if e = s.Stop(); e != nil || ops.session.stops.Load() != 1 || v.restores.Load() != 1 {
		t.Fatal("策略失败未清理")
	}
}
func TestCoreRestorationFailureIsCleanupFailed(t *testing.T) {
	a, ops, v := coreBridgeFixture(t)
	v.activeFn = func(context.Context) error { return ErrExistingVerification }
	v.restoreFn = func(context.Context) error { return errors.New("private resolver remains") }
	s, e := a.Start(context.Background(), a.profile, nil)
	if e != nil {
		t.Fatal(e)
	}
	if !isCoreCleanupError(awaitCoreResult(t, s.Ready())) || !isCoreCleanupError(awaitCoreResult(t, s.Done())) {
		t.Fatal("未映射清理失败")
	}
	if e = s.Stop(); !isCoreCleanupError(e) || ops.session.stops.Load() != 1 {
		t.Fatal("未保留清理失败")
	}
}
func TestCoreContinuousPolicyLossEndsSession(t *testing.T) {
	a, _, v := coreBridgeFixture(t)
	var calls atomic.Int32
	v.activeFn = func(context.Context) error {
		if calls.Add(1) > 1 {
			return ErrExistingVerification
		}
		return nil
	}
	s, e := a.Start(context.Background(), a.profile, nil)
	if e != nil {
		t.Fatal(e)
	}
	if awaitCoreResult(t, s.Ready()) != nil {
		t.Fatal("初始验证失败")
	}
	if awaitCoreResult(t, s.Done()) == nil {
		t.Fatal("策略丢失未终止")
	}
	if e = s.Stop(); e != nil {
		t.Fatal(e)
	}
}
func TestCoreBlockedCallRetainedAfterStopTimeout(t *testing.T) {
	a, ops, _ := coreBridgeFixture(t)
	a.stopTimeout = 15 * time.Millisecond
	entered, release := make(chan struct{}), make(chan struct{})
	ops.begin = func(context.Context, string) (existingNativeSession, error) {
		close(entered)
		<-release
		return ops.session, nil
	}
	s, e := a.Start(context.Background(), a.profile, nil)
	if e != nil {
		t.Fatal(e)
	}
	<-entered
	if e = s.Stop(); !isCoreCleanupError(e) {
		t.Fatal("未知原生退出被误认为已清理")
	}
	if !isCoreCleanupError(awaitCoreResult(t, s.Done())) {
		t.Fatal("Stop返回前未发布终态")
	}
	close(release)
	<-s.(*existingCoreSession).workerDone
	if e = s.Stop(); e != nil {
		t.Fatal(e)
	}
	if awaitCoreResult(t, s.Ready()) == nil {
		t.Fatal("停止超时后发布Ready")
	}
}
func TestCoreConcurrentStopsPublishOnce(t *testing.T) {
	a, ops, _ := coreBridgeFixture(t)
	s, e := a.Start(context.Background(), a.profile, nil)
	if e != nil {
		t.Fatal(e)
	}
	if awaitCoreResult(t, s.Ready()) != nil {
		t.Fatal("未Ready")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := s.Stop(); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if ops.session.stops.Load() != 1 {
		t.Fatal("并发Stop重复原生操作")
	}
	awaitCoreResult(t, s.Done())
	select {
	case <-s.Done():
		t.Fatal("重复Done")
	default:
	}
}
func TestCorePolicyValidation(t *testing.T) {
	for _, mutate := range []func(*ExistingNetworkPolicy){func(p *ExistingNetworkPolicy) { p.IPv6Mode = "" }, func(p *ExistingNetworkPolicy) { p.IPv6Mode = "tunnel" }, func(p *ExistingNetworkPolicy) { p.IPv4Prefixes = []netip.Prefix{netip.MustParsePrefix("10.1.1.1/8")} }, func(p *ExistingNetworkPolicy) { p.DNSDomains = nil }, func(p *ExistingNetworkPolicy) { p.DNSServers = []netip.Addr{netip.IPv4Unspecified()} }} {
		p := testNetworkPolicy()
		mutate(&p)
		if p.valid() {
			t.Fatal("含糊策略被接受")
		}
	}
}

func TestCoreCleanupRetryRemainsBoundedAndOwned(t *testing.T) {
	a, _, v := coreBridgeFixture(t)
	a.stopTimeout = 20 * time.Millisecond
	entered, release := make(chan struct{}), make(chan struct{})
	var attempts atomic.Int32
	v.restoreFn = func(context.Context) error {
		n := attempts.Add(1)
		if n == 1 {
			return errors.New("injected restoration uncertainty")
		}
		if n == 2 {
			close(entered)
			<-release
			return nil
		}
		return nil
	}
	session, err := a.Start(context.Background(), a.profile, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := awaitCoreResult(t, session.Ready()); err != nil {
		t.Fatal(err)
	}
	s := session.(*existingCoreSession)
	s.cancel()
	<-s.workerDone
	result := make(chan error, 1)
	go func() { result <- s.Stop() }()
	<-entered
	if err := awaitCoreResult(t, result); err == nil {
		t.Fatal("阻塞重试错误返回成功")
	}
	if err := s.Stop(); err == nil {
		t.Fatal("未完成重试未保留隔离")
	}
	if attempts.Load() != 2 {
		t.Fatal("重入仍在执行的清理")
	}
	close(release)
	// The first retry's context expired while blocked, so it remains a failed
	// attempt even after returning. A subsequent serialized retry may prove cleanup.
	_ = s.Stop()
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 3 {
		t.Fatal("清理重试次数错误")
	}
}

func isCoreCleanupError(err error) bool {
	var cleanup *core.CleanupError
	return errors.As(err, &cleanup)
}
