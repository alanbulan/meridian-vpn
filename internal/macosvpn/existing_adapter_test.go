package macosvpn

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeExistingSession struct {
	wait  func(context.Context) error
	stop  func(context.Context) error
	stops atomic.Int32
}

func (s *fakeExistingSession) WaitConnected(ctx context.Context) error {
	if s.wait != nil {
		return s.wait(ctx)
	}
	return nil
}
func (s *fakeExistingSession) Stop(ctx context.Context) error {
	s.stops.Add(1)
	if s.stop != nil {
		return s.stop(ctx)
	}
	return nil
}

type fakeExistingOps struct {
	config      ServiceConfiguration
	session     *fakeExistingSession
	inspection  func(context.Context, string) (ServiceInspection, error)
	observation func(context.Context, existingNativeSession, string) (ServiceInspection, error)
	begin       func(context.Context, string) (existingNativeSession, error)
	starts      atomic.Int32
}

func (f *fakeExistingOps) inspect(ctx context.Context, id string) (ServiceInspection, error) {
	if f.inspection != nil {
		return f.inspection(ctx, id)
	}
	return ServiceInspection{Configuration: cloneConfiguration(f.config), Status: Disconnected}, nil
}
func (f *fakeExistingOps) start(ctx context.Context, id string) (existingNativeSession, error) {
	f.starts.Add(1)
	if f.begin != nil {
		return f.begin(ctx, id)
	}
	return f.session, nil
}
func (f *fakeExistingOps) observe(ctx context.Context, s existingNativeSession, id string) (ServiceInspection, error) {
	if f.observation != nil {
		return f.observation(ctx, s, id)
	}
	return ServiceInspection{Configuration: cloneConfiguration(f.config), Status: Connected, Generation: &GenerationEvidence{ConnectTime: 42, Interface: InterfaceEvidence{ServiceID: id, InterfaceName: "ppp7", InterfaceIndex: 8, IPv4Addresses: []netip.Addr{netip.MustParseAddr("10.1.2.3")}}}}, nil
}
func existingFixture(t *testing.T) (*ExistingServiceAdapter, *fakeExistingOps, *ExistingServiceSelection) {
	t.Helper()
	f := &fakeExistingOps{config: ServiceConfiguration{ServiceID: "service-id", Gateway: "vpn.example.test", PPPAuthentication: []string{"MSCHAP2"}, IPSecAuthentication: "SharedSecret"}, session: &fakeExistingSession{}}
	a := newExistingAdapter(f)
	s, err := a.Select(context.Background(), f.config.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	return a, f, s
}
func existingConsent() ExistingServiceConsent { return ExistingServiceConsent{true, true, true, true} }
func TestExistingExplicitSelectionConsentAndNoReady(t *testing.T) {
	a, f, s := existingFixture(t)
	for _, c := range []ExistingServiceConsent{{}, {false, true, true, true}, {true, false, true, true}, {true, true, false, true}, {true, true, true, false}} {
		if _, err := a.Connect(context.Background(), s, c); err != ErrAuthorization {
			t.Fatal("授权缺失仍连接")
		}
	}
	if f.starts.Load() != 0 {
		t.Fatal("未经授权调用系统")
	}
	copied := s.Configuration()
	copied.PPPAuthentication[0] = "PAP"
	out, err := a.Connect(context.Background(), s, existingConsent())
	if err != nil || !out.SystemConnected || out.RouteDNSIPv6Verified {
		t.Fatalf("错误观测: %v", err)
	}
	out.Generation.Interface.IPv4Addresses[0] = netip.MustParseAddr("10.9.9.9")
	if _, err := a.Check(context.Background()); err != nil {
		t.Fatal("调用方篡改了内部代际")
	}
	stop, err := a.Stop(context.Background())
	if err != nil || !stop.InterestReleased || !stop.ServiceDisconnected || stop.NetworkRestored {
		t.Fatal("错误清理声明")
	}
	if _, err := a.Connect(context.Background(), s, existingConsent()); err != ErrAuthorization {
		t.Fatal("重复使用逐次授权")
	}
	if _, err := a.Stop(context.Background()); err != nil || f.session.stops.Load() != 1 {
		t.Fatal("重复清理")
	}
}
func TestExistingForeignSelectionAndActiveRefusal(t *testing.T) {
	a, f, s := existingFixture(t)
	other := newExistingAdapter(f)
	if _, err := other.Connect(context.Background(), s, existingConsent()); err != ErrAuthorization {
		t.Fatal("接受其他实例选择")
	}
	for _, status := range []Status{Connected, Connecting, Disconnecting, Invalid} {
		f.inspection = func(context.Context, string) (ServiceInspection, error) {
			return ServiceInspection{Configuration: f.config, Status: status}, nil
		}
		if _, err := a.Select(context.Background(), "service-id"); err == nil {
			t.Fatal("接管活动服务")
		}
	}
	if f.starts.Load() != 0 {
		t.Fatal("只读选择导致激活")
	}
}
func TestExistingConfigurationDriftBeforeStart(t *testing.T) {
	a, f, s := existingFixture(t)
	f.config.Gateway = "other.example.test"
	if _, err := a.Connect(context.Background(), s, existingConsent()); err == nil || f.starts.Load() != 0 {
		t.Fatal("配置变化仍连接")
	}
}
func TestExistingRejectWeakOrAmbiguousAuth(t *testing.T) {
	a, f, _ := existingFixture(t)
	for _, auth := range [][]string{{"PAP"}, {"MSCHAP2", "PAP"}, {"EAP"}, nil} {
		f.config.PPPAuthentication = auth
		if _, err := a.Select(context.Background(), "service-id"); err == nil {
			t.Fatal("未支持认证仍选择")
		}
	}
}
func TestExistingGenerationAndConfigurationDriftCleanup(t *testing.T) {
	for _, kind := range []string{"time", "interface", "address", "config", "state", "missing"} {
		t.Run(kind, func(t *testing.T) {
			a, f, s := existingFixture(t)
			if _, err := a.Connect(context.Background(), s, existingConsent()); err != nil {
				t.Fatal(err)
			}
			f.observation = func(_ context.Context, _ existingNativeSession, id string) (ServiceInspection, error) {
				out := ServiceInspection{Configuration: cloneConfiguration(f.config), Status: Connected, Generation: &GenerationEvidence{42, InterfaceEvidence{id, "ppp7", 8, []netip.Addr{netip.MustParseAddr("10.1.2.3")}}}}
				switch kind {
				case "time":
					out.Generation.ConnectTime++
				case "interface":
					out.Generation.Interface.InterfaceIndex++
				case "address":
					out.Generation.Interface.IPv4Addresses[0] = netip.MustParseAddr("10.2.3.4")
				case "config":
					out.Configuration.Gateway = "other.example.test"
				case "state":
					out.Status = Disconnected
				case "missing":
					out.Generation = nil
				}
				return out, nil
			}
			if _, err := a.Check(context.Background()); err == nil || f.session.stops.Load() != 1 || a.current != nil {
				t.Fatal("会话漂移仍保留观测或未清理")
			}
		})
	}
}
func TestExistingCleanupQuarantineAndRetry(t *testing.T) {
	a, f, s := existingFixture(t)
	if _, err := a.Connect(context.Background(), s, existingConsent()); err != nil {
		t.Fatal(err)
	}
	f.session.stop = func(context.Context) error { return errors.New("private-native-detail") }
	if _, err := a.Stop(context.Background()); err != ErrCleanup || a.current == nil {
		t.Fatal("清理失败未隔离")
	}
	if _, err := a.Select(context.Background(), "service-id"); err != ErrBusy {
		t.Fatal("隔离时可重连")
	}
	f.session.stop = nil
	f.inspection = func(context.Context, string) (ServiceInspection, error) {
		return ServiceInspection{Configuration: f.config, Status: Connected}, nil
	}
	if _, err := a.Stop(context.Background()); err != ErrCleanup {
		t.Fatal("共享活动服务被认为已断开")
	}
	count := f.session.stops.Load()
	f.inspection = nil
	if _, err := a.Stop(context.Background()); err != nil || f.session.stops.Load() != count {
		t.Fatal("已释放兴趣被重复撤销")
	}
}
func TestExistingUnknownStartQuarantines(t *testing.T) {
	a, f, s := existingFixture(t)
	f.begin = func(context.Context, string) (existingNativeSession, error) { panic("private-start-outcome") }
	if _, err := a.Connect(context.Background(), s, existingConsent()); err != ErrCleanup {
		t.Fatal("未知激活结果未隔离")
	}
	if _, err := a.Stop(context.Background()); err != ErrCleanup || f.session.stops.Load() != 0 {
		t.Fatal("猜测引用或伪造清理")
	}
}
func TestExistingKnownStartFailureWithoutInterest(t *testing.T) {
	a, f, s := existingFixture(t)
	f.begin = func(context.Context, string) (existingNativeSession, error) {
		return nil, errors.New("private-failure")
	}
	if _, err := a.Connect(context.Background(), s, existingConsent()); err != ErrExistingUnavailable || a.current != nil {
		t.Fatal("已知未取得兴趣失败处理错误")
	}
}
func TestExistingReturnedSessionWithErrorMustStop(t *testing.T) {
	a, f, s := existingFixture(t)
	f.begin = func(context.Context, string) (existingNativeSession, error) {
		return f.session, errors.New("private-failure")
	}
	if _, err := a.Connect(context.Background(), s, existingConsent()); err != ErrExistingUnavailable || f.session.stops.Load() != 1 || a.current != nil {
		t.Fatal("带会话失败丢失清理")
	}
}
func TestExistingStopCancelsWait(t *testing.T) {
	a, f, s := existingFixture(t)
	entered := make(chan struct{})
	f.session.wait = func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() }
	done := make(chan error, 1)
	go func() { _, err := a.Connect(context.Background(), s, existingConsent()); done <- err }()
	<-entered
	if _, err := a.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || f.session.stops.Load() != 1 {
		t.Fatal("取消没有清理")
	}
}
func TestExistingBlockedNativeCallNotDetached(t *testing.T) {
	a, f, s := existingFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.begin = func(context.Context, string) (existingNativeSession, error) {
		close(entered)
		<-release
		return f.session, nil
	}
	done := make(chan error, 1)
	go func() { _, err := a.Connect(context.Background(), s, existingConsent()); done <- err }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := a.Stop(ctx); err != ErrCleanup || f.session.stops.Load() != 0 {
		t.Fatal("并发停止未返回原生调用")
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("取消后仍成功")
	}
	if _, err := a.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestExistingConcurrentStopSerializesNative(t *testing.T) {
	a, f, s := existingFixture(t)
	if _, err := a.Connect(context.Background(), s, existingConsent()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.Stop(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if f.session.stops.Load() != 1 {
		t.Fatal("重复原生撤销")
	}
}
func TestExistingInvalidContextAndSelectionNeverStarts(t *testing.T) {
	a, f, s := existingFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{ctx, nil} {
		if _, err := a.Connect(ctx, s, existingConsent()); err == nil {
			t.Fatal("无效上下文仍连接")
		}
	}
	if f.starts.Load() != 0 {
		t.Fatal("无效参数触达原生激活")
	}
}

func TestExistingSelectionValueCopyCannotReplay(t *testing.T) {
	a, f, s := existingFixture(t)
	copyOfSelection := *s
	if _, err := a.Connect(context.Background(), s, existingConsent()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Connect(context.Background(), &copyOfSelection, existingConsent()); err != ErrAuthorization || f.starts.Load() != 1 {
		t.Fatal("值拷贝绕过逐次选择消费")
	}
}

type borrowedGenerationFake struct{ *inspectionFake }

func (b *borrowedGenerationFake) start() error { return nil }
func (b *borrowedGenerationFake) stop() error  { return nil }
func TestExistingGenerationInspectionNeverClosesActiveReference(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		f := diagnosticFake(Connected)
		if invalid {
			f.config = func() (ServiceConfiguration, error) { return ServiceConfiguration{}, errors.New("private detail") }
		}
		session := &Session{native: &borrowedGenerationFake{f}}
		result, err := session.inspectGenerationWith(context.Background(), "service-id", validInterface)
		if invalid != (err != nil) {
			t.Fatal("错误观测结果")
		}
		if !invalid && (result.Generation == nil || result.Status != Connected) {
			t.Fatal("没有保留代际")
		}
		if f.closes != 0 || session.native == nil {
			t.Fatal("借用观测释放活动连接引用")
		}
	}
}
func TestExistingInvalidGenerationCannotBeObserved(t *testing.T) {
	for _, kind := range []string{"bad-name", "missing-index", "loopback", "duplicate", "too-many"} {
		t.Run(kind, func(t *testing.T) {
			a, f, s := existingFixture(t)
			f.observation = func(_ context.Context, _ existingNativeSession, id string) (ServiceInspection, error) {
				g := GenerationEvidence{42, InterfaceEvidence{id, "ppp7", 8, []netip.Addr{netip.MustParseAddr("10.1.2.3")}}}
				switch kind {
				case "bad-name":
					g.Interface.InterfaceName = "en0"
				case "missing-index":
					g.Interface.InterfaceIndex = 0
				case "loopback":
					g.Interface.IPv4Addresses[0] = netip.MustParseAddr("127.0.0.1")
				case "duplicate":
					g.Interface.IPv4Addresses = append(g.Interface.IPv4Addresses, g.Interface.IPv4Addresses[0])
				case "too-many":
					g.Interface.IPv4Addresses = make([]netip.Addr, 17)
				}
				return ServiceInspection{Configuration: f.config, Status: Connected, Generation: &g}, nil
			}
			if _, err := a.Connect(context.Background(), s, existingConsent()); err == nil || f.session.stops.Load() != 1 {
				t.Fatal("无效代际被接受")
			}
		})
	}
}

type existingPanicStatusConnection struct{ stops int }

func (*existingPanicStatusConnection) status() Status { panic("private native status panic") }
func (*existingPanicStatusConnection) start() error   { return nil }
func (c *existingPanicStatusConnection) stop() error  { c.stops++; return nil }
func (*existingPanicStatusConnection) close()         {}
func TestExistingNativeWaitPanicNeverReentersLockedSession(t *testing.T) {
	a, f, s := existingFixture(t)
	native := &existingPanicStatusConnection{}
	f.begin = func(context.Context, string) (existingNativeSession, error) { return &Session{native: native}, nil }
	done := make(chan error, 1)
	go func() { _, err := a.Connect(context.Background(), s, existingConsent()); done <- err }()
	select {
	case err := <-done:
		if err != ErrCleanup {
			t.Fatal("未知调用未隔离")
		}
	case <-time.After(time.Second):
		t.Fatal("panic后重入已锁定原生会话")
	}
	if _, err := a.Stop(context.Background()); err != ErrCleanup || native.stops != 0 {
		t.Fatal("poisoned会话被重入")
	}
}
func TestExistingNativeStopPanicNeverReenters(t *testing.T) {
	a, f, s := existingFixture(t)
	if _, err := a.Connect(context.Background(), s, existingConsent()); err != nil {
		t.Fatal(err)
	}
	f.session.stop = func(context.Context) error { panic("private stop uncertainty") }
	for i := 0; i < 3; i++ {
		if _, err := a.Stop(context.Background()); err != ErrCleanup {
			t.Fatal("未知停止结果未隔离")
		}
	}
	if f.session.stops.Load() != 1 {
		t.Fatal("panic后再次调用原生停止")
	}
}
func TestExistingNativeObservePanicNeverReenters(t *testing.T) {
	a, f, s := existingFixture(t)
	f.observation = func(context.Context, existingNativeSession, string) (ServiceInspection, error) {
		panic("private observe uncertainty")
	}
	if _, err := a.Connect(context.Background(), s, existingConsent()); err != ErrCleanup {
		t.Fatal("未知观测未隔离")
	}
	if _, err := a.Stop(context.Background()); err != ErrCleanup || f.session.stops.Load() != 0 {
		t.Fatal("观测panic后重入原生会话")
	}
}
func TestExistingSuccessfulStopBeforeCancellationIsNotRepeated(t *testing.T) {
	a, f, s := existingFixture(t)
	if _, err := a.Connect(context.Background(), s, existingConsent()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.session.stop = func(context.Context) error { cancel(); return nil }
	if _, err := a.Stop(ctx); err != ErrCleanup {
		t.Fatal("取消后仍声明完整确认")
	}
	f.session.stop = nil
	if _, err := a.Stop(context.Background()); err != nil || f.session.stops.Load() != 1 {
		t.Fatal("已确认撤销因取消而被重复")
	}
}
