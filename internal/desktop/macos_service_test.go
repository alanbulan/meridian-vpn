package desktop

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
	"mygo-vpn/internal/macosvpn"
)

func macUIFixture(t *testing.T) *App {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), unavailableTestAdapter{})
	a.Page = "MacSystemService"
	a.macService.input = macServiceInput{"service-id", "vpn.example.test", "10.2.3.4"}
	return a
}
func TestMacServiceUIRejectsMissingTargetsWithoutRead(t *testing.T) {
	a := macUIFixture(t)
	a.macService.input.Targets = ""
	a.beginMacServiceCheck(func(context.Context, macServiceInput) (macServicePrepared, error) {
		t.Fatal("无目标仍读取系统")
		return macServicePrepared{}, nil
	})
	if a.macService.result != nil || a.Notice == "" {
		t.Fatal("无目标未阻止")
	}
}
func TestMacServiceUICancelClearsSelectionAndConsent(t *testing.T) {
	a := macUIFixture(t)
	a.macService.prepared = &macServicePrepared{input: a.macService.input}
	a.macService.consent = macosvpn.ExistingServiceConsent{NetworkChanges: true, SavedSystemCredentials: true, SharedSystemService: true, LimitedVerification: true}
	a.navigate("Overview")
	if a.macService.prepared != nil || a.macService.consent != (macosvpn.ExistingServiceConsent{}) {
		t.Fatal("导航保留选择或授权")
	}
}
func TestMacServiceUIReadFailureAndStaleCompletion(t *testing.T) {
	a := macUIFixture(t)
	a.macService.result = make(chan macServiceResult, 1)
	a.macService.result <- macServiceResult{version: a.macService.version, err: errors.New("private message")}
	a.pollMacService()
	if a.Notice == "" || strings.Contains(a.Notice, "private") {
		t.Fatal("读取失败未安全显示")
	}
	a.macService.result = make(chan macServiceResult, 1)
	a.macService.result <- macServiceResult{version: a.macService.version - 1, prepared: macServicePrepared{input: a.macService.input}}
	a.pollMacService()
	if a.macService.prepared != nil {
		t.Fatal("陈旧检查被采用")
	}
}
func TestMacServiceUICheckIsReadOnlyAndFresh(t *testing.T) {
	a := macUIFixture(t)
	called := make(chan struct{})
	a.beginMacServiceCheck(func(_ context.Context, input macServiceInput) (macServicePrepared, error) {
		close(called)
		return macServicePrepared{input: input, makeAdapter: func(macosvpn.ExistingServiceConsent) (core.Adapter, core.Profile, error) {
			t.Fatal("读取阶段创建连接")
			return nil, core.Profile{}, nil
		}}, nil
	})
	<-called
	deadline := time.Now().Add(time.Second)
	for a.macService.result != nil && time.Now().Before(deadline) {
		a.pollMacService()
		time.Sleep(time.Millisecond)
	}
	if a.macService.prepared == nil || a.macService.consent != (macosvpn.ExistingServiceConsent{}) {
		t.Fatal("检查未要求新同意")
	}
}
func TestMacServiceUIChangedTargetOrConsentBlocksConnect(t *testing.T) {
	for _, kind := range []string{"target", "gateway", "consent"} {
		a := macUIFixture(t)
		a.macService.prepared = &macServicePrepared{input: a.macService.input, makeAdapter: func(macosvpn.ExistingServiceConsent) (core.Adapter, core.Profile, error) {
			t.Fatal("未验证选择仍连接")
			return nil, core.Profile{}, nil
		}}
		a.macService.consent = macosvpn.ExistingServiceConsent{NetworkChanges: true, SavedSystemCredentials: true, SharedSystemService: true, LimitedVerification: true}
		switch kind {
		case "target":
			a.macService.input.Targets = "192.0.2.1"
		case "gateway":
			a.macService.input.Gateway = "other.example.test"
		case "consent":
			a.macService.consent.LimitedVerification = false
		}
		a.connectMacService()
		if a.Engine.Snapshot().State != core.Disconnected {
			t.Fatal("错误改变会话")
		}
	}
}

type macUIAdapter struct {
	session *macUISession
	scope   string
}

func (a macUIAdapter) Capability() core.Capability { return core.Capability{Available: true} }
func (a macUIAdapter) VerificationScope() string   { return a.scope }
func (a macUIAdapter) Start(context.Context, core.Profile, []byte) (core.Session, error) {
	return a.session, nil
}

type macUISession struct{ ready, done chan error }

func (s *macUISession) Ready() <-chan error       { return s.ready }
func (s *macUISession) Done() <-chan error        { return s.done }
func (s *macUISession) Stop() error               { return nil }
func (s *macUISession) VerificationScope() string { return core.SystemServiceTargetRoutes }
func TestMacServiceUIRequiresMatchingScopeAndConsumesConsent(t *testing.T) {
	a := macUIFixture(t)
	p, _, _ := macServiceProfile(a.macService.input)
	a.macService.prepared = &macServicePrepared{input: a.macService.input, makeAdapter: func(macosvpn.ExistingServiceConsent) (core.Adapter, core.Profile, error) {
		return macUIAdapter{scope: ""}, p, nil
	}}
	a.macService.consent = macosvpn.ExistingServiceConsent{NetworkChanges: true, SavedSystemCredentials: true, SharedSystemService: true, LimitedVerification: true}
	a.connectMacService()
	if a.Engine.Snapshot().State != core.Disconnected || a.macService.prepared != nil || a.macService.consent != (macosvpn.ExistingServiceConsent{}) {
		t.Fatal("范围缺失仍连接或保留授权")
	}
}
func TestMacServiceUIScopedReadyAndNoProfilePersistence(t *testing.T) {
	a := macUIFixture(t)
	p, _, _ := macServiceProfile(a.macService.input)
	s := &macUISession{make(chan error, 1), make(chan error, 1)}
	s.ready <- nil
	a.macService.prepared = &macServicePrepared{input: a.macService.input, makeAdapter: func(macosvpn.ExistingServiceConsent) (core.Adapter, core.Profile, error) {
		return macUIAdapter{s, core.SystemServiceTargetRoutes}, p, nil
	}}
	a.macService.consent = macosvpn.ExistingServiceConsent{NetworkChanges: true, SavedSystemCredentials: true, SharedSystemService: true, LimitedVerification: true}
	a.connectMacService()
	deadline := time.Now().Add(time.Second)
	for a.Engine.Snapshot().State == core.Connecting && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	snapshot := a.Engine.Snapshot()
	if snapshot.State != core.Connected || snapshot.VerificationScope != core.SystemServiceTargetRoutes || len(a.Config.Profiles) != 0 || a.macService.prepared != nil {
		t.Fatal("有限模式未正确隔离")
	}
	a.Config.Settings.Language = "zh"
	v := ui.NewTester(a.View, 1040, 780)
	if !v.HasText("有限验证：系统服务与指定目标路由；不保证全应用 DNS/IPv6 防泄漏。") {
		t.Fatal("连接侧栏未显示有限范围")
	}
	if err := a.Engine.Disconnect(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.Engine.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestMacServiceUICanonicalizesIPv6Targets(t *testing.T) {
	p, targets, err := macServiceProfile(macServiceInput{"service-id", "vpn.example.test", "2001:0db8:0000:0000:0000:0000:0000:0001"})
	if err != nil || p.SystemService.Targets[0] != "2001:db8::1" || targets[0].String() != p.SystemService.Targets[0] {
		t.Fatal("合法 IPv6 未规范化绑定")
	}
}
func TestMacServiceUIRetainsAttemptIdentityAndSuppressesOrdinaryRecovery(t *testing.T) {
	a := macUIFixture(t)
	a.Config.Profiles = []core.Profile{{ID: "ordinary", Name: "Ordinary profile", Protocol: "anyconnect", Gateway: "https://ordinary.example.test"}}
	a.Config.SelectedID = "ordinary"
	a.Config.Settings.ReauthOnLoss = true
	p, _, _ := macServiceProfile(a.macService.input)
	s := &macUISession{make(chan error, 1), make(chan error, 1)}
	s.ready <- nil
	a.macService.prepared = &macServicePrepared{input: a.macService.input, makeAdapter: func(macosvpn.ExistingServiceConsent) (core.Adapter, core.Profile, error) {
		return macUIAdapter{s, core.SystemServiceTargetRoutes}, p, nil
	}}
	a.macService.consent = macosvpn.ExistingServiceConsent{NetworkChanges: true, SavedSystemCredentials: true, SharedSystemService: true, LimitedVerification: true}
	a.connectMacService()
	deadline := time.Now().Add(time.Second)
	for a.Engine.Snapshot().State == core.Connecting && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	now := time.Now()
	a.pollReauthentication(now)
	s.done <- core.NewConnectionError(core.FailureConnectionLost)
	for a.Engine.Snapshot().State != core.Failed && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	snapshot := a.Engine.Snapshot()
	if snapshot.State != core.Failed || snapshot.VerificationScope != "" || !a.macServiceOwnsAttempt(snapshot) {
		t.Fatal("终态丢失有限尝试身份")
	}
	a.pollReauthentication(now.Add(time.Second))
	a.pollReauthentication(now.Add(10 * time.Second))
	if a.reauthVisible || a.observedConnected || a.reauthProfileID != "" {
		t.Fatal("有限连接误触发普通配置重登")
	}
	a.Page = "Overview"
	v := ui.NewTester(a.View, 1040, 780)
	if !v.HasText("现有 macOS 系统服务") || !v.HasText("重新检查系统服务") {
		t.Fatal("终态侧栏未保留有限身份或错误显示普通连接按钮")
	}
	a.reauthVisible = true
	a.reauthProfileID = "ordinary"
	a.reauthAttemptID = snapshot.AttemptID
	a.openRecoveryForm()
	if a.ConnectPanel || a.reauthVisible {
		t.Fatal("显式恢复入口未拦截错误模式")
	}
	next := snapshot
	next.AttemptID++
	if a.macServiceOwnsAttempt(next) {
		t.Fatal("旧有限模式污染下一次尝试")
	}
}
