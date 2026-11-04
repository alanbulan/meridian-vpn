package desktop

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
	"mygo-vpn/internal/macosvpn"
)

type macServiceInput struct{ ID, Gateway, Targets string }
type macServicePrepared struct {
	input       macServiceInput
	makeAdapter func(macosvpn.ExistingServiceConsent) (core.Adapter, core.Profile, error)
}
type macServiceResult struct {
	prepared macServicePrepared
	version  uint64
	err      error
}
type macServiceUI struct {
	input           macServiceInput
	prepared        *macServicePrepared
	consent         macosvpn.ExistingServiceConsent
	version         uint64
	result          chan macServiceResult
	cancel          context.CancelFunc
	activeProfile   *core.Profile
	activeAttemptID uint64
}

func (m *macServiceUI) reset() {
	m.version++
	m.prepared = nil
	m.consent = macosvpn.ExistingServiceConsent{}
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.result = nil
}
func macServiceProfile(input macServiceInput) (core.Profile, []netip.Addr, error) {
	tokens := strings.Fields(input.Targets)
	profile := core.Profile{ID: input.ID, Name: "现有 macOS 系统服务", Protocol: core.ProtocolMacOSSystemL2TP, Gateway: input.Gateway, SystemService: &core.SystemServiceOptions{ServiceID: input.ID, Targets: tokens}}
	if err := core.ValidateProfile(profile); err != nil {
		return core.Profile{}, nil, errors.New("服务标识、期望网关或目标地址无效")
	}
	targets := make([]netip.Addr, len(tokens))
	for i, s := range tokens {
		ip, e := netip.ParseAddr(s)
		if e != nil || ip.IsLoopback() {
			return core.Profile{}, nil, errors.New("目标必须是明确的非回环数值地址")
		}
		targets[i] = ip
		tokens[i] = ip.String()
	}
	return profile, targets, nil
}
func prepareMacService(ctx context.Context, input macServiceInput) (macServicePrepared, error) {
	if runtime.GOOS != "darwin" {
		return macServicePrepared{}, errors.New("此模式仅支持 macOS")
	}
	expected, targets, err := macServiceProfile(input)
	if err != nil {
		return macServicePrepared{}, err
	}
	controller := macosvpn.NewExistingServiceAdapter()
	selection, err := controller.Select(ctx, input.ID)
	if err != nil || ctx.Err() != nil {
		return macServicePrepared{}, errors.New("所选系统服务未通过只读检查")
	}
	observed := selection.Configuration()
	if observed.ServiceID != input.ID || observed.Gateway != input.Gateway {
		return macServicePrepared{}, errors.New("所选系统服务与期望网关不匹配")
	}
	return macServicePrepared{input: input, makeAdapter: func(consent macosvpn.ExistingServiceConsent) (core.Adapter, core.Profile, error) {
		adapter := macosvpn.NewLimitedExistingCoreAdapter(selection, consent, targets)
		p, err := adapter.LimitedProfile()
		if err != nil || !reflect.DeepEqual(p, expected) {
			return nil, core.Profile{}, errors.New("系统服务选择已失效")
		}
		return adapter, p, nil
	}}, nil
}
func (a *App) restoreMacServiceSelection() {
	a.macService.reset()
	if s := a.Config.MacServiceSelection; s != nil {
		input := macServiceInput{s.ServiceID, s.Gateway, strings.Join(s.Targets, " ")}
		if _, _, err := macServiceProfile(input); err == nil {
			a.macService.input = input
		}
	}
}

func (a *App) macServiceSelectionEditable() bool {
	return !a.LoadBlocked && !a.FileBusy && !a.busy() && !a.ShuttingDown && !a.Checking && a.Engine.Snapshot().State != core.CleanupFailed && a.macService.result == nil
}

func (a *App) saveMacServiceSelection() {
	if !a.macServiceSelectionEditable() {
		return
	}
	p, _, err := macServiceProfile(a.macService.input)
	if err != nil {
		a.Notice = err.Error()
		return
	}
	cfg := a.copyConfig()
	cfg.MacServiceSelection = &core.SavedMacServiceSelection{ServiceID: p.SystemService.ServiceID, Gateway: p.Gateway, Targets: append([]string(nil), p.SystemService.Targets...)}
	if a.commit(cfg) {
		a.restoreMacServiceSelection()
		a.Notice = "已保存选择；每次连接仍须重新检查并授权。未保存凭据或授权。"
	}
}

func (a *App) forgetMacServiceSelection() {
	if !a.macServiceSelectionEditable() {
		return
	}
	cfg := a.copyConfig()
	cfg.MacServiceSelection = nil
	if a.commit(cfg) {
		a.macService.reset()
		a.macService.input = macServiceInput{}
		a.Notice = "已忘记 Meridian 保存的选择；系统服务及其凭据未作修改。"
	}
}

func (a *App) beginMacServiceCheck(prepare func(context.Context, macServiceInput) (macServicePrepared, error)) {
	if a.LoadBlocked || a.FileBusy || a.busy() || a.ShuttingDown || a.Checking || a.Engine.Snapshot().State == core.CleanupFailed || a.macService.result != nil {
		return
	}
	input := a.macService.input
	if _, _, err := macServiceProfile(input); err != nil {
		a.Notice = err.Error()
		return
	}
	a.macService.reset()
	version := a.macService.version
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	a.macService.cancel = cancel
	result := make(chan macServiceResult, 1)
	a.macService.result = result
	go func() { defer cancel(); p, err := prepare(ctx, input); result <- macServiceResult{p, version, err} }()
}
func (a *App) pollMacService() {
	if a.macService.result == nil {
		return
	}
	select {
	case result := <-a.macService.result:
		a.macService.result = nil
		a.macService.cancel = nil
		if result.version != a.macService.version || a.Page != "MacSystemService" || a.ShuttingDown {
			return
		}
		if result.err != nil {
			a.macService.prepared = nil
			a.macService.consent = macosvpn.ExistingServiceConsent{}
			a.Notice = "系统服务只读检查未通过；请核对服务标识、期望网关及断开状态。"
			return
		}
		if result.prepared.input != a.macService.input || result.prepared.makeAdapter == nil {
			return
		}
		a.macService.prepared = &result.prepared
		a.macService.consent = macosvpn.ExistingServiceConsent{}
	default:
	}
}
func (a *App) connectMacService() {
	m := &a.macService
	c := m.consent
	if a.LoadBlocked || a.FileBusy || a.busy() || a.ShuttingDown || a.Checking || a.Engine.Snapshot().State == core.CleanupFailed || m.result != nil || m.prepared == nil || m.prepared.input != m.input || !c.NetworkChanges || !c.SavedSystemCredentials || !c.SharedSystemService || !c.LimitedVerification {
		return
	}
	prepared := m.prepared
	defer m.reset() // Consent and single-use selection never survive an attempt.
	adapter, profile, err := prepared.makeAdapter(c)
	if err != nil || adapter == nil {
		a.Notice = "系统服务选择已失效，请重新检查并授权。"
		return
	}
	scope, ok := adapter.(core.ScopedVerification)
	expected, _, validationErr := macServiceProfile(m.input)
	if !ok || scope.VerificationScope() != core.SystemServiceTargetRoutes || validationErr != nil || !reflect.DeepEqual(profile, expected) {
		a.Notice = "后端未提供所选有限验证范围。"
		return
	}
	if err := a.Engine.ReplaceAdapter(adapter); err != nil {
		a.Notice = "当前会话尚不能替换。"
		return
	}
	a.Adapter = adapter
	a.Capability = adapter.Capability()
	a.clearCredentials()
	a.clearReauthentication()
	if err := a.Engine.ConnectWithCredentials(profile, core.Credentials{}, true); err != nil {
		a.Notice = "有限系统服务连接请求未通过；未记录为已连接。"
		return
	}
	m.activeProfile = &profile
	m.activeAttemptID = a.Engine.Snapshot().AttemptID
	a.Notice = "正在等待所选系统服务及指定目标路由验证；不提供全应用 DNS/IPv6 防泄漏保证。"
}
func (a *App) macSystemServiceForm(c *ui.Context) {
	if runtime.GOOS != "darwin" {
		ui.Text(c, "此模式仅支持 macOS。")
		return
	}
	m := &a.macService
	ui.Text(c, "现有 macOS 系统 L2TP 服务").FontSize(18).Bold()
	ui.Text(c, "使用系统中已配置的 L2TP/IPsec 服务及已保存凭据。仅验证该服务、PPP 接口和指定数值目标路由，不提供全应用 DNS/IPv6 防泄漏、独占连接或整机恢复保证。").FillWidth()
	disabled := a.LoadBlocked || a.FileBusy || a.busy() || a.ShuttingDown || a.Checking || a.Engine.Snapshot().State == core.CleanupFailed || m.result != nil
	before := m.input
	ui.Text(c, "系统服务标识（不是显示名称，可用终端 scutil --nc list 查看）")
	ui.TextInput(c.Key("mac-service-id"), &m.input.ID).FillWidth().Disabled(disabled)
	ui.Text(c, "期望网关（必须与系统服务完全一致）")
	ui.TextInput(c.Key("mac-service-gateway"), &m.input.Gateway).FillWidth().Disabled(disabled)
	ui.Text(c, "需要走该服务的数值目标（1–16个，以空格分隔）")
	ui.TextInput(c.Key("mac-service-targets"), &m.input.Targets).FillWidth().Disabled(disabled)
	if before != m.input {
		m.reset()
	}
	ui.Text(c, "保存的选择只用于填入表单；服务已删除或配置改变时需更新选择并重新检查。").FillWidth()
	if ui.Button(c.Key("mac-save-selection"), "保存选择（不保存授权）").Disabled(disabled).Clicked() {
		a.saveMacServiceSelection()
	}
	if ui.Button(c.Key("mac-forget-selection"), "忘记保存的选择").Disabled(disabled || a.Config.MacServiceSelection == nil).Clicked() {
		a.forgetMacServiceSelection()
	}
	if ui.Button(c.Key("mac-check"), "只读检查所选服务").Disabled(disabled).Clicked() {
		a.beginMacServiceCheck(prepareMacService)
	}
	if m.result != nil {
		ui.Text(c, "正在只读检查；尚未连接。")
		c.After(100 * time.Millisecond)
	}
	if m.prepared != nil {
		ui.Text(c, "检查通过。仅本次连接授权以下事项，修改选择将清除授权：").FillWidth()
		ui.Checkbox(c.Key("mac-network"), &m.consent.NetworkChanges, "允许系统服务修改网络路由与 DNS").Disabled(disabled)
		ui.Checkbox(c.Key("mac-credentials"), &m.consent.SavedSystemCredentials, "允许使用该系统服务已保存的凭据").Disabled(disabled)
		ui.Checkbox(c.Key("mac-shared"), &m.consent.SharedSystemService, "理解该服务可能与其他应用共享，不会强制断开他人").Disabled(disabled)
		ui.Checkbox(c.Key("mac-limited"), &m.consent.LimitedVerification, "接受仅验证系统服务与指定目标，不提供全应用 DNS/IPv6 防泄漏保证").Disabled(disabled)
		consent := m.consent
		if ui.PrimaryButton(c.Key("mac-connect"), "连接所选系统服务").Disabled(disabled || !consent.NetworkChanges || !consent.SavedSystemCredentials || !consent.SharedSystemService || !consent.LimitedVerification).Clicked() {
			a.connectMacService()
		}
	}
	ui.Text(c, a.Engine.Snapshot().Message).FillWidth()
}

func (a *App) macServiceSettingsEntry(c *ui.Context) {
	if runtime.GOOS != "darwin" {
		return
	}
	if ui.Button(c.Key("mac-service-mode"), "连接现有 macOS 系统 L2TP 服务（有限验证）").Disabled(a.busy() || a.ShuttingDown || a.Engine.Snapshot().State == core.CleanupFailed).Clicked() {
		a.navigate("MacSystemService")
	}
}

// Retain the admitted mode/identity across cleanup and failure, when the
// success-only Snapshot.VerificationScope has correctly been cleared.
func (a *App) macServiceOwnsAttempt(snapshot core.Snapshot) bool {
	return a.macService.activeProfile != nil && a.macService.activeAttemptID != 0 && snapshot.AttemptID == a.macService.activeAttemptID
}
