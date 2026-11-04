// meridian-macos-service owns one explicitly authorized existing system service
// in the foreground. Default invocation and help do not inspect the system.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"slices"
	"syscall"

	"mygo-vpn/internal/core"
	"mygo-vpn/internal/macosvpn"
)

const usage = `用法：meridian-macos-service --connect-existing-service --service-id <现有服务标识> --expected-gateway <预期网关> --target <数字IP> [--target <数字IP>] --allow-network-changes --allow-saved-system-credentials --allow-shared-system-service --accept-limited-verification
仅限 macOS 已配置的 L2TP/IPsec 系统服务；不创建或修改服务配置，不接收或输出密码/PSK。
四项授权仅适用于本次运行：允许网络变更、使用系统已保存凭据、操作可能共享的系统服务、接受有限验证。
验证仅覆盖所选服务和 1–16 个不同的指定目标路由，不提供全应用 DNS/IPv6 防泄漏或全设备网络恢复保证。
工具在前台持有会话。Ctrl+C 或 SIGTERM 请求取消并清理；清理未确认时保持运行，之后再次发送信号仅重试一次清理。
系统原生调用可能阻塞；取消不保证立即返回。强制结束进程不保证清理。默认运行和 --help 不读取系统服务、不建立连接。`

const (
	msgInvalid    = "参数无效或本次授权不完整；未读取系统服务，未建立连接。"
	msgWaiting    = "正在检查本次明确选择的服务并等待有限验证。原生系统调用可能等待；Ctrl+C 请求取消，但不保证立即返回。"
	msgCancel     = "已请求取消；保留会话并等待当前操作返回，再确认清理。不会并发重试或强制退出。"
	msgCleaning   = "正在确认所选系统服务及已观测 PPP 接口和路由的清理；原生系统调用可能等待。"
	msgQuarantine = "清理尚未确认；会话仍被保留，禁止重新连接或自动退出。请检查所选系统服务；再次按 Ctrl+C 或发送 SIGTERM 仅重试一次清理。强制结束进程不保证清理。"
	msgPoisoned   = "系统调用结果不确定；保留隔离状态，不再调用网络操作，也不自动退出。请人工检查所选系统服务；强制结束进程不保证清理。"
	msgReady      = "系统服务和指定目标路由已验证；不提供全应用 DNS/IPv6 防泄漏保证。前台会话保持运行，Ctrl+C 请求清理。"
	msgStopped    = "所选系统服务及已观测 PPP 接口和路由的清理已确认；未验证全设备网络恢复。"
)

type targetsFlag []string

func (v *targetsFlag) String() string { return "" }
func (v *targetsFlag) Set(s string) error {
	if len(*v) >= 16 {
		return errors.New("too many targets")
	}
	*v = append(*v, s)
	return nil
}

type options struct {
	id, gateway string
	targets     []netip.Addr
	consent     macosvpn.ExistingServiceConsent
}

// Parse and validate every option before any system read, even on macOS.
func parse(args []string, out io.Writer) (options, bool, int) {
	var o options
	var targets targetsFlag
	f := flag.NewFlagSet("meridian-macos-service", flag.ContinueOnError)
	f.SetOutput(io.Discard) // flag errors can contain private user-supplied values.
	connect := f.Bool("connect-existing-service", false, "明确请求一次连接")
	f.StringVar(&o.id, "service-id", "", "现有系统服务标识")
	f.StringVar(&o.gateway, "expected-gateway", "", "预期网关，逐字匹配")
	f.Var(&targets, "target", "待验证的数字目标 IP，可重复指定")
	f.BoolVar(&o.consent.NetworkChanges, "allow-network-changes", false, "允许本次网络变更")
	f.BoolVar(&o.consent.SavedSystemCredentials, "allow-saved-system-credentials", false, "允许使用系统保存凭据")
	f.BoolVar(&o.consent.SharedSystemService, "allow-shared-system-service", false, "允许操作共享系统服务")
	f.BoolVar(&o.consent.LimitedVerification, "accept-limited-verification", false, "接受有限验证")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(out, usage)
			return o, false, 0
		}
		fmt.Fprintln(out, msgInvalid)
		return o, false, 2
	}
	if len(args) == 0 {
		fmt.Fprintln(out, "macOS 有限系统服务前台工具。请用 --help 查看用法；未读取系统服务，未建立连接。")
		return o, false, 0
	}
	c := o.consent
	valid := *connect && f.NArg() == 0 && c.NetworkChanges && c.SavedSystemCredentials && c.SharedSystemService && c.LimitedVerification
	seen := map[netip.Addr]bool{}
	for _, text := range targets {
		ip, err := netip.ParseAddr(text)
		if err != nil || ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() || ip.IsLoopback() || seen[ip] {
			valid = false
		}
		seen[ip] = true
		o.targets = append(o.targets, ip)
	}
	p := expectedProfile(o)
	if !valid || core.ValidateProfile(p) != nil {
		fmt.Fprintln(out, msgInvalid)
		return options{}, false, 2
	}
	return o, true, 0
}

func expectedProfile(o options) core.Profile {
	targets := make([]string, len(o.targets))
	for i, ip := range o.targets {
		targets[i] = ip.String()
	}
	return core.Profile{ID: o.id, Name: "现有 macOS 系统服务", Protocol: core.ProtocolMacOSSystemL2TP, Gateway: o.gateway,
		SystemService: &core.SystemServiceOptions{ServiceID: o.id, Targets: targets}}
}

type limitedAdapter interface {
	core.Adapter
	core.ScopedVerification
	LimitedProfile() (core.Profile, error)
}

// Selection and construction are injectable together, so tests never construct
// an actual native backend or call real Start/Stop on any host platform.
type selectedService struct {
	configuration macosvpn.ServiceConfiguration
	backend       func(macosvpn.ExistingServiceConsent, []netip.Addr) limitedAdapter
}
type dependencies struct {
	platform      string
	signals       <-chan os.Signal
	selectService func(context.Context, string) (selectedService, error)
}

func nativeSelection(ctx context.Context, id string) (selectedService, error) {
	selected, err := macosvpn.NewExistingServiceAdapter().Select(ctx, id)
	if err != nil {
		return selectedService{}, err
	}
	return selectedService{configuration: selected.Configuration(), backend: func(c macosvpn.ExistingServiceConsent, targets []netip.Addr) limitedAdapter {
		return macosvpn.NewLimitedExistingCoreAdapter(selected, c, targets)
	}}, nil
}

type operationResult struct {
	adapter   limitedAdapter
	session   core.Session
	err       error
	message   string
	uncertain bool
}

func start(ctx context.Context, o options, d dependencies) (r operationResult) {
	entered := false
	defer func() {
		if recover() != nil {
			r.err = errors.New("operation failed")
			r.uncertain = entered
			r.message = "系统服务检查未通过；未确认连接。"
		}
	}()
	selected, err := d.selectService(ctx, o.id)
	if err != nil || ctx.Err() != nil {
		r.err, r.message = errors.New("selection failed"), "所选服务检查未通过或已取消；未建立连接。"
		return
	}
	if selected.configuration.ServiceID != o.id || selected.configuration.Gateway != o.gateway || selected.backend == nil {
		r.err, r.message = errors.New("selection mismatch"), "所选服务或预期网关不匹配；未建立连接。"
		return
	}
	r.adapter = selected.backend(o.consent, slices.Clone(o.targets))
	if isNil(r.adapter) || r.adapter.VerificationScope() != core.SystemServiceTargetRoutes || !r.adapter.Capability().Available {
		r.err, r.message = errors.New("backend unavailable"), "有限验证后端不可用；未建立连接。"
		return
	}
	p, err := r.adapter.LimitedProfile()
	if err != nil || core.ValidateProfile(p) != nil || !reflect.DeepEqual(p, expectedProfile(o)) {
		r.err, r.message = errors.New("profile mismatch"), "服务与本次验证目标绑定不匹配；未建立连接。"
		return
	}
	if ctx.Err() != nil {
		r.err, r.message = ctx.Err(), "已取消；未建立连接。"
		return
	}
	entered = true
	r.session, r.err = r.adapter.Start(ctx, p, nil)
	r.message = "服务连接未通过验证；正在处理清理。"
	return
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func cleanupFailure(err error) bool {
	var cleanup *core.CleanupError
	return errors.As(err, &cleanup) || errors.Is(err, core.NewConnectionError(core.FailureCleanup))
}
func stop(s core.Session) (r operationResult) {
	defer func() {
		if recover() != nil {
			r.uncertain = true
		}
	}()
	r.err = s.Stop()
	return
}

// One operation worker serializes inspection, Start, and all Stop requests.
// The owner stays live during blocking native operations and uncertain cleanup.
// No timer or repeated signal spawns overlapping workers or network operations.
func run(args []string, out io.Writer, d dependencies) int {
	o, proceed, code := parse(args, out)
	if !proceed {
		return code
	}
	if d.platform != "darwin" || d.selectService == nil || d.signals == nil {
		fmt.Fprintln(out, "此连接入口仅适用于 macOS 前台会话；未读取系统服务，未建立连接。")
		return 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	operations := make(chan func() operationResult, 1)
	results := make(chan operationResult, 1)
	go func() {
		for op := range operations {
			results <- op()
		}
	}()
	defer close(operations)
	owner := &operationResult{}
	defer runtime.KeepAlive(owner)
	operations <- func() operationResult { return start(ctx, o, d) }
	fmt.Fprintln(out, msgWaiting)
	signals := d.signals
	var ready, done <-chan error
	inFlight, starting, requested, quarantined, poisoned, retry := true, true, false, false, false, false
	exitCode := 1
	drain := func() bool {
		uncertain := false
		select {
		case e := <-ready:
			uncertain = cleanupFailure(e)
			ready = nil
		default:
		}
		select {
		case e := <-done:
			uncertain = cleanupFailure(e) || uncertain
			done = nil
		default:
		}
		return uncertain
	}
	quarantine := func(poison bool) {
		cancel()
		quarantined = true
		poisoned = poisoned || poison
		if poisoned {
			fmt.Fprintln(out, msgPoisoned)
		} else {
			fmt.Fprintln(out, msgQuarantine)
		}
	}
	beginStop := func(manualRetry bool) {
		cancel()
		retry, inFlight = manualRetry, true
		if manualRetry {
			drain()
		} // Historical failures require this new explicit attempt.
		fmt.Fprintln(out, msgCleaning)
		operations <- func() operationResult { return stop(owner.session) }
	}
	for {
		select {
		case _, ok := <-signals:
			if !ok {
				signals = nil
				continue
			}
			requested, exitCode = true, 0
			cancel()
			if poisoned {
				fmt.Fprintln(out, msgPoisoned)
				continue
			}
			if inFlight {
				fmt.Fprintln(out, msgCancel)
				continue
			}
			if isNil(owner.session) {
				quarantine(true)
				continue
			}
			beginStop(quarantined)
		case r := <-results:
			inFlight = false
			if starting {
				starting = false
				*owner = r
				if r.uncertain {
					quarantine(true)
					continue
				}
				if isNil(r.session) {
					if cleanupFailure(r.err) {
						quarantine(true)
						continue
					}
					fmt.Fprintln(out, r.message)
					if requested {
						return 0
					}
					return 1
				}
				ready, done = r.session.Ready(), r.session.Done()
				if cleanupFailure(r.err) {
					quarantine(false)
					continue
				}
				if requested || r.err != nil {
					beginStop(false)
					continue
				}
				if ready == nil || done == nil {
					fmt.Fprintln(out, "会话缺少验证通知；不报告已连接。")
					beginStop(false)
					continue
				}
				if scoped, ok := r.session.(core.ScopedVerification); !ok || scoped.VerificationScope() != core.SystemServiceTargetRoutes {
					fmt.Fprintln(out, "会话验证范围不匹配；不报告已连接。")
					beginStop(false)
				}
				continue
			}
			pending := drain()
			if r.uncertain {
				quarantine(true)
				continue
			}
			if r.err != nil || (!retry && (pending || quarantined)) {
				quarantine(false)
				continue
			}
			// A successful explicit retry is fresh cleanup confirmation. Older
			// one-shot Ready/Done errors cannot erase that confirmation.
			fmt.Fprintln(out, msgStopped)
			return exitCode
		case err, ok := <-ready:
			ready = nil
			if quarantined || inFlight {
				if cleanupFailure(err) {
					quarantined = true
				}
				continue
			}
			if cleanupFailure(err) {
				quarantine(false)
				continue
			}
			if !ok || err != nil {
				fmt.Fprintln(out, "服务未通过有限验证；不报告已连接。")
				beginStop(false)
				continue
			}
			// A queued terminal result must win over simultaneous readiness.
			select {
			case ended := <-done:
				done = nil
				if cleanupFailure(ended) {
					quarantine(false)
				} else {
					beginStop(false)
				}
				continue
			default:
			}
			// Do not advertise readiness over an already queued shutdown signal.
			select {
			case _, open := <-signals:
				if open {
					requested, exitCode = true, 0
					beginStop(false)
					continue
				}
				signals = nil
			default:
			}
			if ctx.Err() != nil {
				beginStop(false)
				continue
			}
			fmt.Fprintln(out, msgReady)
		case err := <-done:
			done = nil
			if quarantined || inFlight {
				if cleanupFailure(err) {
					quarantined = true
				}
				continue
			}
			if cleanupFailure(err) {
				quarantine(false)
				continue
			}
			fmt.Fprintln(out, "所选系统服务已结束；停止报告已连接并确认清理。")
			beginStop(false)
		}
	}
}

func main() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	code := run(os.Args[1:], os.Stdout, dependencies{platform: runtime.GOOS, signals: signals, selectService: nativeSelection})
	signal.Stop(signals)
	os.Exit(code)
}
