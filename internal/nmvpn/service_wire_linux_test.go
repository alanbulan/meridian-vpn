//go:build linux && nmvpnintegration

package nmvpn

// These are real composition tests over a private dbus-daemon and synthetic NM.
// No real system bus, NM daemon, native worker, TUN, or netlink is used.
import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type serviceWireTrace struct {
	mu     sync.Mutex
	events []string
}

func (l *serviceWireTrace) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, s)
}
func (l *serviceWireTrace) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

type serviceWireManager struct {
	mu              sync.Mutex
	f               *nmWireFixture
	journal         ActivationJournal
	plan            PluginPlan
	trace           *serviceWireTrace
	adds, activates int
	omitConnect     bool
}

func (m *serviceWireManager) AddConnection2(sender dbus.Sender, profile map[string]map[string]dbus.Variant, flags uint32, args map[string]dbus.Variant) (dbus.ObjectPath, map[string]dbus.Variant, *dbus.Error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.adds++
	m.trace.add("AddConnection2")
	r, err := m.journal.LoadActivation()
	if err != nil || r == nil || r.Phase != "add-intent" || flags != 0x22 || len(args) != 0 || string(sender) != m.f.bus.UniqueName() {
		return "", nil, dbus.MakeFailedError(errors.New("missing durable add intent"))
	}
	plan := m.plan
	plan.Nonce = r.Nonce
	_, password, err := incomingProfile(profile, plan)
	if err != nil || password != "" || !profileEqual(profile["connection"]["autoconnect"], false) {
		return "", nil, dbus.MakeFailedError(errors.New("unsafe profile"))
	}
	m.f.service.mu.Lock()
	m.f.service.profile = profile
	m.f.service.mu.Unlock()
	return wireSettings, map[string]dbus.Variant{}, nil
}
func (m *serviceWireManager) ActivateConnection(sender dbus.Sender, settings, device, specific dbus.ObjectPath) (dbus.ObjectPath, *dbus.Error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activates++
	m.trace.add("ActivateConnection")
	r, err := m.journal.LoadActivation()
	if err != nil || r == nil || r.Phase != "activate-intent" || settings != wireSettings || device != "/" || specific != "/" || string(sender) != m.f.bus.UniqueName() {
		return "", dbus.MakeFailedError(errors.New("missing durable activate intent"))
	}
	if m.omitConnect {
		return wireActive, nil
	}
	m.f.service.mu.Lock()
	profile := make(map[string]map[string]dbus.Variant)
	for section, values := range m.f.service.profile {
		profile[section] = make(map[string]dbus.Variant)
		for key, value := range values {
			profile[section][key] = value
		}
	}
	m.f.service.mu.Unlock()
	profile["vpn"]["secrets"] = dbus.MakeVariant(map[string]string{"password": nmPluginWirePassword})
	// The callback must complete before ActivateConnection replies. This detects
	// accidental bus-lock retention by the production manager/composition.
	m.trace.add("Connect")
	if call := m.f.service.conn.Object(PluginService, PluginPath).CallWithContext(m.f.ctx, PluginInterface+".Connect", dbus.FlagNoAutoStart, profile); call.Err != nil {
		return "", dbus.MakeFailedError(errors.New("synchronous Connect failed"))
	}
	return wireActive, nil
}
func (m *serviceWireManager) counts() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.adds, m.activates
}
func (m *serviceWireManager) DeactivateConnection(sender dbus.Sender, path dbus.ObjectPath) *dbus.Error {
	m.trace.add("DeactivateConnection")
	return m.f.service.DeactivateConnection(sender, path)
}

type serviceWireBackend struct {
	*nmPluginWireBroker
	trace          *serviceWireTrace
	done           chan struct{}
	closeErr       error
	closes         int
	closeContextOK bool
	closeRelease   <-chan struct{}
}

func (b *serviceWireBackend) Binding() Binding      { return b.binding }
func (b *serviceWireBackend) Offer() Offer          { return b.offer }
func (b *serviceWireBackend) Done() <-chan struct{} { return b.done }
func (b *serviceWireBackend) Close(ctx context.Context) error {
	b.trace.add("Close")
	b.closes++
	_, bounded := ctx.Deadline()
	b.closeContextOK = ctx.Err() == nil && bounded
	if b.closeRelease != nil {
		select {
		case <-b.closeRelease:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return b.closeErr
}

type serviceWireFixture struct {
	*nmWireFixture
	config       ServiceConfig
	manager      *serviceWireManager
	trace        *serviceWireTrace
	backend      *serviceWireBackend
	activation   *Activation
	factoryCalls int
	policyCalls  int
	mode         string
	closeRelease chan struct{}
}

func newServiceWireFixture(t *testing.T) *serviceWireFixture {
	t.Helper()
	f := &nmWireFixture{socket: nmPrivateBus(t), ctx: nmContext(t)}
	f.service = nmInstallService(t, f.socket)
	if err := f.service.conn.BusObject().Call("org.freedesktop.DBus.GetId", 0).Store(&f.pin.BusID); err != nil {
		t.Fatal(err)
	}
	if err := f.service.conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, NMName).Store(&f.pin.Owner); err != nil {
		t.Fatal(err)
	}
	f.pin.BusUID = uint32(os.Geteuid())
	f.pin.OwnerUID = uint32(os.Geteuid())
	var err error
	f.bus, err = OpenPinnedBus(f.ctx, nmRawConn(t, f.socket), f.pin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.bus.Close() })
	// Deliberately neither ServePlugin nor ClaimPluginName here. Run owns both.
	plan, err := NewPluginPlan(wireUUID, "meridian0", "alice")
	if err != nil {
		t.Fatal(err)
	}
	aj, err := NewFileActivationJournal(privateJournalDir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = aj.Close() })
	pj, err := NewFileJournal(privateJournalDir(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pj.Close() })
	f.offer, f.policy = configFixture()
	w := &serviceWireFixture{nmWireFixture: f, trace: &serviceWireTrace{}}
	w.config = ServiceConfig{Bus: f.bus, Plan: plan, Network: nmSafeSettings(), Allowlist: f.policy, ActivationJournal: aj, PublicationJournal: pj,
		Boot: func(context.Context) (string, error) { return "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", nil }}
	w.manager = &serviceWireManager{f: f, journal: aj, plan: plan, trace: w.trace}
	if err = f.service.conn.ExportMethodTable(map[string]any{"AddConnection2": w.manager.AddConnection2}, managerSettingsPath, managerSettingsInterface); err != nil {
		t.Fatal(err)
	}
	if err = f.service.conn.ExportMethodTable(map[string]any{"ActivateConnection": w.manager.ActivateConnection, "DeactivateConnection": w.manager.DeactivateConnection}, NMPath, NMName); err != nil {
		t.Fatal(err)
	}
	w.config.Factory = &serviceTestFactory{preflight: func(context.Context) error {
		w.trace.add("factory preflight")
		if w.mode == "factory preflight" {
			return injectedError
		}
		return nil
	}, start: func(ctx context.Context, r *ActivationReceipt, a *Activation) (ServiceBackend, error) {
		w.factoryCalls++
		w.trace.add("factory Start")
		w.activation = a
		// Factory must receive the original receipt already correlated by Run.
		binding, err := r.RetainedCorrelation(ctx, a)
		if err != nil {
			return nil, err
		}
		if r.activation != a || binding.Identity.Session != "" || r.manager.record.Phase != "correlated" {
			return nil, errors.New("factory received uncorrelated receipt")
		}
		if err = a.UsePassword(ctx, func(password []byte) error {
			if string(password) != nmPluginWirePassword {
				return errors.New("wrong synthetic credential")
			}
			return nil
		}); err != nil {
			return nil, err
		}
		binding.Identity.Session = f.offer.Session
		if err = a.Bind(ctx, binding, f.offer); err != nil {
			return nil, err
		}
		b := &serviceWireBackend{nmPluginWireBroker: &nmPluginWireBroker{nmWireBroker: &nmWireBroker{binding: binding, offer: f.offer}, activation: a}, trace: w.trace, done: make(chan struct{}), closeRelease: w.closeRelease}
		w.backend = b
		switch w.mode {
		case "partial factory":
			return b, injectedError
		case "peer provenance":
			b.unsafe = true
		case "binding mismatch":
			b.binding.Identity.Session = strings.Repeat("f", 32)
		case "closed Done":
			close(b.done)
		case "nil Done":
			b.done = nil
		case "failed Close":
			b.closeErr = injectedError
		}
		return b, nil
	}}
	w.config.GlobalPolicy = &serviceTestPolicy{done: make(chan struct{}), preflight: func(context.Context) error {
		w.trace.add("policy preflight")
		if w.mode == "policy preflight" {
			return injectedError
		}
		return nil
	}, check: func(ctx context.Context, b Binding, o Offer) error {
		w.policyCalls++
		w.trace.add("publication policy")
		if w.mode == "mid policy revocation" && w.policyCalls == 2 {
			close(w.config.GlobalPolicy.(*serviceTestPolicy).done)
		}
		if w.mode == "second policy" && w.policyCalls == 2 {
			return injectedError
		}
		return nil
	}}
	return w
}
func (w *serviceWireFixture) newService(t *testing.T) *Service {
	t.Helper()
	s, err := NewService(w.config)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func (w *serviceWireFixture) state() uint32 {
	if w.activation == nil {
		return 0
	}
	p := w.activation.plugin
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}
func serviceWireState(t *testing.T, w *serviceWireFixture, ch <-chan *dbus.Signal, want uint32) {
	t.Helper()
	s := nmNextPluginSignal(t, w.ctx, ch)
	if s.Sender != w.bus.UniqueName() || s.Path != PluginPath || s.Name != PluginInterface+".StateChanged" || len(s.Body) != 1 || s.Body[0] != want {
		t.Fatalf("unexpected lifecycle signal: %#v", s)
	}
}

type serviceWireResult struct {
	result ServiceResult
	err    error
}

func TestNMVPNWireServiceActualCompositionLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "failed Close", "policy revoked", "backend ended", "Disconnect", "owner loss"} {
		t.Run(mode, func(t *testing.T) {
			w := newServiceWireFixture(t)
			w.mode = mode
			if mode == "Disconnect" {
				w.closeRelease = make(chan struct{})
			}
			s := w.newService(t)
			copied := &Service{self: s, config: s.config}
			if r, e := copied.Run(w.ctx); e == nil || r != (ServiceResult{}) || s.claimed.Load() {
				t.Fatal("copied service consumed original authority")
			}
			signals := nmSignals(t, w.service.conn)
			ctx, cancel := context.WithCancel(w.ctx)
			defer cancel()
			done := make(chan serviceWireResult, 1)
			go func() { r, e := s.Run(ctx); done <- serviceWireResult{r, e} }()
			serviceWireState(t, w, signals, 3)
			encoded, err := Encode(w.offer, w.policy)
			if err != nil {
				t.Fatal(err)
			}
			for _, part := range []struct {
				name    string
				payload map[string]dbus.Variant
			}{{"Config", encoded.General}, {"Ip4Config", encoded.IPv4}} {
				signal := nmNextPluginSignal(t, w.ctx, signals)
				if signal.Sender != w.bus.UniqueName() || signal.Path != PluginPath || signal.Name != PluginInterface+"."+part.name || len(signal.Body) != 1 || !reflect.DeepEqual(signal.Body[0], part.payload) {
					t.Fatalf("incorrect configuration: %#v", signal)
				}
			}
			serviceWireState(t, w, signals, 4)
			// Observing the signal alone is insufficient: stateLocked performs a final
			// pin readback after Emit. Join its mutex release before ending the
			// generation. This also synchronizes reads of the initialized backend.
			plugin := w.bus.plugin.Load()
			if plugin == nil {
				t.Fatal("Run did not retain plugin")
			}
			plugin.mu.Lock()
			plugin.mu.Unlock()
			// Startup timer finalization may still return errService on cancellation,
			// but cleanup must retain this exact bus for NM withdrawal and STOPPED.
			switch mode {
			case "policy revoked":
				close(w.config.GlobalPolicy.(*serviceTestPolicy).done)
			case "backend ended":
				close(w.backend.done)
			case "Disconnect":
				// The reader cancels Activation before dispatching Disconnect.
				// Hold the final local join until its handler emits STOPPING,
				// so MarkStopped cannot overtake the authenticated method reply.
				var release sync.Once
				unblock := func() { release.Do(func() { close(w.closeRelease) }) }
				defer unblock()
				if err := w.service.conn.Object(PluginService, PluginPath).CallWithContext(w.ctx, PluginInterface+".Disconnect", dbus.FlagNoAutoStart).Err; err != nil {
					t.Fatal("authenticated Disconnect failed", err)
				}
				serviceWireState(t, w, signals, 5)
				unblock()
			case "owner loss":
				if reply, err := w.service.conn.ReleaseName(NMName); err != nil || reply != dbus.ReleaseNameReplyReleased {
					t.Fatal("synthetic NM owner release failed", err)
				}
			default:
				cancel()
			}
			var got serviceWireResult
			select {
			case got = <-done:
			case <-w.ctx.Done():
				t.Fatal("Run failed to join cancellation")
			}
			if !got.result.Published || got.result.NetworkAbsent != (mode != "failed Close" && mode != "owner loss") || !got.result.ReconciliationRequired {
				t.Fatalf("incorrect result: %+v", got)
			}
			if (mode == "policy revoked" || mode == "backend ended" || mode == "Disconnect") && !errors.Is(got.err, errService) {
				t.Fatal("generation loss did not report lifecycle failure", got.err)
			}
			if mode == "owner loss" {
				if !errors.Is(got.err, errServiceCleanup) || !got.result.LocalStopped || !w.bus.invalid.Load() || !w.backend.stopped {
					t.Fatalf("owner loss did not retain uncertainty and join local handles: %+v", got)
				}
				// The invalidated plugin bus cannot report STOPPED. Local state
				// alone is not evidence that a state signal was delivered.
			} else if mode != "failed Close" {
				if (got.err != nil && !errors.Is(got.err, errService)) || !got.result.LocalStopped {
					t.Fatalf("successful lifecycle failed: %+v", got)
				}
				serviceWireState(t, w, signals, 6)
			} else {
				if got.err == nil || got.result.LocalStopped || w.state() == 6 {
					t.Fatal("failed local Close claimed STOPPED")
				}
			}
			if w.backend.closes != 1 || !w.backend.closeContextOK || w.factoryCalls != 1 || w.policyCalls != 2 {
				t.Fatal("factory, gate, or bounded cleanup count wrong")
			}
			w.service.mu.Lock()
			deactivations, caller, active := w.service.deactivations, w.service.caller, w.service.active
			w.service.mu.Unlock()
			if mode == "owner loss" {
				if deactivations != 0 || !active {
					t.Fatal("lost owner allowed NM withdrawal or invented absence")
				}
			} else if deactivations != 1 || caller != w.bus.UniqueName() || active {
				t.Fatal("ended generation lost pinned cleanup bus")
			}
			expected := []string{"factory preflight", "policy preflight", "AddConnection2", "ActivateConnection", "Connect", "factory Start", "publication policy", "publication policy", "DeactivateConnection", "Close"}
			if mode == "owner loss" {
				expected = append(expected[:8], "Close")
			}
			if !reflect.DeepEqual(w.trace.snapshot(), expected) {
				t.Fatal("incorrect composition order", w.trace.snapshot())
			}
			if r, e := w.config.PublicationJournal.Load(); mode == "owner loss" {
				if e != nil || r == nil || r.Phase != "quarantine" || r.Identity != w.backend.binding.Identity {
					t.Fatal("owner loss discarded exact publication recovery evidence", e)
				}
			} else if e != nil || r != nil {
				t.Fatal("proven removal retained publication journal", e)
			}
			if r, e := w.config.ActivationJournal.LoadActivation(); e != nil || r == nil || r.Phase != "quarantine" || r.ActivePath != string(wireActive) {
				t.Fatal("activation intent was lost", e)
			}
			if r, e := s.Run(context.Background()); e == nil || r != (ServiceResult{}) {
				t.Fatal("second Run replayed lifecycle")
			}
			if adds, activates := w.manager.counts(); adds != 1 || activates != 1 || w.backend.closes != 1 {
				t.Fatal("second Run repeated mutation or cleanup")
			}
		})
	}
}

func TestNMVPNWireServiceFailureBeforeAndDuringPublication(t *testing.T) {
	for _, mode := range []string{"partial factory", "peer provenance", "binding mismatch", "nil Done", "closed Done", "second policy"} {
		t.Run(mode, func(t *testing.T) {
			w := newServiceWireFixture(t)
			w.mode = mode
			s := w.newService(t)
			result, err := s.Run(w.ctx)
			if err == nil || strings.Contains(err.Error(), injectedError.Error()) || result.Published || result.NetworkAbsent || !result.LocalStopped || !result.ReconciliationRequired {
				t.Fatalf("failure not contained: %+v %v", result, err)
			}
			if w.factoryCalls != 1 || w.backend == nil || w.backend.closes != 1 || !w.backend.closeContextOK {
				t.Fatal("partially owned backend not joined exactly once")
			}
			wantSignals, wantPolicy, wantDeactivate := uint32(0), 0, 0
			if mode == "second policy" {
				wantSignals = 1
				wantPolicy = 2
				wantDeactivate = 1
			}
			if w.activation.plugin.published.Load() != wantSignals || w.policyCalls != wantPolicy || w.state() != 6 {
				t.Fatal("failure emitted STARTED/configuration or failed local stop")
			}
			w.service.mu.Lock()
			count := w.service.deactivations
			w.service.mu.Unlock()
			if count != wantDeactivate {
				t.Fatal("cleanup missing or replayed", count)
			}
			if r, e := w.config.ActivationJournal.LoadActivation(); e != nil || r == nil || r.Phase != "quarantine" {
				t.Fatal("failure lost activation intent")
			}
			if _, e := s.Run(w.ctx); e == nil {
				t.Fatal("failed Run replayed")
			}
			if adds, activates := w.manager.counts(); adds != 1 || activates != 1 || w.backend.closes != 1 {
				t.Fatal("failure replayed manager or close")
			}
		})
	}
}

func TestNMVPNWireServicePreflightAndRestartBarriers(t *testing.T) {
	for _, mode := range []string{"factory preflight", "policy preflight", "activation intent", "publication intent", "activation corrupt", "publication corrupt", "already canceled", "nil policy Done", "closed policy Done"} {
		t.Run(mode, func(t *testing.T) {
			w := newServiceWireFixture(t)
			w.mode = mode
			switch mode {
			case "nil policy Done":
				w.config.GlobalPolicy.(*serviceTestPolicy).done = nil
			case "closed policy Done":
				close(w.config.GlobalPolicy.(*serviceTestPolicy).done)
			case "activation intent":
				r := activationJournalFixture()
				if err := w.config.ActivationJournal.SaveActivation(r); err != nil {
					t.Fatal(err)
				}
			case "publication intent":
				if err := w.config.PublicationJournal.Save(journalFixture()); err != nil {
					t.Fatal(err)
				}
			case "activation corrupt":
				w.config.ActivationJournal = &activationMemoryJournal{corrupt: true}
			case "publication corrupt":
				w.config.PublicationJournal = &memoryJournal{trace: new([]string), loadErr: injectedError}
			}
			s := w.newService(t)
			ctx := w.ctx
			if mode == "already canceled" {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			result, err := s.Run(ctx)
			if err == nil || result.Published || result.LocalStopped || result.NetworkAbsent {
				t.Fatal("preflight or restart barrier admitted service")
			}
			wantReconcile := strings.Contains(mode, "intent") || strings.Contains(mode, "corrupt")
			if result.ReconciliationRequired != wantReconcile {
				t.Fatal("incorrect restart obligation")
			}
			if adds, activates := w.manager.counts(); adds != 0 || activates != 0 || w.factoryCalls != 0 || w.backend != nil || w.policyCalls != 0 || w.bus.plugin.Load() != nil {
				t.Fatal("barrier allowed plugin/manager/native side effects")
			}
			w.service.mu.Lock()
			count := w.service.deactivations
			w.service.mu.Unlock()
			if count != 0 {
				t.Fatal("barrier mutated NM")
			}
			if mode == "activation intent" {
				r, e := w.config.ActivationJournal.LoadActivation()
				if e != nil || r == nil || *r != activationJournalFixture() {
					t.Fatal("stale activation evidence rewritten")
				}
			}
			if mode == "publication intent" {
				r, e := w.config.PublicationJournal.Load()
				if e != nil || r == nil || *r != journalFixture() {
					t.Fatal("stale publication evidence rewritten")
				}
			}
		})
	}
}

func TestNMVPNWireServicePolicyRevokedBetweenSignals(t *testing.T) {
	w := newServiceWireFixture(t)
	w.mode = "mid policy revocation"
	s := w.newService(t)
	result, err := s.Run(w.ctx)
	if err == nil || result.Published || result.NetworkAbsent || !result.LocalStopped || !result.ReconciliationRequired {
		t.Fatalf("revocation escaped containment: %+v %v", result, err)
	}
	if w.backend == nil || w.backend.closes != 1 || !w.backend.closeContextOK || w.policyCalls != 2 || w.activation.plugin.published.Load() != 1 {
		t.Fatal("revoked policy allowed second signal or skipped local join")
	}
	// Revocation can win while Publish is still inside its pinned bus call.
	// In that case bus loss is intentional and STOPPED/network absence cannot
	// be claimed. In either ordering the generation must never reach STARTED.
	if w.state() == 4 {
		t.Fatal("revoked generation reached STARTED")
	}
	w.service.mu.Lock()
	deactivations := w.service.deactivations
	w.service.mu.Unlock()
	if deactivations > 1 {
		t.Fatal("revocation cleanup replayed NM withdrawal")
	}
	if r, e := w.config.ActivationJournal.LoadActivation(); e != nil || r == nil || r.Phase != "quarantine" {
		t.Fatal("revocation lost manager recovery evidence")
	}
	if _, e := s.Run(w.ctx); e == nil {
		t.Fatal("revoked service replayed")
	}
	if w.backend.closes != 1 || w.policyCalls != 2 {
		t.Fatal("revoked generation was reused")
	}
}

func TestNMVPNWireServiceMissingConnectIsBounded(t *testing.T) {
	w := newServiceWireFixture(t)
	w.manager.mu.Lock()
	w.manager.omitConnect = true
	w.manager.mu.Unlock()
	s := w.newService(t)
	// Allow durable fsync and manager replies ample CI time, but do not wait for
	// the production 60-second startup bound. The absent callback is deliberate.
	ctx, cancel := context.WithTimeout(w.ctx, time.Second)
	defer cancel()
	done := make(chan serviceWireResult, 1)
	go func() { r, e := s.Run(ctx); done <- serviceWireResult{r, e} }()
	var got serviceWireResult
	select {
	case got = <-done:
	case <-w.ctx.Done():
		t.Fatal("missing Connect left Receive unbounded")
	}
	if ctx.Err() != context.DeadlineExceeded || got.err == nil || got.result.Published || got.result.LocalStopped || got.result.NetworkAbsent || !got.result.ReconciliationRequired {
		t.Fatalf("missing Connect was not contained: %+v %v", got.result, got.err)
	}
	if w.factoryCalls != 0 || w.backend != nil || w.activation != nil || w.policyCalls != 0 {
		t.Fatal("missing Connect reached native or publication admission")
	}
	if adds, activates := w.manager.counts(); adds != 1 || activates != 1 {
		t.Fatal("manager transaction did not complete before Receive")
	}
	r, err := w.config.ActivationJournal.LoadActivation()
	if err != nil || r == nil || r.Phase != "quarantine" || r.ConnectionPath != string(wireSettings) || r.ActivePath != string(wireActive) {
		t.Fatal("missing Connect lost exact completed manager receipt", err)
	}
	if publication, e := w.config.PublicationJournal.Load(); e != nil || publication != nil {
		t.Fatal("missing Connect created publication intent")
	}
	plugin := w.bus.plugin.Load()
	if plugin == nil || plugin.activation.Load() != nil || plugin.published.Load() != 0 {
		t.Fatal("missing Connect created activation or configuration")
	}
	w.service.mu.Lock()
	deactivations := w.service.deactivations
	w.service.mu.Unlock()
	if deactivations != 0 {
		t.Fatal("unbound generation was deactivated")
	}
	expected := []string{"factory preflight", "policy preflight", "AddConnection2", "ActivateConnection"}
	if !reflect.DeepEqual(w.trace.snapshot(), expected) {
		t.Fatal("missing Connect crossed prepublication boundary", w.trace.snapshot())
	}
	if result, e := s.Run(w.ctx); e == nil || result != (ServiceResult{}) {
		t.Fatal("timed out service was replayable")
	}
	if adds, activates := w.manager.counts(); adds != 1 || activates != 1 {
		t.Fatal("missing Connect replayed manager mutation")
	}
}
