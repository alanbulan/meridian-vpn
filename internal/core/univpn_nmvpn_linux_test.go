//go:build linux

package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mygo-vpn/internal/nmvpn"
	"mygo-vpn/internal/packetrelay"
)

// These fixtures never launch a process, contact D-Bus, open a socket, create a
// TUN, change networking, or read a real credential. Only the private seam can
// inject these objects; the public constructor keeps concrete native provenance.
type nmBridgeActivation struct {
	ctx        context.Context
	cancel     context.CancelFunc
	password   []byte
	uses       int
	bindErr    error
	receiptErr error
	binding    nmvpn.Binding
	offer      nmvpn.Offer
	bound      bool
}

func (a *nmBridgeActivation) Context() context.Context { return a.ctx }
func (a *nmBridgeActivation) UUID() string             { return "11111111-2222-3333-4444-555555555555" }
func (a *nmBridgeActivation) Interface() string        { return "meridian0" }
func (a *nmBridgeActivation) Nonce() string            { return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
func (a *nmBridgeActivation) CheckReceipt(ctx context.Context, b nmvpn.Binding) error {
	if a.receiptErr != nil || !validUniVPNNMReceipt(b, a) {
		return errors.New("receipt does not match local pins")
	}
	return a.CheckLive(ctx)
}
func (a *nmBridgeActivation) CheckLive(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return a.ctx.Err()
}
func (a *nmBridgeActivation) UsePassword(ctx context.Context, fn func([]byte) error) error {
	if a.uses != 0 || a.CheckLive(ctx) != nil {
		return errors.New("unavailable")
	}
	a.uses++
	p := append([]byte(nil), a.password...)
	clear(a.password)
	defer clear(p)
	return fn(p)
}
func (a *nmBridgeActivation) Bind(ctx context.Context, b nmvpn.Binding, o nmvpn.Offer) error {
	if a.bindErr != nil || a.bound || a.CheckLive(ctx) != nil {
		return errors.New("binding rejected")
	}
	a.binding, a.offer, a.bound = b, cloneUniVPNNMOffer(o), true
	return nil
}
func (a *nmBridgeActivation) VerifyBinding(b nmvpn.Binding, o nmvpn.Offer) error {
	if !a.bound || a.binding != b || !reflect.DeepEqual(a.offer, o) {
		return errors.New("binding mismatch")
	}
	return nil
}

type nmBridgePacket struct{ closes atomic.Int32 }

func (*nmBridgePacket) ReadPacket([]byte) (int, error)  { return 0, io.EOF }
func (*nmBridgePacket) WritePacket(b []byte) (int, error) { return len(b), nil }
func (p *nmBridgePacket) Close() error                  { p.closes.Add(1); return nil }

type nmBridgeProcess struct {
	done, waiting, returned chan struct{}
	stopOnce               sync.Once
	waits, stops           atomic.Int32
	blockStop              bool
	waitErr                error
}

func (p *nmBridgeProcess) Wait() error {
	p.waits.Add(1)
	close(p.waiting)
	<-p.done
	close(p.returned)
	return p.waitErr
}
func (p *nmBridgeProcess) Stop() error {
	p.stops.Add(1)
	if !p.blockStop {
		p.stopOnce.Do(func() { close(p.done) })
	}
	return nil
}

type nmBridgeSource struct {
	process *nmBridgeProcess
	packet  *nmBridgePacket
	offer   UniVPNOffer
	err, closedErr error
}

func (s *nmBridgeSource) WaitOffer(ctx context.Context, p UniVPNNativeProcess) (UniVPNOffer, packetrelay.PacketIO, error) {
	if p != s.process {
		return UniVPNOffer{}, nil, errors.New("wrong process")
	}
	select {
	case <-ctx.Done():
		return UniVPNOffer{}, nil, ctx.Err()
	case <-s.process.waiting: // Wait must already have its single owner.
	}
	return cloneUniVPNOffer(s.offer), s.packet, s.err
}
func (s *nmBridgeSource) CheckLive(ctx context.Context, p UniVPNNativeProcess) error {
	if p != s.process || ctx.Err() != nil {
		return errors.New("not live")
	}
	select {
	case <-s.process.done:
		return errors.New("worker exited")
	default:
		return nil
	}
}
func (s *nmBridgeSource) ProveClosed(ctx context.Context, p UniVPNNativeProcess) error {
	if p != s.process || ctx.Err() != nil || s.closedErr != nil {
		return errors.New("closure unproven")
	}
	select {
	case <-s.process.returned:
		return nil
	default:
		return errors.New("not joined")
	}
}

type nmBridgeHost struct {
	mu sync.Mutex
	receipt nmvpn.Binding
	attachedBinding nmvpn.Binding
	attachedOffer nmvpn.Offer
	packet packetrelay.PacketIO
	attachErr, verifyErr, liveErr, stopErr, absenceErr error
	attaches, verifies, lives, stops, absences int
}

func (h *nmBridgeHost) Binding() nmvpn.Binding {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.receipt
}
func (h *nmBridgeHost) Attach(_ context.Context, b nmvpn.Binding, o nmvpn.Offer, p packetrelay.PacketIO) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.attaches++
	h.attachedBinding, h.attachedOffer, h.packet = b, cloneUniVPNNMOffer(o), p
	// A provider receives its own copy, not the frozen offer used later.
	if len(o.Routes) > 0 {
		o.Routes[0] = netip.MustParsePrefix("192.0.2.0/24")
	}
	return h.attachErr
}
func (h *nmBridgeHost) Verify(_ context.Context, b nmvpn.Binding, o nmvpn.Offer) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.verifies++
	if h.verifyErr != nil || h.attachedBinding != b || !reflect.DeepEqual(h.attachedOffer, o) {
		return errors.New("host receipt not proven")
	}
	return nil
}
func (h *nmBridgeHost) CheckLive(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lives++
	if h.stops != 0 {
		return errors.New("host no longer live")
	}
	return h.liveErr
}
func (h *nmBridgeHost) StopLocal(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stops++
	if h.packet != nil {
		_ = h.packet.Close()
		h.packet = nil
	}
	return h.stopErr
}
func (h *nmBridgeHost) ProveAbsent(context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.absences++
	if h.stops != 1 {
		return errors.New("host not stopped")
	}
	return h.absenceErr
}

type nmBridgeFixture struct {
	a *nmBridgeActivation
	p *nmBridgeProcess
	s *nmBridgeSource
	h *nmBridgeHost
	policy nmvpn.Policy
	deps uniVPNNMDependencies
	launches int
	secret []byte
	order []string
}

func newNMBridgeFixture(t *testing.T) *nmBridgeFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	f := &nmBridgeFixture{a: &nmBridgeActivation{ctx: ctx, cancel: cancel, password: []byte("synthetic-password")}}
	f.p = &nmBridgeProcess{done: make(chan struct{}), waiting: make(chan struct{}), returned: make(chan struct{})}
	f.s = &nmBridgeSource{process: f.p, packet: &nmBridgePacket{}, offer: UniVPNOffer{
		Session: "0123456789abcdef0123456789abcdef",
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.20.30.7/24")},
		Routes: []netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")},
		Endpoint: netip.MustParseAddr("192.0.2.1"),
	}}
	f.h = &nmBridgeHost{receipt: nmvpn.Binding{
		Identity: nmvpn.Identity{BootID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", BusID: "11111111111111111111111111111111", Owner: ":1.7", UUID: f.a.UUID(), ActivePath: "/org/freedesktop/NetworkManager/ActiveConnection/17", Interface: f.a.Interface()},
		ConnectionPath: "/org/freedesktop/NetworkManager/Settings/9", PluginOwner: ":1.8",
	}}
	f.policy = nmvpn.Policy{Addresses: append([]netip.Prefix(nil), f.s.offer.Addresses...), Endpoints: []netip.Addr{f.s.offer.Endpoint}, Routes: append([]netip.Prefix(nil), f.s.offer.Routes...)}
	f.deps = uniVPNNMDependencies{
		authorize: func(context.Context) (UniVPNNMHostBinding, error) { f.order = append(f.order, "authorize"); return f.h, nil },
		launch: func(_ context.Context, password []byte) (UniVPNNativeProcess, error) {
			f.order = append(f.order, "launch")
			f.launches++
			f.secret = password // deliberate test-only retention to assert erasure
			if string(password) != "synthetic-password" { return nil, errors.New("wrong test secret") }
			return f.p, nil
		},
		source: f.s,
	}
	t.Cleanup(cancel)
	return f
}

func (f *nmBridgeFixture) start(t *testing.T) *UniVPNNMBroker {
	t.Helper()
	b, err := startUniVPNNM(context.Background(), f.a, f.policy, f.deps)
	if err != nil || b == nil { t.Fatal("start", err) }
	t.Cleanup(func() { _ = b.Close(context.Background()) })
	return b
}

func TestUniVPNNMBrokerBoundLifecycle(t *testing.T) {
	f := newNMBridgeFixture(t)
	b := f.start(t)
	if !reflect.DeepEqual(f.order, []string{"authorize", "launch"}) || f.launches != 1 || f.a.uses != 1 || !bytes.Equal(f.secret, make([]byte, len(f.secret))) || !bytes.Equal(f.a.password, make([]byte, len(f.a.password))) {
		t.Fatal("authorization order or credential ownership")
	}
	id, offer := b.Binding(), b.Offer()
	if id.Identity.Session != f.s.offer.Session || offer.Interface != f.a.Interface() || b.Verify(context.Background(), id, offer) != nil { t.Fatal("native binding missing") }
	if b.VerifyPublish(context.Background(), id, offer) != nil { t.Fatal("live publication refused") }
	if b.ProveAbsent(context.Background(), id) == nil { t.Fatal("absence before stop") }
	// Copies returned to callers/providers cannot rewrite the frozen plan.
	offer.Routes[0] = netip.MustParsePrefix("10.60.0.0/16")
	if b.Verify(context.Background(), id, offer) == nil || b.Offer().Routes[0] != f.s.offer.Routes[0] { t.Fatal("mutable plan") }
	if b.Stop(context.Background(), id) != nil { t.Fatal("stop") }
	f.a.cancel() // retained provenance must survive Disconnect.
	if b.Verify(context.Background(), id, b.Offer()) != nil || b.ProveAbsent(context.Background(), id) != nil { t.Fatal("stopped provenance lost") }
	if b.VerifyPublish(context.Background(), id, b.Offer()) == nil { t.Fatal("stopped native could publish") }
	if b.Stop(context.Background(), id) != nil || f.p.waits.Load() != 1 || f.p.stops.Load() != 1 || f.s.packet.closes.Load() != 1 { t.Fatal("duplicate lifecycle ownership") }
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	if f.h.attaches != 1 || f.h.stops != 1 || f.h.absences != 1 { t.Fatal("wrong host lifecycle") }
}

func TestUniVPNNMBrokerRejectsEveryIdentitySubstitution(t *testing.T) {
	f := newNMBridgeFixture(t)
	b := f.start(t)
	changes := []func(*nmvpn.Binding){
		func(b *nmvpn.Binding) { b.Identity.BootID = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee" },
		func(b *nmvpn.Binding) { b.Identity.BusID = strings.Repeat("2", 32) },
		func(b *nmvpn.Binding) { b.Identity.Owner = ":1.9" },
		func(b *nmvpn.Binding) { b.Identity.UUID = "22222222-2222-3333-4444-555555555555" },
		func(b *nmvpn.Binding) { b.Identity.ActivePath += "0" },
		func(b *nmvpn.Binding) { b.Identity.Session = strings.Repeat("2", 32) },
		func(b *nmvpn.Binding) { b.Identity.Interface = "meridian1" },
		func(b *nmvpn.Binding) { b.ConnectionPath += "0" },
		func(b *nmvpn.Binding) { b.PluginOwner = ":1.9" },
	}
	for _, change := range changes {
		id := b.Binding(); change(&id)
		if b.Verify(context.Background(), id, b.Offer()) == nil || b.Stop(context.Background(), id) == nil || b.ProveAbsent(context.Background(), id) == nil { t.Fatal("accepted substitution") }
	}
	if f.p.stops.Load() != 0 { t.Fatal("wrong binding stopped the worker") }
}

func TestUniVPNNMBrokerFailureRetainsAuthorityAndClearsSecrets(t *testing.T) {
	secretError := errors.New("backend contains synthetic-password")
	tests := map[string]func(*nmBridgeFixture){
		"authorization": func(f *nmBridgeFixture) { f.deps.authorize = func(context.Context) (UniVPNNMHostBinding, error) { return f.h, secretError } },
		"wrong activation receipt": func(f *nmBridgeFixture) { f.h.receipt.Identity.UUID = "22222222-2222-3333-4444-555555555555" },
		"preassigned native session": func(f *nmBridgeFixture) { f.h.receipt.Identity.Session = f.s.offer.Session },
		"local receipt pins": func(f *nmBridgeFixture) { f.a.receiptErr = secretError },
		"launch": func(f *nmBridgeFixture) { f.deps.launch = func(_ context.Context, p []byte) (UniVPNNativeProcess, error) { f.secret = p; return f.p, secretError } },
		"offer": func(f *nmBridgeFixture) { f.s.err = secretError },
		"wrong session": func(f *nmBridgeFixture) { f.s.offer.Session = "not-a-native-generation" },
		"DNS": func(f *nmBridgeFixture) { f.s.offer.DNS = []netip.Addr{netip.MustParseAddr("10.20.30.53")} },
		"unapproved offer": func(f *nmBridgeFixture) { f.policy.Routes = nil },
		"activation bind": func(f *nmBridgeFixture) { f.a.bindErr = secretError },
		"partial attach": func(f *nmBridgeFixture) { f.h.attachErr = secretError },
		"host provenance": func(f *nmBridgeFixture) { f.h.verifyErr = secretError },
		"host live policy": func(f *nmBridgeFixture) { f.h.liveErr = secretError },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			f := newNMBridgeFixture(t); change(f)
			b, err := startUniVPNNM(context.Background(), f.a, f.policy, f.deps)
			if b == nil || err == nil || b.host != f.h || strings.Contains(err.Error(), "synthetic-password") { t.Fatal("lost authority or leaked error", err) }
			if !bytes.Equal(f.secret, make([]byte, len(f.secret))) { t.Fatal("secret not cleared") }
			if b.VerifyPublish(context.Background(), b.Binding(), b.Offer()) == nil { t.Fatal("failed start became publishable") }
			if b.Close(context.Background()) != nil { t.Fatal("clean local teardown failed") }
			if b.process != nil && (f.p.waits.Load() != 1 || f.p.stops.Load() != 1) { t.Fatal("worker not joined exactly once") }
			f.h.mu.Lock(); stops := f.h.stops; attaches := f.h.attaches; f.h.mu.Unlock()
			if stops != 1 { t.Fatal("host recovery not invoked") }
			if b.process != nil && (attaches > 0 || f.s.err != nil || name != "launch") && f.s.packet.closes.Load() != 1 { t.Fatal("packet ownership lost") }
		})
	}
}

func TestUniVPNNMBrokerCleanupUncertaintyIsSticky(t *testing.T) {
	for _, which := range []string{"containment", "host", "wait"} {
		t.Run(which, func(t *testing.T) {
			f := newNMBridgeFixture(t)
			if which == "containment" { f.s.closedErr = errors.New("unproven") }
			if which == "host" { f.h.stopErr = errors.New("uncertain") }
			if which == "wait" { f.p.waitErr = &CleanupError{} }
			b := f.start(t)
			var cleanup *CleanupError
			if err := b.Stop(context.Background(), b.Binding()); !errors.As(err, &cleanup) { t.Fatal("cleanup uncertainty lost", err) }
			if b.Close(context.Background()) == nil || b.ProveAbsent(context.Background(), b.Binding()) == nil || b.VerifyPublish(context.Background(), b.Binding(), b.Offer()) == nil { t.Fatal("uncertainty became publication or cleanup success") }
			if b.Verify(context.Background(), b.Binding(), b.Offer()) != nil { t.Fatal("uncertainty discarded immutable recovery authority") }
			if b.host != f.h || b.process != f.p || f.p.stops.Load() != 1 { t.Fatal("lost or retried owned handles") }
			f.h.mu.Lock(); defer f.h.mu.Unlock()
			if f.h.stops != 1 || f.h.absences != 0 { t.Fatal("retried mutation or claimed absence") }
		})
	}
}

func TestUniVPNNMBrokerDisconnectStopsOnlyLocalHandles(t *testing.T) {
	f := newNMBridgeFixture(t)
	b := f.start(t)
	f.a.cancel()
	select {
	case <-f.p.returned:
	case <-time.After(time.Second): t.Fatal("Disconnect did not stop the worker")
	}
	if b.Close(context.Background()) != nil { t.Fatal("local cleanup incomplete") }
	f.h.mu.Lock(); defer f.h.mu.Unlock()
	if f.h.absences != 0 || f.h.stops != 1 { t.Fatal("automatic cleanup claimed networking absence") }
}

func TestUniVPNNMBrokerNaturalExitStopsRelay(t *testing.T) {
	f := newNMBridgeFixture(t)
	b := f.start(t)
	f.p.stopOnce.Do(func() { close(f.p.done) })
	select {
	case <-b.run.Done():
	case <-time.After(time.Second): t.Fatal("worker exit was ignored")
	}
	if b.Close(context.Background()) != nil || f.s.packet.closes.Load() != 1 { t.Fatal("relay not joined after exit") }
}

func TestUniVPNNMBrokerStopDeadlineRetainsUncertainWorker(t *testing.T) {
	f := newNMBridgeFixture(t)
	f.p.blockStop = true
	b := f.start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if b.Stop(ctx, b.Binding()) == nil { t.Fatal("unjoined worker accepted") }
	f.p.stopOnce.Do(func() { close(f.p.done) }) // release only our in-memory fixture
	<-f.p.returned
	if b.Close(context.Background()) == nil || f.p.stops.Load() != 1 || b.process != f.p { t.Fatal("uncertain stop retried or forgotten") }
}

func TestUniVPNNMBrokerChangedHostReceiptNeverTargetsReplacement(t *testing.T) {
	f := newNMBridgeFixture(t)
	b := f.start(t)
	f.h.mu.Lock(); f.h.receipt.Identity.Interface = "replacement0"; f.h.mu.Unlock()
	if b.Stop(context.Background(), b.Binding()) == nil || f.p.stops.Load() != 1 { t.Fatal("local worker not stopped or replacement accepted") }
	f.h.mu.Lock(); defer f.h.mu.Unlock()
	if f.h.stops != 0 || f.h.absences != 0 || b.host != f.h { t.Fatal("targeted replacement or lost evidence") }
	_ = f.s.packet.Close() // fixture only; bridge correctly retained uncertainty
}

func TestUniVPNNMBrokerMissingAuthorityAndPublicGuards(t *testing.T) {
	f := newNMBridgeFixture(t)
	f.deps.authorize = func(context.Context) (UniVPNNMHostBinding, error) { return nil, errors.New("no trusted receipt") }
	if b, err := startUniVPNNM(context.Background(), f.a, f.policy, f.deps); b != nil || err == nil || f.launches != 0 || f.a.uses != 0 { t.Fatal("launch without authority") }
	if b, err := StartUniVPNNMBroker(context.Background(), nil, nil, "", nil, nmvpn.Policy{}, nil); b != nil || err == nil { t.Fatal("public nil guard") }
	if b, err := startUniVPNNM(context.Background(), nil, f.policy, f.deps); b != nil || err == nil { t.Fatal("private nil activation guard") }
}

func TestUniVPNNMBrokerCanceledOperationsDoNotMutate(t *testing.T) {
	f := newNMBridgeFixture(t)
	b := f.start(t)
	ctx, cancel := context.WithCancel(context.Background()); cancel()
	if b.Verify(ctx, b.Binding(), b.Offer()) == nil || b.Stop(ctx, b.Binding()) == nil || b.ProveAbsent(ctx, b.Binding()) == nil { t.Fatal("accepted canceled operation") }
	if f.p.stops.Load() != 0 { t.Fatal("canceled call mutated") }
	// Waiting for another operation's gate is also cancellation-aware.
	<-b.gate
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if b.Verify(ctx, b.Binding(), b.Offer()) == nil { t.Fatal("lock contention ignored cancellation") }
	b.gate <- struct{}{}
}

func TestUniVPNNMBrokerFailedLaunchRetainsCleanupMarkerAndProviders(t *testing.T) {
	for _, stage := range []string{"authorize", "launch", "offer"} {
		t.Run(stage, func(t *testing.T) {
			f := newNMBridgeFixture(t)
			pin := &UniVPNExecLauncher{Executable: "/synthetic-never-executed"}
			f.deps.launcher = pin
			switch stage {
			case "authorize":
				f.deps.authorize = func(context.Context) (UniVPNNMHostBinding, error) {
					return nil, &CleanupError{}
				}
			case "launch":
				f.deps.launch = func(_ context.Context, password []byte) (UniVPNNativeProcess, error) {
					f.secret = password
					return nil, &CleanupError{}
				}
			case "offer":
				f.s.err = &CleanupError{}
			}
			b, err := startUniVPNNM(context.Background(), f.a, f.policy, f.deps)
			var cleanup *CleanupError
			if b == nil || b.launcher != pin || !errors.As(err, &cleanup) {
				t.Fatal("unproven acquisition discarded recovery authority", err)
			}
			if b.Close(context.Background()) == nil || b.VerifyPublish(context.Background(), b.Binding(), b.Offer()) == nil {
				t.Fatal("unproven acquisition became success")
			}
			if !bytes.Equal(f.secret, make([]byte, len(f.secret))) {
				t.Fatal("failed launch retained secret")
			}
		})
	}
}

func TestUniVPNNMBrokerRejectsNativePasswordGrammarBeforeLaunch(t *testing.T) {
	for _, password := range []string{"", "line\nbreak", "carriage\rreturn", "nul\x00byte", strings.Repeat("x", 4096)} {
		f := newNMBridgeFixture(t)
		f.a.password = []byte(password)
		b, err := startUniVPNNM(context.Background(), f.a, f.policy, f.deps)
		if b == nil || err == nil || f.launches != 0 || f.a.uses != 1 || b.Close(context.Background()) != nil {
			t.Fatal("invalid native password launched a worker")
		}
		if !bytes.Equal(f.a.password, make([]byte, len(f.a.password))) {
			t.Fatal("rejected password not erased")
		}
	}
}

func TestUniVPNNMStartupDeadlineJoinsWinningCallback(t *testing.T) {
	t.Run("stopped before deadline", func(t *testing.T) {
		var calls atomic.Int32
		finish := uniVPNNMStartupDeadline(time.Hour, func() { calls.Add(1) })
		finish()
		finish() // repeated join cannot wait for a callback that never ran
		if calls.Load() != 0 {
			t.Fatal("stopped timer canceled the successful lifetime")
		}
	})
	t.Run("winning callback joined", func(t *testing.T) {
		entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
		finish := uniVPNNMStartupDeadline(0, func() {
			close(entered)
			<-release
		})
		<-entered
		go func() { finish(); close(joined) }()
		select {
		case <-joined:
			t.Fatal("timer stop did not join the winning callback")
		case <-time.After(10 * time.Millisecond):
		}
		close(release)
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Fatal("completed callback did not release join")
		}
		finish()
	})
}
