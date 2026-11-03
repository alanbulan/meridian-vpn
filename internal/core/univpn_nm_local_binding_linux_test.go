//go:build linux

package core

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"mygo-vpn/internal/nmvpn"
	"mygo-vpn/internal/packetrelay"
)

// These are core orchestration tests, not real NM/TUN acceptance. Only the
// private seam substitutes receipt and relay observations. Packet endpoints are
// actual unnamed local socketpairs; the process reader uses temporary files.
// No command is started, real TUN opened, bus contacted, or host policy changed.
type uniVPNLocalFixture struct {
	proc         *uniVPNProcFixture
	b            *UniVPNNMBroker
	p            *uniVPNExecProcess
	a            *nmBridgeActivation
	h            *nmBridgeHost
	provider     *UniVPNPacketPairProvider
	native       uniVPNPacketNative
	child        *packetrelay.DatagramPackets
	receipt      *nmvpn.ActivationReceipt
	relay        *packetrelay.TUNRelay
	correlations atomic.Int32
	observations atomic.Int32
	checks       atomic.Int32
	finished     sync.Once
}

func newUniVPNLocalFixture(t *testing.T) *uniVPNLocalFixture {
	t.Helper()
	f := &uniVPNLocalFixture{proc: newUniVPNProcFixture(t), provider: NewUniVPNPacketPairProvider()}
	f.b, f.p = uniVPNFixtureBroker(f.proc)
	b, p := f.b, f.p
	b.self = b
	b.run, b.cancel = context.WithCancel(context.Background())
	b.unhook = func() bool { return false }
	t.Cleanup(b.cancel)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f.a = &nmBridgeActivation{ctx: ctx, cancel: cancel, bound: true}
	b.activation = f.a
	b.receipt = nmvpn.Binding{
		Identity: nmvpn.Identity{
			BootID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", BusID: strings.Repeat("1", 32),
			Owner: ":1.7", UUID: f.a.UUID(), ActivePath: "/org/freedesktop/NetworkManager/ActiveConnection/17", Interface: f.a.Interface(),
		},
		ConnectionPath: "/org/freedesktop/NetworkManager/Settings/9", PluginOwner: ":1.8",
	}
	b.binding = b.receipt
	b.binding.Identity.Session = p.sessionID
	b.offer = nmvpn.Offer{
		Session: p.sessionID, Interface: f.a.Interface(), Address: netip.MustParsePrefix("10.20.30.7/24"),
		Endpoint: netip.MustParseAddr("192.0.2.1"), Routes: []netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")},
		DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, Domains: []string{"test.invalid"},
	}
	f.a.binding, f.a.offer = b.binding, cloneUniVPNNMOffer(b.offer)
	f.h = &nmBridgeHost{receipt: b.receipt, attachedBinding: b.binding, attachedOffer: cloneUniVPNNMOffer(b.offer)}
	b.host = f.h
	b.source = UniVPNNativeOfferSource{}
	p.offer = newUniVPNOfferChannel()
	p.offer.offer = &UniVPNOffer{Session: p.sessionID, Addresses: []netip.Prefix{b.offer.Address}, Routes: append([]netip.Prefix(nil), b.offer.Routes...), Endpoint: b.offer.Endpoint}
	close(p.offer.ready)
	p.contained = make(chan struct{})
	var endpoint packetrelay.PacketIO
	var err error
	f.native, endpoint, err = acquireUniVPNPacket(context.Background(), f.provider, p.sessionID, duplicateUniVPNPacket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.native.owner.Close() })
	t.Cleanup(func() { _ = endpoint.Close() })
	var ok bool
	f.child, ok = endpoint.(*packetrelay.DatagramPackets)
	if !ok || f.child == nil {
		t.Fatal("concrete pair endpoint missing")
	}
	cmd, _ := packetWiringCmd(t)
	p.cmd, p.packet = cmd, endpoint
	if err := wireUniVPNPacket(p.cmd, f.native.file); err != nil {
		t.Fatal(err)
	}
	if err := retainUniVPNPacketProvenance(p, f.provider, f.native); err != nil {
		t.Fatal(err)
	}
	_, transferred, err := b.source.WaitOffer(context.Background(), p)
	if err != nil || transferred != f.child || !nilInterface(p.packet) {
		t.Fatal("native source did not transfer the original endpoint", err)
	}
	f.h.packet = transferred
	// These zero objects are identity placeholders ONLY for the private seam.
	// Their public methods cannot mint a valid NM receipt or relay binding.
	f.receipt, f.relay = &nmvpn.ActivationReceipt{}, &packetrelay.TUNRelay{}
	return f
}

func (f *uniVPNLocalFixture) inputs(receipt *nmvpn.ActivationReceipt, relay *packetrelay.TUNRelay) uniVPNNMLocalInputs {
	expected := f.b.receipt
	return uniVPNNMLocalInputs{
		receipt: receipt, relay: relay,
		correlate: func(ctx context.Context) (nmvpn.Binding, error) {
			f.correlations.Add(1)
			if ctx.Err() != nil || receipt != f.receipt {
				return nmvpn.Binding{}, errUniVPNNM
			}
			return expected, nil
		},
		observeRelay: func(ctx context.Context, child *packetrelay.DatagramPackets, name string) (packetrelay.TUNRelayBinding, packetrelay.TUNObservation, error) {
			f.observations.Add(1)
			if ctx.Err() != nil || relay != f.relay || child != f.child || name != expected.Identity.Interface {
				return packetrelay.TUNRelayBinding{}, packetrelay.TUNObservation{}, errUniVPNNM
			}
			return packetrelay.TUNRelayBinding{}, packetrelay.TUNObservation{Name: name, Flags: 0x1001}, nil
		},
		checkRelay: func(_ packetrelay.TUNRelayBinding, child *packetrelay.DatagramPackets) error {
			f.checks.Add(1)
			if relay != f.relay || child != f.child {
				return errUniVPNNM
			}
			return nil
		},
	}
}

func (f *uniVPNLocalFixture) retain(ctx context.Context) (*UniVPNNMLocalBinding, error) {
	return f.b.retainLocalBinding(ctx, f.inputs(f.receipt, f.relay))
}

func (f *uniVPNLocalFixture) finishProcess() {
	// Model the terminal lifecycle without executing, signaling, or waiting on
	// a real worker. Close then takes its already-exited branch.
	f.finished.Do(func() {
		f.p.offer.mu.Lock()
		f.p.offer.terminal = true
		f.p.offer.mu.Unlock()
		close(f.p.offer.done)
		close(f.p.exited)
		close(f.p.contained)
		close(f.b.waitDone)
		_ = f.proc.obs.close()
	})
}

func assertUniVPNLocalPairOpen(t *testing.T, f *uniVPNLocalFixture) {
	t.Helper()
	if err := f.native.file.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.child.WritePacket([]byte("retained-owner")); err != nil {
		t.Fatal("non-owning binding attempt closed the child", err)
	}
	buf := make([]byte, 64)
	if n, err := f.native.owner.ReadPacket(buf); err != nil || string(buf[:n]) != "retained-owner" {
		t.Fatal("non-owning binding attempt changed packet ownership", err)
	}
}

func TestUniVPNNMLocalBindingPrivateSuccessAndSnapshotCopies(t *testing.T) {
	f := newUniVPNLocalFixture(t)
	l, err := f.retain(context.Background())
	if err != nil || l == nil {
		t.Fatal("private correlation failed", err)
	}
	if l.broker != f.b || l.process != f.p || l.pair != f.p.packetPair || l.receipt != f.receipt || l.relay != f.relay || f.b.local != l {
		t.Fatal("binding did not retain original identities")
	}
	if f.correlations.Load() != 2 || f.observations.Load() != 2 || !f.p.packetPair.claimed {
		t.Fatal("receipt, relay or permanent generation claim missing")
	}
	if err := f.b.CheckLocalBinding(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	want, err := l.Snapshot()
	if err != nil || want.Binding != f.b.binding || !reflect.DeepEqual(want.Offer, f.b.offer) || want.Native.Session != f.p.sessionID || want.Native.PID != f.proc.pid || want.Native.Executable.SHA256 != f.proc.digest || want.TUN.Name != f.a.Interface() {
		t.Fatal("incorrect copied metadata", err)
	}
	changed, _ := l.Snapshot()
	changed.Binding.Identity.Interface = "wrong0"
	changed.Offer.Routes[0] = netip.MustParsePrefix("198.51.100.0/24")
	changed.Offer.DNS[0] = netip.MustParseAddr("198.51.100.53")
	changed.Offer.Domains[0] = "changed.invalid"
	changed.Native.PID++
	changed.TUN.Name = "wrong1"
	again, err := l.Snapshot()
	if err != nil || !reflect.DeepEqual(again, want) || !reflect.DeepEqual(f.b.offer, want.Offer) {
		t.Fatal("snapshot aliases retained state", err)
	}
	if again, err := f.retain(context.Background()); again != nil || err == nil {
		t.Fatal("successful attempt replayed")
	}
	assertUniVPNLocalPairOpen(t, f)
	for _, value := range []any{l, *l, want, &want} {
		if _, ok := value.(UniVPNNMHostAuthority); ok {
			t.Fatalf("%T gained host authority", value)
		}
		if _, ok := value.(UniVPNNMHostBinding); ok {
			t.Fatalf("%T gained host binding", value)
		}
		if _, ok := value.(UniVPNHostLease); ok {
			t.Fatalf("%T gained a host lease", value)
		}
		if _, ok := value.(nmvpn.Broker); ok {
			t.Fatalf("%T gained broker authority", value)
		}
		if _, ok := value.(nmvpn.PublicationVerifier); ok {
			t.Fatalf("%T gained publication authority", value)
		}
	}
}

func TestUniVPNNMLocalBindingRejectsZeroCopiedAndForeign(t *testing.T) {
	f, other := newUniVPNLocalFixture(t), newUniVPNLocalFixture(t)
	l, err := f.retain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := other.retain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	copyL := *l
	for _, invalid := range []*UniVPNNMLocalBinding{nil, {}, &copyL, foreign} {
		if err := f.b.CheckLocalBinding(context.Background(), invalid); err == nil {
			t.Fatal("nil, zero, copied or foreign token accepted")
		}
	}
	for _, invalid := range []*UniVPNNMLocalBinding{nil, {}, &copyL} {
		if got, err := invalid.Snapshot(); err == nil || !reflect.DeepEqual(got, UniVPNNMLocalSnapshot{}) {
			t.Fatal("invalid token produced metadata")
		}
	}
	copyB := reflect.New(reflect.TypeOf(f.b).Elem()).Interface().(*UniVPNNMBroker)
	reflect.ValueOf(copyB).Elem().Set(reflect.ValueOf(f.b).Elem())
	for _, invalid := range []*UniVPNNMBroker{nil, {}, copyB} {
		if got, err := invalid.retainLocalBinding(context.Background(), f.inputs(f.receipt, f.relay)); got != nil || err == nil {
			t.Fatal("nil, zero or copied broker acquired local binding")
		}
		if err := invalid.CheckLocalBinding(context.Background(), l); err == nil {
			t.Fatal("nil, zero or copied broker accepted local binding")
		}
	}
	if err := f.b.CheckLocalBinding(context.Background(), l); err != nil {
		t.Fatal("rejections changed original historical identity", err)
	}
}

type uniVPNLocalWrappedProvider struct{ UniVPNPacketProvider }
type uniVPNLocalWrappedSource struct{ UniVPNNativeOfferSource }

func TestUniVPNNMLocalBindingConcretePacketWitness(t *testing.T) {
	f := newUniVPNLocalFixture(t)
	witness := f.p.packetPair
	if witness == nil || witness.process != f.p || witness.child != f.child || witness.session != f.p.sessionID || witness.claimed {
		t.Fatal("concrete acquisition/duplication/wiring lost provenance")
	}
	if f.p.cmd.Process != nil || f.p.cmd.ExtraFiles[3] != f.native.file {
		t.Fatal("unexpected worker execution or packet slot")
	}
	// The real amd64 bootstrap appends root and image pins after these four
	// slots. Reproduce that command shape without platform-specific deployment
	// setup: the witness must be minted before wrapping, never reminted after it.
	firstFour := append([]*os.File(nil), f.p.cmd.ExtraFiles...)
	root, image := transportPipe(t)
	f.p.cmd.ExtraFiles = append(f.p.cmd.ExtraFiles, root, image)
	if len(f.p.cmd.ExtraFiles) != 6 || !reflect.DeepEqual(f.p.cmd.ExtraFiles[:4], firstFour) || f.p.packetPair != witness || witness.process.cmd != f.p.cmd {
		t.Fatal("bootstrap-shaped command lost original generation")
	}
	l, err := f.retain(context.Background())
	if err != nil || l.pair != witness || f.p.cmd.Process != nil {
		t.Fatal("post-wrapper correlation lost the pre-wrapper witness", err)
	}
	assertUniVPNLocalPairOpen(t, f)

	t.Run("wrapper gets no concrete witness", func(t *testing.T) {
		f := newUniVPNLocalFixture(t)
		f.p.packetPair, f.p.packet = nil, f.child
		wrapped := uniVPNLocalWrappedProvider{f.provider}
		if err := retainUniVPNPacketProvenance(f.p, wrapped, f.native); err != nil || f.p.packetPair != nil {
			t.Fatal("arbitrary provider gained concrete-pair proof", err)
		}
		f.p.packet = nil
		if l, err := f.retain(context.Background()); l != nil || err == nil {
			t.Fatal("unwitnessed pair acquired local binding")
		}
		assertUniVPNLocalPairOpen(t, f)
	})
}

func TestUniVPNNMLocalBindingRejectsMismatchesAndConsumesAttempt(t *testing.T) {
	for _, name := range []string{
		"nil receipt", "foreign receipt", "nil relay", "foreign relay", "receipt value", "receipt session", "second receipt", "receipt error",
		"relay error", "relay name", "relay check", "second relay error", "second relay drift", "wrong peer", "copied peer",
		"activation receipt", "activation binding", "host binding", "offer", "session", "pair session", "pair process", "claimed pair", "untransferred endpoint", "no witness", "wrapped source", "foreign process",
		"nil correlate", "nil observe", "nil check",
	} {
		t.Run(name, func(t *testing.T) {
			f := newUniVPNLocalFixture(t)
			in := f.inputs(f.receipt, f.relay)
			switch name {
			case "nil receipt":
				in.receipt = nil
			case "foreign receipt":
				in = f.inputs(&nmvpn.ActivationReceipt{}, f.relay)
			case "nil relay":
				in.relay = nil
			case "foreign relay":
				in = f.inputs(f.receipt, &packetrelay.TUNRelay{})
			case "receipt value", "receipt session", "second receipt", "receipt error":
				original := in.correlate
				in.correlate = func(ctx context.Context) (nmvpn.Binding, error) {
					value, err := original(ctx)
					switch name {
					case "receipt value":
						value.PluginOwner = ":1.99"
					case "receipt session":
						value.Identity.Session = f.p.sessionID
					case "second receipt":
						if f.correlations.Load() == 2 {
							value.Identity.ActivePath += "0"
						}
					case "receipt error":
						err = io.ErrUnexpectedEOF
					}
					return value, err
				}
			case "relay error", "relay name", "second relay error", "second relay drift":
				original := in.observeRelay
				in.observeRelay = func(ctx context.Context, child *packetrelay.DatagramPackets, expected string) (packetrelay.TUNRelayBinding, packetrelay.TUNObservation, error) {
					binding, observation, err := original(ctx, child, expected)
					if name == "relay error" || (name == "second relay error" && f.observations.Load() == 2) {
						err = io.ErrUnexpectedEOF
					}
					if name == "relay name" {
						observation.Name = "foreign0"
					}
					if name == "second relay drift" && f.observations.Load() == 2 {
						observation.Flags++
					}
					return binding, observation, err
				}
			case "relay check":
				in.checkRelay = func(packetrelay.TUNRelayBinding, *packetrelay.DatagramPackets) error { return io.ErrUnexpectedEOF }
			case "wrong peer":
				other := newUniVPNLocalFixture(t)
				f.p.packetPair.child = other.child
			case "copied peer":
				copyP := reflect.New(reflect.TypeOf(f.child).Elem()).Interface().(*packetrelay.DatagramPackets)
				reflect.ValueOf(copyP).Elem().Set(reflect.ValueOf(f.child).Elem())
				f.p.packetPair.child = copyP
			case "activation receipt":
				f.a.receiptErr = io.ErrUnexpectedEOF
			case "activation binding":
				f.a.binding.Identity.ActivePath += "0"
			case "host binding":
				f.h.attachedBinding.PluginOwner = ":1.99"
			case "offer":
				f.b.offer.Routes[0] = netip.MustParsePrefix("198.51.100.0/24")
			case "session":
				f.p.sessionID = strings.Repeat("b", 32)
			case "pair session":
				f.p.packetPair.session = strings.Repeat("b", 32)
			case "pair process":
				f.p.packetPair.process = &uniVPNExecProcess{}
			case "claimed pair":
				f.p.packetPair.claimed = true
			case "untransferred endpoint":
				f.p.packet = f.child
			case "no witness":
				f.p.packetPair = nil
			case "wrapped source":
				f.b.source = uniVPNLocalWrappedSource{}
			case "foreign process":
				f.b.process = &nmBridgeProcess{}
			case "nil correlate":
				in.correlate = nil
			case "nil observe":
				in.observeRelay = nil
			case "nil check":
				in.checkRelay = nil
			}
			if got, err := f.b.retainLocalBinding(context.Background(), in); got != nil || err == nil || f.b.local != nil {
				t.Fatal("invalid correlation minted a binding")
			}
			if !f.b.localTried.Load() {
				t.Fatal("failed attempt was not consumed")
			}
			before := [3]int32{f.correlations.Load(), f.observations.Load(), f.checks.Load()}
			if got, err := f.retain(context.Background()); got != nil || err == nil {
				t.Fatal("failed attempt replayed")
			}
			if after := [3]int32{f.correlations.Load(), f.observations.Load(), f.checks.Load()}; after != before {
				t.Fatal("replay repeated observations")
			}
			assertUniVPNLocalPairOpen(t, f)
		})
	}
}

func TestUniVPNNMLocalBindingCanceledInputConsumesBeforeGate(t *testing.T) {
	for _, nilContext := range []bool{false, true} {
		f := newUniVPNLocalFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if nilContext {
			ctx = nil
		}
		// An unavailable gate must not delay an invalid-context attempt or leave
		// a fresh generation available to a later caller.
		<-f.b.gate
		if got, err := f.retain(ctx); got != nil || err == nil || !f.b.localTried.Load() {
			t.Fatal("invalid context did not consume the attempt")
		}
		f.b.gate <- struct{}{}
		if got, err := f.retain(context.Background()); got != nil || err == nil || f.correlations.Load() != 0 {
			t.Fatal("canceled attempt was replayable")
		}
		assertUniVPNLocalPairOpen(t, f)
	}
}

func TestUniVPNNMLocalBindingPublicBoundaryRejectsFixtureObjects(t *testing.T) {
	for _, nilRelay := range []bool{false, true} {
		f := newUniVPNLocalFixture(t)
		relay := f.relay
		if nilRelay {
			relay = nil
		}
		if got, err := f.b.RetainLocalBinding(context.Background(), f.receipt, relay); got != nil || err == nil {
			t.Fatal("public path accepted synthetic activation/receipt/relay")
		}
		if got, err := f.retain(context.Background()); got != nil || err == nil {
			t.Fatal("public-path failure did not consume attempt")
		}
		assertUniVPNLocalPairOpen(t, f)
	}
}

func TestUniVPNNMLocalBindingConcurrentClaimSingleWinner(t *testing.T) {
	f := newUniVPNLocalFixture(t)
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := f.retain(context.Background())
			if err == nil && l != nil {
				successes.Add(1)
			} else if err == nil || l != nil {
				t.Error("losing caller received partial success")
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || f.correlations.Load() != 2 || f.observations.Load() != 2 || f.b.local == nil {
		t.Fatal("concurrent claim did not have exactly one winner")
	}
	assertUniVPNLocalPairOpen(t, f)
}

func TestUniVPNNMLocalBindingGenerationClaimSurvivesFailedBroker(t *testing.T) {
	f := newUniVPNLocalFixture(t)
	in := f.inputs(f.receipt, f.relay)
	in.correlate = func(context.Context) (nmvpn.Binding, error) { return nmvpn.Binding{}, io.ErrUnexpectedEOF }
	if l, err := f.b.retainLocalBinding(context.Background(), in); l != nil || err == nil || !f.p.packetPair.claimed {
		t.Fatal("failed correlation did not permanently consume generation")
	}
	// A distinct synthetic broker with the same immutable values and exact
	// process cannot evade the original pair's claim with a fresh broker flag.
	other := &UniVPNNMBroker{
		gate: make(chan struct{}, 1), activation: f.a, host: f.h, receipt: f.b.receipt,
		binding: f.b.binding, offer: cloneUniVPNNMOffer(f.b.offer), source: f.b.source,
		launcher: f.b.launcher, process: f.p, run: f.b.run, prepared: true, bound: true, waitDone: f.b.waitDone,
	}
	other.self = other
	other.gate <- struct{}{}
	if l, err := other.retainLocalBinding(context.Background(), f.inputs(f.receipt, f.relay)); l != nil || err == nil || f.correlations.Load() != 0 {
		t.Fatal("second broker reused the claimed process generation")
	}
	assertUniVPNLocalPairOpen(t, f)
}

func TestUniVPNNMLocalBindingRejectsIdentitySwapDuringObservation(t *testing.T) {
	for _, phase := range []string{"second receipt", "final relay"} {
		for _, name := range []string{"activation", "process", "pair", "child", "observation", "launcher", "receipt", "binding", "offer", "session", "untransferred endpoint", "launch cleanup"} {
			t.Run(phase+"/"+name, func(t *testing.T) {
				f := newUniVPNLocalFixture(t)
				in := f.inputs(f.receipt, f.relay)
				mutate := func() {
					switch name {
					case "activation":
						copyA := *f.a
						f.b.activation = &copyA
					case "process":
						f.b.process = &uniVPNExecProcess{cmd: f.p.cmd, exited: f.p.exited, observation: f.p.observation, sessionID: f.p.sessionID, offer: f.p.offer, packetPair: f.p.packetPair}
					case "pair":
						copyPair := *f.p.packetPair
						f.p.packetPair = &copyPair
					case "child":
						other := newUniVPNLocalFixture(t)
						f.p.packetPair.child = other.child
					case "observation":
						f.p.observation = newUniVPNProcFixture(t).obs
					case "launcher":
						copyLauncher := *f.b.launcher
						f.b.launcher = &copyLauncher
					case "receipt":
						f.b.receipt.PluginOwner = ":1.99"
					case "binding":
						f.b.binding.Identity.ActivePath += "0"
					case "offer":
						f.b.offer.Routes[0] = netip.MustParsePrefix("198.51.100.0/24")
					case "session":
						f.p.sessionID = strings.Repeat("b", 32)
					case "untransferred endpoint":
						f.p.packet = f.child
					case "launch cleanup":
						f.p.launchCleanupErr = &CleanupError{}
					}
				}
				original := in.correlate
				in.correlate = func(ctx context.Context) (nmvpn.Binding, error) {
					value, err := original(ctx)
					if phase == "second receipt" && f.correlations.Load() == 2 {
						mutate()
					}
					return value, err
				}
				observe := in.observeRelay
				in.observeRelay = func(ctx context.Context, child *packetrelay.DatagramPackets, name string) (packetrelay.TUNRelayBinding, packetrelay.TUNObservation, error) {
					binding, tun, err := observe(ctx, child, name)
					if phase == "final relay" && f.observations.Load() == 2 {
						mutate()
					}
					return binding, tun, err
				}
				if l, err := f.b.retainLocalBinding(context.Background(), in); l != nil || err == nil || f.b.local != nil {
					t.Fatal("substituted generation or unknown cleanup accepted")
				}
				assertUniVPNLocalPairOpen(t, f)
			})
		}
	}
}

func TestUniVPNNMLocalBindingInterruptionsDuringObservations(t *testing.T) {
	for _, phase := range []string{"first receipt", "native", "first relay", "second receipt", "second relay"} {
		for _, interruption := range []string{"caller cancel", "activation cancel", "run cancel", "exit", "stop"} {
			// The last relay read holds the broker gate. Close itself is tested
			// outside that gate; independent exit/cancellation must still win here.
			if phase == "second relay" && interruption == "stop" {
				continue
			}
			t.Run(phase+"/"+interruption, func(t *testing.T) {
				f := newUniVPNLocalFixture(t)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				var once sync.Once
				interrupt := func() {
					once.Do(func() {
						switch interruption {
						case "caller cancel":
							cancel()
						case "activation cancel":
							f.a.cancel()
						case "run cancel":
							f.b.cancel()
						case "exit":
							f.finishProcess()
						case "stop":
							f.finishProcess()
							if err := f.b.Close(ctx); err != nil {
								t.Error("synthetic local stop failed", err)
							}
						}
					})
				}
				in := f.inputs(f.receipt, f.relay)
				correlate := in.correlate
				in.correlate = func(ctx context.Context) (nmvpn.Binding, error) {
					value, err := correlate(ctx)
					if (phase == "first receipt" && f.correlations.Load() == 1) || (phase == "second receipt" && f.correlations.Load() == 2) {
						interrupt()
					}
					return value, err
				}
				observe := in.observeRelay
				in.observeRelay = func(ctx context.Context, child *packetrelay.DatagramPackets, name string) (packetrelay.TUNRelayBinding, packetrelay.TUNObservation, error) {
					binding, tun, err := observe(ctx, child, name)
					if (phase == "first relay" && f.observations.Load() == 1) || (phase == "second relay" && f.observations.Load() == 2) {
						interrupt()
					}
					return binding, tun, err
				}
				if phase == "native" {
					read := f.proc.obs.read
					f.proc.obs.read = func(ctx context.Context, dir *os.File, pid int) (UniVPNNMProcessObservation, error) {
						result, err := read(ctx, dir, pid)
						interrupt()
						return result, err
					}
				}
				if l, err := f.b.retainLocalBinding(ctx, in); l != nil || err == nil || f.b.local != nil {
					t.Fatal("interrupted observation returned a binding")
				}
				if l, err := f.retain(context.Background()); l != nil || err == nil {
					t.Fatal("interrupted attempt was replayable")
				}
			})
		}
	}
}

func TestUniVPNNMLocalBindingHistoricalAfterLifecycleEnd(t *testing.T) {
	for _, name := range []string{"activation canceled", "run canceled", "exited", "stopped", "partial cleanup"} {
		t.Run(name, func(t *testing.T) {
			f := newUniVPNLocalFixture(t)
			l, err := f.retain(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			before, err := l.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			end := func(f *uniVPNLocalFixture) {
				switch name {
				case "activation canceled":
					f.a.cancel()
				case "run canceled":
					f.b.cancel()
				case "exited":
					f.finishProcess()
				case "stopped", "partial cleanup":
					f.finishProcess()
					if name == "partial cleanup" {
						f.h.stopErr = io.ErrUnexpectedEOF
					}
					err := f.b.Close(context.Background())
					var cleanup *CleanupError
					if name == "stopped" && (err != nil || !f.b.stopped) {
						t.Fatal("synthetic stop failed", err)
					}
					if name == "partial cleanup" && (!errors.As(err, &cleanup) || f.b.stopped) {
						t.Fatal("partial cleanup did not remain uncertain", err)
					}
					if repeated := f.b.Close(context.Background()); repeated != err || f.h.stops != 1 {
						t.Fatal("teardown was replayed or sticky result changed")
					}
				}
			}
			end(f)
			correlations, observations := f.correlations.Load(), f.observations.Load()
			if err := f.b.CheckLocalBinding(context.Background(), l); err != nil {
				t.Fatal("lifecycle end discarded historical association", err)
			}
			after, err := l.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) || f.correlations.Load() != correlations || f.observations.Load() != observations {
				t.Fatal("historical check performed live observations or changed metadata", err)
			}
			if err := f.b.VerifyPublish(context.Background(), f.b.binding, f.b.offer); err == nil {
				t.Fatal("historical local binding authorized publication")
			}
			if l, err := f.retain(context.Background()); l != nil || err == nil {
				t.Fatal("historical binding could be refreshed")
			}
			fresh := newUniVPNLocalFixture(t)
			end(fresh)
			if l, err := fresh.retain(context.Background()); l != nil || err == nil || fresh.correlations.Load() != 0 || fresh.observations.Load() != 0 {
				t.Fatal("ended generation acquired its first local binding")
			}
		})
	}
}

// Exercise the same preparation helper that Launch uses, without starting a
// command or touching isolation. The wrapper checks provenance before adding
// bootstrap handles, so reversing the orchestration order fails this test.
type uniVPNLocalWrapper struct {
	wrapFn func(*exec.Cmd, string) error
}

func (w *uniVPNLocalWrapper) wrap(cmd *exec.Cmd, digest string) error {
	return w.wrapFn(cmd, digest)
}
func (*uniVPNLocalWrapper) Prepare(*exec.Cmd) error { panic("unexpected process preparation") }
func (*uniVPNLocalWrapper) WaitEmpty(context.Context, *exec.Cmd) error {
	panic("unexpected containment wait")
}

func TestUniVPNPacketProvenanceBeforeBootstrapWrapper(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "wrapper failure"}[fail], func(t *testing.T) {
			f := newUniVPNLocalFixture(t)
			f.p.packetPair, f.p.packet = nil, f.child
			root, image := transportPipe(t)
			calls := 0
			f.p.isolation = &uniVPNLocalWrapper{wrapFn: func(cmd *exec.Cmd, digest string) error {
				calls++
				witness := f.p.packetPair
				if witness == nil || witness.process != f.p || witness.child != f.child || witness.session != f.p.sessionID || witness.claimed || cmd != f.p.cmd || cmd.Process != nil || digest != f.proc.digest || len(cmd.ExtraFiles) != 4 || cmd.ExtraFiles[3] != f.native.file {
					t.Fatal("wrapper ran before the original packet provenance was retained")
				}
				if fail {
					return io.ErrUnexpectedEOF
				}
				cmd.ExtraFiles = append(cmd.ExtraFiles, root, image)
				return nil
			}}
			err := prepareUniVPNPacketProcess(f.p, f.provider, f.native, f.proc.digest)
			if calls != 1 || (fail && !errors.Is(err, io.ErrUnexpectedEOF)) || (!fail && err != nil) || f.p.cmd.Process != nil {
				t.Fatal("preparation did not preserve wrapper result or attempted a command", err)
			}
			if (!fail && len(f.p.cmd.ExtraFiles) != 6) || (fail && len(f.p.cmd.ExtraFiles) != 4) {
				t.Fatal("unexpected bootstrap descriptor shape")
			}
			assertUniVPNLocalPairOpen(t, f)
		})
	}
}
