//go:build linux

package core

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mygo-vpn/internal/fdtransport"
	"mygo-vpn/internal/nmvpn"
	"mygo-vpn/internal/packetrelay"
)

// UniVPNNMHostAuthority is trusted broker provisioning, never desktop input.
// Authorize must correlate the exact authenticated Connect receipt with the
// broker's own activation transaction AND Activation.Nonce() BEFORE credentials
// or workers are used. The nonce must originate from the trusted manager's
// one-time activation receipt, not merely be echoed from untrusted fields.
// A UUID scan, a profile supplied by the desktop, or a device-name lookup is not
// that authority. It must not create networking or start a worker/relay here.
// Any returned binding transfers ownership, including when an error is returned.
// No production implementation is supplied; absence keeps this path disabled.
type UniVPNNMHostAuthority interface {
	Authorize(context.Context, *nmvpn.Activation) (UniVPNNMHostBinding, error)
}

// UniVPNNMHostBinding retains the actual broker-owned resource handles and
// activation receipt, not replaceable names or process IDs. Its dynamic type
// must be comparable. Binding returns an immutable receipt with an EMPTY native
// Session; every other field must already be independently authenticated.
//
// Attach takes exclusive ownership of the packet endpoint even on failure. It
// must bind only this fresh native generation to its real host TUN and relay,
// enforce separately approved packet policy, and retain partial-acquisition
// recovery handles. The host TUN must never pass to the native worker. Attach is
// called once, only after validating and binding the authenticated native offer.
//
// Verify attests immutable receipt/handle provenance in every phase, including
// AFTER StopLocal. CheckLive independently verifies the live link/relay and the
// complete applied/global/dispatcher policy; it is not an activation proof.
// StopLocal stops/joins only retained local handles, not NM configuration, and
// must also handle failure before Attach. ProveAbsent independently reads back
// the generation's link/routes/DNS/relay absence. Neither an NM object's loss
// nor a successful Close proves absence. All calls must honor their context.
// This interface does not provide an exclusive UniVPNHostLease.
type UniVPNNMHostBinding interface {
	Binding() nmvpn.Binding
	Attach(context.Context, nmvpn.Binding, nmvpn.Offer, packetrelay.PacketIO) error
	Verify(context.Context, nmvpn.Binding, nmvpn.Offer) error
	CheckLive(context.Context) error
	StopLocal(context.Context) error
	ProveAbsent(context.Context) error
}

type uniVPNNMActivation interface {
	Context() context.Context
	UUID() string
	Interface() string
	Nonce() string
	CheckReceipt(context.Context, nmvpn.Binding) error
	UsePassword(context.Context, func([]byte) error) error
	Bind(context.Context, nmvpn.Binding, nmvpn.Offer) error
	VerifyBinding(nmvpn.Binding, nmvpn.Offer) error
	CheckLive(context.Context) error
}

type uniVPNNMDependencies struct {
	authorize func(context.Context) (UniVPNNMHostBinding, error)
	launch    func(context.Context, []byte) (UniVPNNativeProcess, error)
	source    UniVPNOfferSource
	launcher  *UniVPNExecLauncher
}

// UniVPNNMBroker supplies the native half of nmvpn.Broker, conditional on a real
// independently trusted host authority. It does not publish configuration, expose
// core.Ready, acquire a host-network lease, or wire the normal application.
//
// It owns the original worker's sole Wait, its native channel and the retained
// host binding for the entire generation. Never also give that worker to
// UniVPNBrokerBackend. A stopped or failed instance can never be started again.
type UniVPNNMBroker struct {
	self       *UniVPNNMBroker
	gate       chan struct{}
	activation uniVPNNMActivation
	host       UniVPNNMHostBinding
	receipt    nmvpn.Binding
	binding    nmvpn.Binding
	offer      nmvpn.Offer
	source     UniVPNOfferSource
	launcher   *UniVPNExecLauncher                                // retain isolation/transport authority after failed launch
	authorize  func(context.Context) (UniVPNNMHostBinding, error) // retain provider; never replay
	process    UniVPNNativeProcess
	packet     packetrelay.PacketIO
	packetDone bool
	waitDone   chan struct{}
	waitErr    error // published by closing waitDone
	run        context.Context
	cancel     context.CancelFunc
	unhook     func() bool
	bound      bool
	prepared   bool
	stopTried  bool
	stopped    bool
	stopErr    error
	uncertain  bool        // launch/source reported resources whose cleanup was not proven
	localTried atomic.Bool // one retained local correlation attempt, never reset
	local      *UniVPNNMLocalBinding
}

var _ nmvpn.Broker = (*UniVPNNMBroker)(nil)
var _ nmvpn.PublicationVerifier = (*UniVPNNMBroker)(nil)

var errUniVPNNM = errors.New("NM native binding unavailable or invalid")

// StartUniVPNNMBroker freezes administrator launch arguments, executable pins,
// transport policy and offer policy before authorizing or launching anything.
// Credentials are consumed only through the authenticated Activation. The public
// path always uses the concrete pinned launcher and concrete native offer source.
// The caller must not mutate launcher/configuration while this call snapshots it.
//
// IMPORTANT: once host authority has been returned, a non-nil broker is returned
// EVEN ON ERROR. Keep it for Close/recovery; an error is not proof that all native
// or host resources are gone. Failed cleanup is sticky and retains its evidence.
// This constructor cannot make an arbitrary broken host provider cancellable.
// Startup is limited to 45 seconds, or the caller's shorter lifetime/deadline.
func StartUniVPNNMBroker(ctx context.Context, activation *nmvpn.Activation, launcher *UniVPNExecLauncher, executable string, args []string, policy nmvpn.Policy, hosts UniVPNNMHostAuthority) (*UniVPNNMBroker, error) {
	if ctx == nil || activation == nil || launcher == nil || nilInterface(hosts) {
		return nil, errUniVPNNM
	}
	l, args, err := snapshotUniVPNNMLaunch(launcher, executable, args, activation.Username())
	if err != nil {
		return nil, errUniVPNNM
	}
	return startUniVPNNM(ctx, activation, policy, uniVPNNMDependencies{
		authorize: func(ctx context.Context) (UniVPNNMHostBinding, error) { return hosts.Authorize(ctx, activation) },
		launch: func(ctx context.Context, password []byte) (UniVPNNativeProcess, error) {
			p, err := l.Launch(ctx, executable, append([]string(nil), args...), password)
			// Launch is concrete; do not introduce an arbitrary process-provider
			// seam at this production boundary.
			if p != nil {
				if actual, ok := p.(*uniVPNExecProcess); !ok || actual == nil {
					return p, errors.Join(errUniVPNNM, &CleanupError{})
				}
			}
			return p, err
		},
		source:   UniVPNNativeOfferSource{},
		launcher: l,
	})
}

// Shared admission/snapshot for the bridge and service composition. Argument
// validation may read trusted CA metadata, but never changes state. The service
// checks executable bytes and deployment providers separately BEFORE NM mutation.
func snapshotUniVPNNMLaunch(launcher *UniVPNExecLauncher, executable string, args []string, plannedUsername string) (*UniVPNExecLauncher, []string, error) {
	if launcher == nil {
		return nil, nil, errUniVPNNM
	}
	l := *launcher
	l.AllowedCAFiles = cloneUniVPNNMBools(launcher.AllowedCAFiles)
	l.TransportGateways = make(map[string]fdtransport.Endpoint, len(launcher.TransportGateways))
	for gateway, endpoint := range launcher.TransportGateways {
		l.TransportGateways[gateway] = endpoint
	}
	args = append([]string(nil), args...)
	if executable != l.Executable || !l.NativeSessionChannel || nilInterface(l.Isolation) || nilInterface(l.Transport) || nilInterface(l.PacketProvider) || validateUniVPNBrokerArgs(args, l.AllowedCAFiles) != nil {
		return nil, nil, errUniVPNNM
	}
	if _, err := l.transportEndpoint(args[len(args)-1]); err != nil {
		return nil, nil, errUniVPNNM
	}
	username := ""
	for _, arg := range args[:len(args)-2] {
		if strings.HasPrefix(arg, "--user=") {
			username = strings.TrimPrefix(arg, "--user=")
		}
	}
	if username == "" || username != plannedUsername {
		return nil, nil, errUniVPNNM
	}
	return &l, args, nil
}

func cloneUniVPNNMBools(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneUniVPNNMOffer(o nmvpn.Offer) nmvpn.Offer {
	o.Routes = append([]netip.Prefix(nil), o.Routes...)
	o.DNS = append([]netip.Addr(nil), o.DNS...)
	o.Domains = append([]string(nil), o.Domains...)
	return o
}

var uniVPNNMUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var uniVPNNMNonce = regexp.MustCompile(`^[0-9a-f]{32}$`)
var uniVPNNMOwner = regexp.MustCompile(`^:[0-9]+\.[0-9]+$`)
var uniVPNNMActive = regexp.MustCompile(`^/org/freedesktop/NetworkManager/ActiveConnection/[0-9]+$`)
var uniVPNNMSettings = regexp.MustCompile(`^/org/freedesktop/NetworkManager/Settings/[0-9]+$`)

func validUniVPNNMReceipt(r nmvpn.Binding, a uniVPNNMActivation) bool {
	i := r.Identity
	return i.Session == "" && i.UUID == a.UUID() && i.Interface == a.Interface() && uniVPNNMNonce.MatchString(a.Nonce()) && safeUniVPNLink(i.Interface) && uniVPNNMUUID.MatchString(i.BootID) && uniVPNNMUUID.MatchString(i.UUID) && uniVPNNMNonce.MatchString(i.BusID) && len(i.Owner) <= 64 && uniVPNNMOwner.MatchString(i.Owner) && len(r.PluginOwner) <= 64 && uniVPNNMOwner.MatchString(r.PluginOwner) && len(i.ActivePath) <= 128 && uniVPNNMActive.MatchString(i.ActivePath) && len(r.ConnectionPath) <= 128 && uniVPNNMSettings.MatchString(string(r.ConnectionPath))
}

// Joining a winning timeout callback prevents it from canceling a constructor
// that has already returned success. The callback never takes the lifecycle gate.
func uniVPNNMStartupDeadline(delay time.Duration, cancel context.CancelFunc) func() {
	done := make(chan struct{})
	timer := time.AfterFunc(delay, func() {
		cancel()
		close(done)
	})
	var once sync.Once
	return func() {
		once.Do(func() {
			if !timer.Stop() {
				<-done
			}
		})
	}
}

// Only package-private tests can replace launch/source/activation. Production
// enters through StartUniVPNNMBroker and cannot bypass their concrete provenance.
func startUniVPNNM(ctx context.Context, a uniVPNNMActivation, policy nmvpn.Policy, deps uniVPNNMDependencies) (result *UniVPNNMBroker, resultErr error) {
	if ctx == nil || nilInterface(a) || deps.authorize == nil || deps.launch == nil || nilInterface(deps.source) || a.Context() == nil {
		return nil, errUniVPNNM
	}
	if ctx.Err() != nil || a.CheckLive(ctx) != nil {
		return nil, errUniVPNNM
	}
	policy.Addresses = append([]netip.Prefix(nil), policy.Addresses...)
	policy.Endpoints = append([]netip.Addr(nil), policy.Endpoints...)
	policy.Routes = append([]netip.Prefix(nil), policy.Routes...)
	run, cancel := context.WithCancel(ctx)
	b := &UniVPNNMBroker{gate: make(chan struct{}, 1), activation: a, source: deps.source, launcher: deps.launcher, authorize: deps.authorize, run: run, cancel: cancel}
	b.self = b
	b.unhook = context.AfterFunc(a.Context(), cancel)
	finishStartup := uniVPNNMStartupDeadline(45*time.Second, cancel)
	// Hold the gate throughout acquisition; a cancellation watcher cannot race
	// half-constructed ownership. Every acquired handle is recorded before use.
	defer func() {
		finishStartup()
		if run.Err() != nil && resultErr == nil {
			resultErr = errUniVPNNM
		}
		if resultErr != nil {
			b.prepared = false
			cleanup, finish := context.WithTimeout(context.Background(), 10*time.Second)
			if b.closeLocked(cleanup) != nil {
				resultErr = errors.Join(errUniVPNNM, &CleanupError{})
			}
			finish()
		}
		b.gate <- struct{}{}
	}()
	host, err := deps.authorize(run)
	var cleanupError *CleanupError
	if errors.As(err, &cleanupError) {
		b.uncertain = true
	}
	if nilInterface(host) {
		b.unhook()
		cancel()
		if b.uncertain {
			return b, errors.Join(errUniVPNNM, &CleanupError{})
		}
		return nil, errUniVPNNM
	}
	b.host = host
	b.receipt = host.Binding()
	b.binding = b.receipt
	result = b // retain authority on every subsequent failure
	if err != nil || !reflect.TypeOf(host).Comparable() || !validUniVPNNMReceipt(b.receipt, a) || run.Err() != nil || a.CheckReceipt(run, b.receipt) != nil || a.CheckLive(run) != nil {
		return b, errUniVPNNM
	}
	err = a.UsePassword(run, func(password []byte) error {
		if len(password) == 0 || len(password) > 4095 || bytes.IndexAny(password, "\r\n\x00") >= 0 || run.Err() != nil || a.CheckLive(run) != nil {
			return errUniVPNNM
		}
		p, launchErr := deps.launch(run, password)
		var cleanup *CleanupError
		if errors.As(launchErr, &cleanup) {
			b.uncertain = true
		}
		if !nilInterface(p) {
			b.process = p
			b.waitDone = make(chan struct{})
			go func() {
				b.waitErr = p.Wait()
				close(b.waitDone)
				cancel()
			}()
			go func() {
				<-run.Done()
				cleanup, finish := context.WithTimeout(context.Background(), 10*time.Second)
				defer finish()
				_ = b.Close(cleanup)
			}()
		}
		if launchErr != nil || nilInterface(p) {
			return errUniVPNNM
		}
		return nil
	})
	if err != nil {
		return b, errUniVPNNM
	}
	offer, packet, err := b.source.WaitOffer(run, b.process)
	b.packet = packet
	if errors.As(err, &cleanupError) {
		b.uncertain = true
	}
	if err != nil || nilInterface(packet) || len(offer.Addresses) != 1 || len(offer.DNS) != 0 {
		return b, errUniVPNNM
	}
	b.binding.Identity.Session = offer.Session
	b.offer = nmvpn.Offer{Session: offer.Session, Interface: b.receipt.Identity.Interface, Address: offer.Addresses[0], Endpoint: offer.Endpoint, Routes: append([]netip.Prefix(nil), offer.Routes...)}
	if _, err = nmvpn.Encode(b.offer, policy); err != nil {
		return b, errUniVPNNM
	}
	if a.Bind(run, b.binding, cloneUniVPNNMOffer(b.offer)) != nil {
		return b, errUniVPNNM
	}
	b.bound = true
	if a.CheckLive(run) != nil || b.source.CheckLive(run, b.process) != nil || b.host.Binding() != b.receipt {
		return b, errUniVPNNM
	}
	// Attach owns even a partial failure. Never close its transferred endpoint
	// here, or substitute a new handle if cleanup becomes uncertain.
	b.packet = nil
	if b.host.Attach(run, b.binding, cloneUniVPNNMOffer(b.offer), packet) != nil {
		return b, errUniVPNNM
	}
	b.prepared = true
	if b.verifyPublishLocked(run, b.binding, b.offer) != nil {
		return b, errUniVPNNM
	}
	return b, nil
}

// Binding and Offer are immutable values after Start returns. Offer owns copies
// of every slice. Publication still requires nmvpn's controller and pinned bus.
func (b *UniVPNNMBroker) Binding() nmvpn.Binding { return b.binding }
func (b *UniVPNNMBroker) Offer() nmvpn.Offer     { return cloneUniVPNNMOffer(b.offer) }

func (b *UniVPNNMBroker) lock(ctx context.Context) error {
	if b == nil || ctx == nil || b.gate == nil || ctx.Err() != nil {
		return errUniVPNNM
	}
	select {
	case <-ctx.Done():
		return errUniVPNNM
	case <-b.gate:
		if ctx.Err() != nil {
			b.gate <- struct{}{}
			return errUniVPNNM
		}
		return nil
	}
}

func (b *UniVPNNMBroker) verifyLocked(ctx context.Context, binding nmvpn.Binding, offer nmvpn.Offer) error {
	if !b.bound || binding != b.binding || !reflect.DeepEqual(offer, b.offer) || nilInterface(b.host) || b.host.Binding() != b.receipt || b.activation.VerifyBinding(binding, cloneUniVPNNMOffer(offer)) != nil || b.host.Verify(ctx, binding, cloneUniVPNNMOffer(offer)) != nil || ctx.Err() != nil {
		return errUniVPNNM
	}
	return nil
}

func (b *UniVPNNMBroker) verifyPublishLocked(ctx context.Context, binding nmvpn.Binding, offer nmvpn.Offer) error {
	if !b.prepared || b.stopTried || b.verifyLocked(ctx, binding, offer) != nil || b.run.Err() != nil || b.activation.CheckLive(ctx) != nil || b.source.CheckLive(ctx, b.process) != nil || b.host.CheckLive(ctx) != nil || ctx.Err() != nil {
		return errUniVPNNM
	}
	return nil
}

// Verify checks immutable provenance only. Death, cancellation and failed local
// cleanup must not remove authority to stop independently retained handles.
func (b *UniVPNNMBroker) Verify(ctx context.Context, binding nmvpn.Binding, offer nmvpn.Offer) error {
	if b.lock(ctx) != nil {
		return errUniVPNNM
	}
	defer func() { b.gate <- struct{}{} }()
	return b.verifyLocked(ctx, binding, offer)
}

// VerifyPublish is the publication-only liveness gate used immediately before
// each NM signal. Successful immutable Verify alone cannot authorize publishing
// after Disconnect, a worker exit, local teardown, or incomplete construction.
func (b *UniVPNNMBroker) VerifyPublish(ctx context.Context, binding nmvpn.Binding, offer nmvpn.Offer) error {
	if b.lock(ctx) != nil {
		return errUniVPNNM
	}
	defer func() { b.gate <- struct{}{} }()
	return b.verifyPublishLocked(ctx, binding, offer)
}

// Stop does not require NM/bus liveness. It checks retained provenance, then
// joins only this instance's handles. Close also supports pre-Bind failures.
// No Broker callback emits plugin state: DBusPeer holds the bus operation lock.
// The caller may invoke Activation.MarkStopped after Controller.Stop returns.
func (b *UniVPNNMBroker) Stop(ctx context.Context, binding nmvpn.Binding) error {
	if b.lock(ctx) != nil {
		return &CleanupError{}
	}
	defer func() { b.gate <- struct{}{} }()
	if !b.bound || binding != b.binding || b.activation.VerifyBinding(binding, cloneUniVPNNMOffer(b.offer)) != nil {
		return &CleanupError{}
	}
	return b.closeLocked(ctx)
}

// Close is local teardown, never proof of NM/network cleanup. On uncertainty it
// retains all identity/handle evidence and never retries destructive operations.
func (b *UniVPNNMBroker) Close(ctx context.Context) error {
	if b.lock(ctx) != nil {
		return &CleanupError{}
	}
	defer func() { b.gate <- struct{}{} }()
	return b.closeLocked(ctx)
}

func (b *UniVPNNMBroker) closeLocked(ctx context.Context) error {
	if b.stopTried {
		return b.stopErr
	}
	b.stopTried = true
	b.cancel()
	b.unhook()
	bad := b.uncertain
	if !nilInterface(b.packet) && !b.packetDone {
		b.packetDone = true // Close may have executed even when it returns an error.
		if b.packet.Close() != nil {
			bad = true
		}
	}
	if !nilInterface(b.process) && b.process.Stop() != nil {
		bad = true
	}
	if !nilInterface(b.host) {
		if b.host.Binding() != b.receipt || b.host.StopLocal(ctx) != nil {
			bad = true
		}
	}
	if b.waitDone != nil {
		select {
		case <-ctx.Done():
			bad = true
		case <-b.waitDone:
			var cleanup *CleanupError
			if errors.As(b.waitErr, &cleanup) || b.source.ProveClosed(ctx, b.process) != nil {
				bad = true
			}
		}
	}
	if bad || ctx.Err() != nil {
		b.stopErr = &CleanupError{}
		return b.stopErr
	}
	b.stopped = true
	return nil
}

func (b *UniVPNNMBroker) ProveAbsent(ctx context.Context, binding nmvpn.Binding) error {
	if b.lock(ctx) != nil {
		return &CleanupError{}
	}
	defer func() { b.gate <- struct{}{} }()
	if !b.stopped || b.verifyLocked(ctx, binding, b.offer) != nil || b.source.ProveClosed(ctx, b.process) != nil || b.host.ProveAbsent(ctx) != nil || ctx.Err() != nil {
		return &CleanupError{}
	}
	return nil
}


// Done observes this generation's lifetime without taking a second process Wait
// or revealing a replaceable PID. It closes on cancellation/exit/local teardown,
// not proof of cleanup. A successfully started broker always returns a channel.
func (b *UniVPNNMBroker) Done() <-chan struct{} {
	if b == nil || b.self != b || b.run == nil {
		return nil
	}
	return b.run.Done()
}
