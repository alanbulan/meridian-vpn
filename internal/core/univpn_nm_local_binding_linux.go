//go:build linux

package core

import (
	"context"
	"reflect"
	"syscall"

	"mygo-vpn/internal/nmvpn"
	"mygo-vpn/internal/packetrelay"
)

// UniVPNNMLocalSnapshot is copied historical metadata, never cleanup authority,
// a live snapshot, a host-namespace assertion, or permission to publish Ready.
type UniVPNNMLocalSnapshot struct {
	Binding nmvpn.Binding
	Offer   nmvpn.Offer
	Native  UniVPNNMProcessObservation
	TUN     packetrelay.TUNObservation
}

// UniVPNNMLocalBinding retains the original manager receipt, worker, concrete
// packet-pair witness and exact local relay identity. It owns no second copy of
// a resource. Existing broker/host and relay owners remain responsible for all
// cleanup, including failed acquisition. Do not copy this object.
//
// It deliberately cannot implement HostAuthority, HostBinding, Broker or a host
// lease. Successful correlation is not applied policy, liveness or absence.
type UniVPNNMLocalBinding struct {
	self         *UniVPNNMLocalBinding
	broker       *UniVPNNMBroker
	process      *uniVPNExecProcess
	pair         *uniVPNPacketProvenance
	child        *packetrelay.DatagramPackets
	observation  *uniVPNProcessObservation
	activation   uniVPNNMActivation
	receipt      *nmvpn.ActivationReceipt
	relay        *packetrelay.TUNRelay
	relayBinding packetrelay.TUNRelayBinding
	checkRelay   func(packetrelay.TUNRelayBinding, *packetrelay.DatagramPackets) error
	snapshot     UniVPNNMLocalSnapshot
}

func (l *UniVPNNMLocalBinding) Snapshot() (UniVPNNMLocalSnapshot, error) {
	if l == nil || l.self != l || l.broker == nil || l.process == nil || l.pair == nil || l.receipt == nil || l.relay == nil {
		return UniVPNNMLocalSnapshot{}, errUniVPNNM
	}
	s := l.snapshot
	s.Offer = cloneUniVPNNMOffer(s.Offer)
	return s, nil
}

// RetainLocalBinding makes one non-owning correlation attempt on an already
// prepared broker. The independent HostBinding required to prepare that broker
// is NOT replaced by this method, so the normal application remains disabled.
// No TUN is acquired, relay started, command launched or NM method called.
//
// Failure consumes the attempt but leaves every resource with its existing
// owner, including a foreign supplied relay. Cancellation cannot be retried to
// select a different generation. Observations are sequential, not atomic; name
// agreement with NM is only consistency, not proof NM owns this exact TUN.
func (b *UniVPNNMBroker) RetainLocalBinding(ctx context.Context, receipt *nmvpn.ActivationReceipt, relay *packetrelay.TUNRelay) (*UniVPNNMLocalBinding, error) {
	var activation *nmvpn.Activation
	if b != nil {
		activation, _ = b.activation.(*nmvpn.Activation)
	}
	return b.retainLocalBinding(ctx, uniVPNNMLocalInputs{
		receipt: receipt, relay: relay,
		correlate: func(ctx context.Context) (nmvpn.Binding, error) {
			if activation == nil || receipt == nil {
				return nmvpn.Binding{}, errUniVPNNM
			}
			return receipt.RetainedCorrelation(ctx, activation)
		},
		observeRelay: relay.ObservePacketBinding,
		checkRelay:   relay.CheckPacketBinding,
	})
}

// Only package tests substitute cross-package observations. Production always
// supplies the concrete original receipt and retained relay methods above.
type uniVPNNMLocalInputs struct {
	receipt      *nmvpn.ActivationReceipt
	relay        *packetrelay.TUNRelay
	correlate    func(context.Context) (nmvpn.Binding, error)
	observeRelay func(context.Context, *packetrelay.DatagramPackets, string) (packetrelay.TUNRelayBinding, packetrelay.TUNObservation, error)
	checkRelay   func(packetrelay.TUNRelayBinding, *packetrelay.DatagramPackets) error
}

func (b *UniVPNNMBroker) retainLocalBinding(ctx context.Context, in uniVPNNMLocalInputs) (*UniVPNNMLocalBinding, error) {
	if b == nil || b.self != b || !b.localTried.CompareAndSwap(false, true) || b.lock(ctx) != nil {
		return nil, errUniVPNNM
	}
	p, ok := b.process.(*uniVPNExecProcess)
	_, concreteSource := b.source.(UniVPNNativeOfferSource)
	if !ok || !concreteSource || !b.processObservableLocked(p) || p.launchCleanupErr != nil || nilInterface(b.activation) || !reflect.TypeOf(b.activation).Comparable() || in.receipt == nil || in.relay == nil || in.correlate == nil || in.observeRelay == nil || in.checkRelay == nil || b.verifyLocked(ctx, b.binding, b.offer) != nil || b.activation.CheckLive(ctx) != nil || b.source.CheckLive(ctx, p) != nil {
		b.gate <- struct{}{}
		return nil, errUniVPNNM
	}
	p.packetMu.Lock()
	pair := p.packetPair
	if pair == nil || pair.process != p || pair.child == nil || pair.session != p.sessionID || pair.claimed || !nilInterface(p.packet) {
		p.packetMu.Unlock()
		b.gate <- struct{}{}
		return nil, errUniVPNNM
	}
	pair.claimed = true
	child, session := pair.child, pair.session
	p.packetMu.Unlock()
	activation, expected, binding, offer := b.activation, b.receipt, b.binding, cloneUniVPNNMOffer(b.offer)
	launcher, source := b.launcher, b.source
	digest := launcher.ExecutableSHA256
	observation := p.observation
	b.gate <- struct{}{}

	actual, err := in.correlate(ctx)
	if err != nil || actual != expected || actual.Identity.Session != "" || activation.CheckReceipt(ctx, actual) != nil {
		return nil, errUniVPNNM
	}
	native, err := observation.observe(ctx, digest)
	if err != nil || native.Executable.UID != 0 || native.Executable.Mode&(0022|syscall.S_ISUID|syscall.S_ISGID|syscall.S_ISVTX) != 0 {
		return nil, errUniVPNNM
	}
	native.Session = session
	relayBinding, tun, err := in.observeRelay(ctx, child, expected.Identity.Interface)
	if err != nil || tun.Name != expected.Identity.Interface || in.checkRelay(relayBinding, child) != nil {
		return nil, errUniVPNNM
	}
	// Recheck the same receipt after descriptor/process observations. This is
	// local provenance only, not an NM readback or an atomic resource snapshot.
	actual, err = in.correlate(ctx)
	if err != nil || actual != expected || ctx.Err() != nil || b.lock(ctx) != nil {
		return nil, errUniVPNNM
	}
	defer func() { b.gate <- struct{}{} }()
	if b.process != p || p.observation != observation || b.activation != activation || b.source != source || b.receipt != expected || b.binding != binding || !reflect.DeepEqual(b.offer, offer) || b.launcher != launcher || !b.processObservableLocked(p) || p.launchCleanupErr != nil || launcher.ExecutableSHA256 != digest || b.verifyLocked(ctx, binding, offer) != nil || activation.CheckLive(ctx) != nil || b.source.CheckLive(ctx, p) != nil || ctx.Err() != nil {
		return nil, errUniVPNNM
	}
	// A completed direct relay Stop or changed retained TUN between the first
	// observation and this gate must not be silently accepted. These sequential
	// checks still cannot exclude a change immediately after the final read.
	finalRelay, finalTUN, err := in.observeRelay(ctx, child, expected.Identity.Interface)
	if err != nil || finalRelay != relayBinding || finalTUN != tun || in.checkRelay(finalRelay, child) != nil || b.process != p || p.observation != observation || b.activation != activation || b.source != source || b.receipt != expected || b.binding != binding || !reflect.DeepEqual(b.offer, offer) || b.launcher != launcher || launcher.ExecutableSHA256 != digest || p.launchCleanupErr != nil || !b.processObservableLocked(p) || activation.CheckLive(ctx) != nil || b.source.CheckLive(ctx, p) != nil || ctx.Err() != nil {
		return nil, errUniVPNNM
	}
	p.packetMu.Lock()
	unchanged := p.packetPair == pair && pair.process == p && pair.child == child && pair.session == session && session == p.sessionID && pair.claimed && nilInterface(p.packet)
	p.packetMu.Unlock()
	if !unchanged {
		return nil, errUniVPNNM
	}
	l := &UniVPNNMLocalBinding{broker: b, process: p, pair: pair, child: child, observation: observation, activation: activation, receipt: in.receipt, relay: in.relay, relayBinding: relayBinding, checkRelay: in.checkRelay, snapshot: UniVPNNMLocalSnapshot{Binding: binding, Offer: offer, Native: native, TUN: tun}}
	l.self = l
	b.local = l
	return l, nil
}

// CheckLocalBinding verifies only the historical association. It remains valid
// after cancellation, exit, stopped relays and sticky cleanup failures. It does
// no live readback and cannot authorize publication or prove anything absent.
func (b *UniVPNNMBroker) CheckLocalBinding(ctx context.Context, l *UniVPNNMLocalBinding) error {
	if b == nil || b.self != b || b.lock(ctx) != nil {
		return errUniVPNNM
	}
	defer func() { b.gate <- struct{}{} }()
	if l == nil || l.self != l || l != b.local || l.broker != b || l.process != b.process || l.activation != b.activation || l.observation != l.process.observation || l.pair == nil || l.pair.process != l.process || l.pair != l.process.packetPair || l.pair.child != l.child || l.pair.session != l.snapshot.Native.Session || l.snapshot.Binding != b.binding || !reflect.DeepEqual(l.snapshot.Offer, b.offer) || l.checkRelay == nil || l.checkRelay(l.relayBinding, l.child) != nil {
		return errUniVPNNM
	}
	return nil
}
