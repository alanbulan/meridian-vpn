//go:build linux

package packetrelay

import (
	"context"
	"errors"
	"sync"
)

var errTUNRelay = errors.New("TUN relay unavailable or already consumed")

// TUNRelayBinding is an opaque, process-local identity of one retained owner.
// A copied binding is still the same identity. The zero value is invalid. It is
// not serializable recovery authority, an NM receipt, a native session identity,
// a host lease, a liveness assertion, or evidence that networking is absent.
type TUNRelayBinding struct { owner *TUNRelay }

type tunRelayClaim struct {
	mu sync.Mutex
	owner *TUNRelay
}

// TUNRelay owns one retained TUN and one concrete native packet channel. It
// neither acquires nor configures networking. Bind does not forward packets;
// Start is a separate, one-shot action. No application path calls either API.
// Do not copy it. Stop/Wait must establish completion before discarding it.
// All handles and historical identity remain retained after any failure.
type TUNRelay struct {
	self *TUNRelay
	mu sync.Mutex
	tun *TUNResource
	child PacketIO
	done chan struct{}
	attempted bool
	cancel context.CancelFunc
	counts Counts
	runErr error
	cleanupErr error
}

// BindTUNRelay transfers ownership only on success. It performs no device I/O,
// packet forwarding or mutation. Failure leaves both arguments with their
// existing owner; in particular, a duplicate cannot close an active alias.
// Successful ownership claims are permanent, including after Stop or failure.
// The caller must not use/close/share either endpoint after ownership transfer.
// Only NewDatagramPackets' concrete transport is admitted by this public API.
func BindTUNRelay(tun *TUNResource, child *DatagramPackets) (*TUNRelay, error) {
	if child == nil || child.self != child || child.file == nil || child.raw == nil || child.recv == nil || child.send == nil {
		return nil, errTUNRelay
	}
	return bindTUNRelay(tun, child, &child.relayClaim)
}

// Only package tests can substitute packet endpoints. The production entry
// point always supplies the concrete child's own permanent claim.
func bindTUNRelay(tun *TUNResource, child PacketIO, claim *tunRelayClaim) (*TUNRelay, error) {
	if tun == nil || tun.self != tun || nilEndpoint(child) || claim == nil {
		return nil, errTUNRelay
	}
	// Fixed lock order. Neither lock is held during packet I/O or pump joins.
	claim.mu.Lock()
	defer claim.mu.Unlock()
	tun.mu.Lock()
	defer tun.mu.Unlock()
	if claim.owner != nil || tun.relay != nil || tun.closed || tun.device == nil || !tun.observed {
		return nil, errors.Join(errTUNRelay, tun.closeErr)
	}
	r := &TUNRelay{tun: tun, child: child, done: make(chan struct{})}
	r.self = r
	claim.owner, tun.relay = r, r
	return r, nil
}

// Binding is historical identity and remains available after local shutdown.
func (r *TUNRelay) Binding() TUNRelayBinding {
	if r == nil || r.self != r || r.done == nil { return TUNRelayBinding{} }
	return TUNRelayBinding{owner: r}
}

// CheckBinding checks exact retained-owner identity without live I/O. It never
// resolves a name or treats a matching observation as authority over a new TUN.
func (r *TUNRelay) CheckBinding(b TUNRelayBinding) error {
	if r == nil || r.self != r || r.done == nil || b.owner != r { return errTUNRelay }
	return nil
}

// Start consumes its only attempt BEFORE validating context, policy or fresh
// descriptor observation. Any failure closes both owned endpoints. Policy is
// separately trusted provisioning, never inferred from a native offer. It is
// copied and revalidated, including rejecting a zero Policy. A nil return means
// only that a local run was launched, not that it is still running or ready.
// Context covers the run's whole lifetime. Kernel syscalls and short mutex waits
// cannot be interrupted by it. No complete host-policy attestation is provided.
func (r *TUNRelay) Start(ctx context.Context, policy *Policy) error {
	if r == nil || r.self != r || r.done == nil { return errTUNRelay }
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.attempted { return errTUNRelay }
	r.attempted = true
	fail := func(err error) error {
		r.finishBeforeRunLocked(err)
		return r.runErr
	}
	if ctx == nil || policy == nil { return fail(errTUNRelay) }
	if err := ctx.Err(); err != nil { return fail(err) }
	frozen, err := NewPolicy(policy.cfg)
	if err != nil { return fail(err) }
	if _, err = r.tun.Observe(ctx); err != nil { return fail(err) }
	if err = ctx.Err(); err != nil { return fail(err) }
	run, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	go func() {
		counts, runErr := Run(run, frozen, &tunRelayPackets{resource: r.tun}, r.child)
		cancel()
		r.mu.Lock()
		r.counts, r.runErr = counts, runErr
		if errors.Is(runErr, ErrCleanup) { r.cleanupErr = runErr }
		close(r.done)
		r.mu.Unlock()
	}()
	return nil
}

func (r *TUNRelay) finishBeforeRunLocked(cause error) {
	closeErr := errors.Join(r.tun.Close(), r.child.Close())
	if closeErr != nil { r.cleanupErr = errors.Join(ErrCleanup, closeErr) }
	r.runErr = errors.Join(cause, r.cleanupErr)
	close(r.done)
}

// Stop permanently prevents start or cancels the original run, then joins it.
// Its nil result proves only local pump completion and successful handle closes,
// never link/routes/DNS absence. Operational Run errors remain available in Wait.
// A wait timeout returns ErrCleanup without erasing the owner or completion
// channel; later Stop/Wait can join that SAME run. Actual close errors are sticky.
func (r *TUNRelay) Stop(ctx context.Context) error {
	if r == nil || r.self != r || r.done == nil || ctx == nil { return errTUNRelay }
	r.mu.Lock()
	if !r.attempted {
		r.attempted = true
		r.finishBeforeRunLocked(context.Canceled)
	} else if r.cancel != nil {
		r.cancel()
	}
	r.mu.Unlock()
	if err := r.waitDone(ctx); err != nil { return errors.Join(ErrCleanup, err) }
	return r.cleanupErr
}

// Wait observes completion, without canceling the run. A caller timeout is not
// a completed relay result. The immutable final result can be read repeatedly.
func (r *TUNRelay) Wait(ctx context.Context) (Counts, error) {
	if r == nil || r.self != r || r.done == nil || ctx == nil { return Counts{}, errTUNRelay }
	if err := r.waitDone(ctx); err != nil { return Counts{}, err }
	return r.counts, r.runErr
}

func (r *TUNRelay) waitDone(ctx context.Context) error {
	// Prefer an already-established terminal result over caller cancellation.
	select { case <-r.done: return nil; default: }
	select {
	case <-r.done: return nil
	case <-ctx.Done(): return ctx.Err()
	}
}

// This private adapter is never given to the native child. The device pointer
// is immutable after acquisition. Do not hold the lifecycle mutex across I/O:
// the original Close must be able to unblock both pending reads and writes.
type tunRelayPackets struct { resource *TUNResource }
func (p *tunRelayPackets) ReadPacket(b []byte) (int, error) { return p.resource.device.readPacket(b) }
func (p *tunRelayPackets) WritePacket(b []byte) (int, error) { return p.resource.device.writePacket(b) }
func (p *tunRelayPackets) Close() error { return p.resource.Close() }
