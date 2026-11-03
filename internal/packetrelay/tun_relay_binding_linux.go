//go:build linux

package packetrelay

import (
	"context"
	"errors"
)

// ObservePacketBinding checks the exact retained concrete child and returns a
// fresh observation of this relay's original TUN. The name is only an expected
// value, never permission to look up, adopt, or close an interface by name.
// The caller acquires no ownership and must retain the relay's existing owner
// for Stop/Wait. Rejection never closes either endpoint or consumes Start.
//
// This is a bounded, process-local association, not host authority, a native
// generation receipt, an NM binding, namespace proof, or readiness. In
// particular, equality with an NM interface name grants no host ownership.
// Success does not ensure that either endpoint remains open after return.
// Context cannot interrupt an in-flight syscall or a lifecycle mutex wait.
func (r *TUNRelay) ObservePacketBinding(ctx context.Context, child *DatagramPackets, name string) (TUNRelayBinding, TUNObservation, error) {
	reject := func(err error) (TUNRelayBinding, TUNObservation, error) {
		return TUNRelayBinding{}, TUNObservation{}, errors.Join(errTUNRelay, err)
	}
	if r.CheckPacketBinding(r.Binding(), child) != nil || ctx == nil {
		return reject(nil)
	}
	if err := ctx.Err(); err != nil {
		return reject(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.done:
		return reject(r.cleanupErr)
	default:
	}
	if err := ctx.Err(); err != nil {
		return reject(err)
	}
	if r.tun == nil || r.tun.self != r.tun {
		return reject(nil)
	}
	// Match Start's lock order: relay before TUN, with no pump join inside.
	r.tun.mu.Lock()
	defer r.tun.mu.Unlock()
	if r.tun.relay != r || r.tun.closed || r.tun.device == nil || !r.tun.observed {
		return reject(errors.Join(errTUNResource, r.tun.closeErr))
	}
	if name != r.tun.initial.Name {
		return reject(errTUNResource)
	}
	if err := ctx.Err(); err != nil {
		return reject(err)
	}
	// Probe only the original retained RawConn. This cannot consume packets,
	// mutate socket flags, adopt a replacement, or reopen a closed descriptor.
	if err := child.raw.Control(func(uintptr) {}); err != nil {
		return reject(err)
	}
	if err := ctx.Err(); err != nil {
		return reject(err)
	}
	// TUNResource.Observe closes on failure. This non-owning check deliberately
	// reads without that lifecycle side effect; the owner retains all cleanup.
	value, err := r.tun.device.observe()
	if err != nil || value != r.tun.initial || ctx.Err() != nil {
		return reject(errors.Join(errTUNResource, err, ctx.Err()))
	}
	return r.Binding(), value, nil
}

// CheckPacketBinding checks historical exact relay and concrete child identity
// without live I/O. A different pair, same-name TUN, session label, copied owner,
// or copied child cannot substitute for the original objects. It remains valid
// after failed start, stop, descriptor drift, or uncertain cleanup, but proves
// neither current liveness nor independent host network absence.
func (r *TUNRelay) CheckPacketBinding(binding TUNRelayBinding, child *DatagramPackets) error {
	if r.CheckBinding(binding) != nil || child == nil || child.self != child || child.file == nil || child.raw == nil || child.recv == nil || child.send == nil {
		return errTUNRelay
	}
	retained, ok := r.child.(*DatagramPackets)
	if !ok || retained != child {
		return errTUNRelay
	}
	return nil
}
