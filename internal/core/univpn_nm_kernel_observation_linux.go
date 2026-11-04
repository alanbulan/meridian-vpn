//go:build linux

package core

import (
	"context"
	"errors"

	"mygo-vpn/internal/packetrelay"
)

// UniVPNNMKernelObservation attaches sequential kernel observations to an
// already-established historical local association. Local remains historical:
// this does not refresh native/NM liveness, prove NM owns this kernel link, or
// identify the initial host namespace. Kernel.Link is a name/index lookup, not
// an FD-derived device-generation identity. No publication/cleanup authority is
// acquired, and the mandatory independent HostBinding is not replaced.
type UniVPNNMKernelObservation struct {
	Local  UniVPNNMLocalSnapshot
	Kernel packetrelay.TUNKernelObservation
}

// ObserveKernelLink reads only the original relay/TUN retained by this opaque
// local token. It neither discovers NM devices nor treats parent Devices or a
// same-name NM object as VPN ownership. Calling it requires the previously
// prepared broker and cannot resolve the missing HostBinding startup gate.
// Existing owners must retain and close the resources after any read failure.
func (l *UniVPNNMLocalBinding) ObserveKernelLink(ctx context.Context) (UniVPNNMKernelObservation, error) {
	if l == nil || l.self != l || l.relay == nil {
		return UniVPNNMKernelObservation{}, errUniVPNNM
	}
	return l.observeKernelLink(ctx, func(ctx context.Context) (packetrelay.TUNKernelObservation, error) {
		return l.relay.ObserveKernelBinding(ctx, l.relayBinding)
	})
}

// Only package tests substitute the cross-package kernel observation.
func (l *UniVPNNMLocalBinding) observeKernelLink(ctx context.Context, observe func(context.Context) (packetrelay.TUNKernelObservation, error)) (UniVPNNMKernelObservation, error) {
	zero := UniVPNNMKernelObservation{}
	if l == nil || l.self != l || l.broker == nil || observe == nil || l.broker.CheckLocalBinding(ctx, l) != nil {
		return zero, errUniVPNNM
	}
	local, err := l.Snapshot()
	if err != nil {
		return zero, errUniVPNNM
	}
	kernel, err := observe(ctx)
	if err != nil || kernel.TUN != local.TUN || kernel.Link.Name != local.Binding.Identity.Interface || kernel.Link.Index <= 0 || kernel.Namespace.Inode == 0 || ctx.Err() != nil || l.broker.CheckLocalBinding(ctx, l) != nil {
		return zero, errors.Join(errUniVPNNM, err, ctx.Err())
	}
	return UniVPNNMKernelObservation{Local: local, Kernel: kernel}, nil
}
