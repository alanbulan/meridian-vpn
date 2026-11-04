//go:build linux

package core

import (
	"context"
	"errors"

	"mygo-vpn/internal/nmvpn"
)

// UniVPNNMIPv4Observation associates NM's post-publication projection with the
// original local worker/relay receipt. Local is historical metadata. IPv4 is an
// NM projection, not kernel route/RPDB/resolver readback or an ownership lease.
// Neither this value nor matching observations authorize Ready or cleanup.
type UniVPNNMIPv4Observation struct {
	Local UniVPNNMLocalSnapshot
	IPv4  nmvpn.IPv4ObservationSnapshot
}

// ObserveIPv4 reads through the original receipt and concrete activation only.
// It accepts no replacement bus, activation, offer, paths, or expected policy.
// The receipt consumes one observation attempt and quarantines on failure;
// callers must not retry it. Invoke outside Broker callbacks (which hold locks
// needed by NM). No configuration is published and no resources are acquired or
// stopped. The existing independent HostBinding startup gate remains required.
func (l *UniVPNNMLocalBinding) ObserveIPv4(ctx context.Context) (UniVPNNMIPv4Observation, error) {
	if l == nil || l.self != l || l.receipt == nil {
		return UniVPNNMIPv4Observation{}, errUniVPNNM
	}
	a, ok := l.activation.(*nmvpn.Activation)
	if !ok || a == nil {
		return UniVPNNMIPv4Observation{}, errUniVPNNM
	}
	return l.observeIPv4(ctx, func(ctx context.Context) (nmvpn.IPv4ObservationSnapshot, error) {
		observation, err := l.receipt.ObserveIPv4(ctx, a)
		if err != nil {
			return nmvpn.IPv4ObservationSnapshot{}, err
		}
		return observation.Snapshot()
	})
}

// Only package tests replace the cross-package observer. Production uses the
// receipt's bounded parser and never accepts caller-created observation data.
func (l *UniVPNNMLocalBinding) observeIPv4(ctx context.Context, observe func(context.Context) (nmvpn.IPv4ObservationSnapshot, error)) (UniVPNNMIPv4Observation, error) {
	zero := UniVPNNMIPv4Observation{}
	if l == nil || l.self != l || l.broker == nil || l.receipt == nil || observe == nil || l.broker.CheckLocalBinding(ctx, l) != nil {
		return zero, errUniVPNNM
	}
	local, err := l.Snapshot()
	if err != nil {
		return zero, errUniVPNNM
	}
	projection, err := observe(ctx)
	if err != nil || projection.Binding != local.Binding || projection.Address != local.Offer.Address || ctx.Err() != nil || l.broker.CheckLocalBinding(ctx, l) != nil {
		return zero, errors.Join(errUniVPNNM, err, ctx.Err())
	}
	// The NM parser already validates exact routes against the bound offer.
	// Copy its collections again to keep this combined result independently owned.
	projection.ParentDevices = append(projection.ParentDevices[:0:0], projection.ParentDevices...)
	projection.Routes = append(projection.Routes[:0:0], projection.Routes...)
	return UniVPNNMIPv4Observation{Local: local, IPv4: projection}, nil
}
