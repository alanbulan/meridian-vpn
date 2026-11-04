//go:build linux

package core

import (
	"context"
	"errors"
	"reflect"

	"mygo-vpn/internal/packetrelay"
)

// UniVPNNMPolicyObservation associates a sequential policy read with the
// original local TUN namespace. It grants no host/publication/cleanup authority.
// Kernel policy records must still be interpreted and DNS/firewall/dispatcher
// state inspected independently; matching reads cannot exclude intervening ABA.
type UniVPNNMPolicyObservation struct {
	Local  UniVPNNMKernelObservation
	Policy packetrelay.KernelPolicyObservation
}

// ObserveKernelPolicy reads the namespace of the retained original TUN, checking
// its local association and kernel link before and after the policy dump. It
// does not resolve the independent HostBinding required to prepare the broker.
// Every failed read leaves resource cleanup with the original retained owners.
func (l *UniVPNNMLocalBinding) ObserveKernelPolicy(ctx context.Context) (UniVPNNMPolicyObservation, error) {
	return l.observeKernelPolicy(ctx, l.ObserveKernelLink, packetrelay.ObserveKernelPolicy)
}

func (l *UniVPNNMLocalBinding) observeKernelPolicy(ctx context.Context, link func(context.Context) (UniVPNNMKernelObservation, error), policy func(context.Context, packetrelay.KernelNamespaceIdentity) (packetrelay.KernelPolicyObservation, error)) (UniVPNNMPolicyObservation, error) {
	zero := UniVPNNMPolicyObservation{}
	if l == nil || l.self != l || ctx == nil || ctx.Err() != nil || link == nil || policy == nil {
		return zero, errUniVPNNM
	}
	before, err := link(ctx)
	if err != nil || before.Kernel.Namespace.Inode == 0 || ctx.Err() != nil {
		return zero, errors.Join(errUniVPNNM, err, ctx.Err())
	}
	observed, err := policy(ctx, before.Kernel.Namespace)
	if err != nil || observed.Namespace != before.Kernel.Namespace || ctx.Err() != nil {
		return zero, errors.Join(errUniVPNNM, err, ctx.Err())
	}
	after, err := link(ctx)
	if err != nil || !reflect.DeepEqual(before, after) || ctx.Err() != nil {
		return zero, errors.Join(errUniVPNNM, err, ctx.Err())
	}
	// Do not retain or expose an alias even at the private test seam.
	copied := make([]packetrelay.KernelPolicyRecord, len(observed.Records))
	for i, record := range observed.Records {
		copied[i] = packetrelay.KernelPolicyRecord{Type: record.Type, Data: append([]byte(nil), record.Data...)}
	}
	observed.Records = copied
	return UniVPNNMPolicyObservation{Local: before, Policy: observed}, nil
}
