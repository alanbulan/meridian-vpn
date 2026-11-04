//go:build linux

package nmvpn

import (
	"context"

	"github.com/godbus/dbus/v5"
)

// RetainedCorrelation returns the identity retained by a successful Correlate
// for this exact receipt and authenticated activation. A receipt copied after
// correlation retains the same manager provenance; an uncorrelated receipt or
// an arbitrary Binding cannot create that provenance.
//
// This is a local, read-only historical correlation, not a fresh NM readback,
// networking lease, host-policy proof, cleanup authority, or readiness permit.
// Local cancellation, revocation, and quarantine still reject it. It never
// calls NM, reads boot identity or a journal, changes state, fences a plugin, or
// closes a bus, including when the caller supplies a foreign activation. Session
// remains empty; no native worker or link is identified by this result.
func (r *ActivationReceipt) RetainedCorrelation(ctx context.Context, activation *Activation) (Binding, error) {
	if r == nil || r.manager == nil || ctx == nil || ctx.Err() != nil {
		return Binding{}, errPeer
	}
	m := r.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	// Correlate writes r.activation and the phase while holding this same lock.
	// The captured profile, plan, and bus pins are immutable after Start.
	if !m.started || m.plugin == nil || m.bus == nil || nilValue(m.journal) || m.boot == nil || m.record.Phase != "correlated" || validateActivationRecord(m.record) != nil || activation == nil || r.activation != activation || activation.ctx == nil {
		return Binding{}, errPeer
	}
	p := m.plugin
	if activation.plugin != p || p.ctx == nil || p.ctx.Err() != nil || p.bus != m.bus || m.bus.plugin.Load() != p || !p.managerClaimed.Load() || activation.CheckLive(ctx) != nil {
		return Binding{}, errPeer
	}
	plan := p.plan
	if !validPluginPlan(plan) || m.record.BootID != m.bootID || m.record.BusID != m.bus.pin.BusID || m.record.Owner != m.bus.pin.Owner || m.record.PluginOwner != m.bus.unique || m.record.UUID != plan.UUID || m.record.Interface != plan.Interface || m.record.Nonce != plan.Nonce || activation.Nonce() != m.record.Nonce || !equivalentProfiles(m.profile, activation.profile, Identity{UUID: m.record.UUID, Interface: m.record.Interface}) {
		return Binding{}, errPeer
	}
	// Profile validation is bounded, but cancellation/revocation can happen
	// independently of the manager mutex. Recheck before returning the copy.
	if p.ctx.Err() != nil || activation.CheckLive(ctx) != nil {
		return Binding{}, errPeer
	}
	return Binding{
		Identity: Identity{
			BootID: m.record.BootID, BusID: m.record.BusID, Owner: m.record.Owner,
			UUID: m.record.UUID, ActivePath: m.record.ActivePath, Interface: m.record.Interface,
		},
		ConnectionPath: dbus.ObjectPath(m.record.ConnectionPath), PluginOwner: m.record.PluginOwner,
	}, nil
}
