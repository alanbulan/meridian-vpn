//go:build linux

package nmvpn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
)

// ActivationRecord contains identifiers only. No credentials or profiles belong
// in the journal. A prior record never constitutes a recoverable receipt.
type ActivationRecord struct {
	Version                                                   int
	BootID, BusID, Owner, PluginOwner, UUID, Interface, Nonce string
	ConnectionPath, ActivePath, Phase                         string
}
type ActivationJournal interface {
	LoadActivation() (*ActivationRecord, error)
	SaveActivation(ActivationRecord) error
}

func validateActivationRecord(r ActivationRecord) error {
	if r.Version != 1 || !uuidPattern.MatchString(r.BootID) || !sessionPattern.MatchString(r.BusID) || !validPluginOwner(r.Owner) || !validPluginOwner(r.PluginOwner) || !uuidPattern.MatchString(r.UUID) || !linkPattern.MatchString(r.Interface) || r.Interface == "lo" || !sessionPattern.MatchString(r.Nonce) {
		return errPeer
	}
	settings := r.ConnectionPath != ""
	active := r.ActivePath != ""
	if (settings && (len(r.ConnectionPath) > 128 || !settingsPathPattern.MatchString(r.ConnectionPath))) || (active && (len(r.ActivePath) > 128 || !activePattern.MatchString(r.ActivePath))) || (active && !settings) {
		return errPeer
	}
	switch r.Phase {
	case "add-intent":
		if settings || active {
			return errPeer
		}
	case "added", "activate-intent":
		if !settings || active {
			return errPeer
		}
	case "activated", "correlated":
		if !settings || !active {
			return errPeer
		}
	case "quarantine":
	default:
		return errPeer
	}
	return nil
}

const managerSettingsPath = dbus.ObjectPath("/org/freedesktop/NetworkManager/Settings")
const managerSettingsInterface = "org.freedesktop.NetworkManager.Settings"

// BootIdentity reads the boot identity from trusted provisioning, never from a
// gateway, profile, environment variable or desktop request.
type BootIdentity func(context.Context) (string, error)

// ActivationManager owns one non-replayable manager transaction. The supplied
// journal must be exclusively held for this manager's entire lifetime. It never
// discovers a bus or recovers authority from a UUID or an on-disk record.
type ActivationManager struct {
	mu      sync.Mutex
	bus     *PinnedBus
	plugin  *Plugin
	journal ActivationJournal
	boot    BootIdentity
	bootID  string
	started bool
	record  ActivationRecord
	profile map[string]map[string]dbus.Variant

	// Protected by mu; a copied receipt cannot repeat the observation attempt.
	hostObservationClaimed bool
	ipv4ObservationClaimed bool
}

// ActivationReceipt is unforgeable outside this package. It proves only the
// manager transaction and matching authenticated Connect, not worker/link policy,
// cleanup authority, applied networking or native readiness.
type ActivationReceipt struct {
	manager    *ActivationManager
	activation *Activation
}

func NewActivationManager(ctx context.Context, bus *PinnedBus, plugin *Plugin, journal ActivationJournal, boot BootIdentity) (*ActivationManager, error) {
	if ctx == nil || ctx.Err() != nil || bus == nil || plugin == nil || plugin.bus != bus || bus.plugin.Load() != plugin || nilValue(journal) || boot == nil {
		return nil, errPeer
	}
	if !plugin.managerClaimed.CompareAndSwap(false, true) {
		return nil, errPeer
	}
	m := &ActivationManager{bus: bus, plugin: plugin, journal: journal, boot: boot}
	admitted := false
	defer func() {
		if !admitted {
			plugin.fence()
			_ = bus.Close()
		}
	}()
	id, err := boot(ctx)
	if err != nil || !uuidPattern.MatchString(id) {
		return nil, errPeer
	}
	m.bootID = id
	// A prior intent, including a fully acknowledged transaction, cannot mint a
	// new receipt. Recovery is quarantine-only and performs no manager mutation.
	old, err := journal.LoadActivation()
	if err != nil {
		return nil, errPeer
	}
	if old != nil {
		if validateActivationRecord(*old) == nil {
			old.Phase = "quarantine"
			_ = journal.SaveActivation(*old)
		}
		return nil, errPeer
	}
	if m.check(ctx) != nil {
		return nil, errPeer
	}
	plugin.mu.Lock()
	defer plugin.mu.Unlock()
	if plugin.consumed || plugin.disconnected.Load() {
		return nil, errPeer
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errPeer
	}
	plugin.plan.Nonce = hex.EncodeToString(nonce[:])
	admitted = true
	return m, nil
}

func (m *ActivationManager) check(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || m.plugin.ctx.Err() != nil || m.plugin.disconnected.Load() || m.bus.plugin.Load() != m.plugin {
		return errPeer
	}
	boot, err := m.boot(ctx)
	if err != nil || boot != m.bootID {
		return errPeer
	}
	return m.bus.run(ctx, func(ctx context.Context) error { return m.bus.check(ctx, true) })
}

func (m *ActivationManager) quarantine() error {
	m.started = true
	if m.record.Version != 0 {
		m.record.Phase = "quarantine"
		_ = m.journal.SaveActivation(m.record)
	}
	m.plugin.fence()
	_ = m.bus.Close()
	return errPeer
}

func (m *ActivationManager) save(phase string) error {
	m.record.Phase = phase
	return m.journal.SaveActivation(m.record)
}

// Start installs an immutable secret-free profile and requests its activation.
// The nonce is the fresh nonce of the matching served PluginPlan. Inputs must be
// owned by the caller for this call (concurrent mutation of Go maps is invalid).
// No password is accepted or stored here. NM supplies credentials via Connect.
func (m *ActivationManager) Start(ctx context.Context, network map[string]map[string]dbus.Variant) (*ActivationReceipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return nil, errPeer
	}
	m.started = true
	plan := m.plugin.plan
	if ValidateProfile(network, Identity{UUID: plan.UUID, Interface: plan.Interface}) != nil {
		return nil, m.quarantine()
	}
	m.profile = cloneSafeProfile(network)
	// Normalize the optional empty envelope before captured-profile checks.
	delete(m.profile["vpn"], "data")
	delete(m.profile["vpn"], "secrets")
	m.profile["connection"]["autoconnect"] = dbus.MakeVariant(false)
	profile := cloneSafeProfile(m.profile)
	profile["vpn"]["user-name"] = dbus.MakeVariant(plan.Username)
	profile["vpn"]["data"] = dbus.MakeVariant(map[string]string{"meridian-activation": plan.Nonce, "password-flags": "2"})
	if m.check(ctx) != nil || m.plugin.activation.Load() != nil {
		return nil, m.quarantine()
	}
	// Re-read to fail closed if a wrongly shared/custom journal changed.
	old, err := m.journal.LoadActivation()
	if err != nil || old != nil {
		// Never replace unexpected/corrupt evidence with this new transaction.
		m.record = ActivationRecord{}
		if err == nil && old != nil && validateActivationRecord(*old) == nil {
			m.record = *old
		}
		return nil, m.quarantine()
	}
	m.record = ActivationRecord{Version: 1, BootID: m.bootID, BusID: m.bus.pin.BusID, Owner: m.bus.pin.Owner, PluginOwner: m.bus.unique, UUID: plan.UUID, Interface: plan.Interface, Nonce: plan.Nonce, Phase: "add-intent"}
	if m.save("add-intent") != nil {
		return nil, m.quarantine()
	}
	var settings dbus.ObjectPath
	var result map[string]dbus.Variant
	err = m.bus.run(ctx, func(ctx context.Context) error {
		if m.bus.check(ctx, true) != nil {
			return errPeer
		}
		return m.bus.call(ctx, m.record.Owner, managerSettingsPath, managerSettingsInterface+".AddConnection2", []any{profile, uint32(0x22), map[string]dbus.Variant{}}, &settings, &result)
	})
	if err != nil || len(result) > 64 || len(settings) > 128 || !settingsPathPattern.MatchString(string(settings)) {
		return nil, m.quarantine()
	}
	m.record.ConnectionPath = string(settings)
	if m.save("added") != nil || m.check(ctx) != nil {
		return nil, m.quarantine()
	}
	if m.save("activate-intent") != nil || m.check(ctx) != nil {
		return nil, m.quarantine()
	}
	var active dbus.ObjectPath
	// Do not hold bus.mu: NM may synchronously call Connect before returning.
	// Connect authenticates and emits its state on this same pinned connection.
	err = m.activate(ctx, settings, &active)
	if err != nil || len(active) > 128 || !activePattern.MatchString(string(active)) {
		return nil, m.quarantine()
	}
	m.record.ActivePath = string(active)
	if m.save("activated") != nil || m.check(ctx) != nil {
		return nil, m.quarantine()
	}
	return &ActivationReceipt{manager: m}, nil
}

func (m *ActivationManager) activate(ctx context.Context, settings dbus.ObjectPath, active *dbus.ObjectPath) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = m.bus.Close(); close(done) })
	err := m.bus.call(ctx, m.record.Owner, NMPath, NMName+".ActivateConnection", []any{settings, dbus.ObjectPath("/"), dbus.ObjectPath("/")}, active)
	if !stop() {
		<-done
	}
	if ctx.Err() != nil {
		_ = m.bus.Close()
		return errPeer
	}
	return err
}

// Correlate accepts only the exact Plugin's authenticated, nonce-checked Connect
// and reads back the exact returned objects. Binding is output, never authority
// supplied by a caller. Session stays empty until the native owner creates it.
func (r *ActivationReceipt) Correlate(ctx context.Context, activation *Activation) (Binding, error) {
	if r == nil || r.manager == nil {
		return Binding{}, errPeer
	}
	m := r.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	fail := func() (Binding, error) { return Binding{}, m.quarantine() }
	if ctx == nil || (m.record.Phase != "activated" && m.record.Phase != "correlated") || activation == nil || activation.plugin != m.plugin || activation.CheckLive(ctx) != nil || activation.Nonce() != m.record.Nonce || !equivalentProfiles(m.profile, activation.profile, Identity{UUID: m.record.UUID, Interface: m.record.Interface}) || (r.activation != nil && r.activation != activation) || m.check(ctx) != nil {
		return fail()
	}
	err := m.bus.run(ctx, func(ctx context.Context) error {
		var props map[string]dbus.Variant
		if m.bus.call(ctx, m.record.Owner, dbus.ObjectPath(m.record.ActivePath), propertiesInterface+".GetAll", []any{ActiveInterface}, &props) != nil || len(props) > 64 || !profileEqual(props["Uuid"], m.record.UUID) || !profileEqual(props["Type"], "vpn") || !profileEqual(props["Vpn"], true) || !profileEqual(props["Connection"], dbus.ObjectPath(m.record.ConnectionPath)) {
			return errPeer
		}
		var current map[string]map[string]dbus.Variant
		if m.bus.call(ctx, m.record.Owner, dbus.ObjectPath(m.record.ConnectionPath), SettingsInterface+".GetSettings", nil, &current) != nil {
			return errPeer
		}
		network, password, err := incomingProfile(current, m.plugin.plan)
		if err != nil || password != "" || !equivalentProfiles(m.profile, network, Identity{UUID: m.record.UUID, Interface: m.record.Interface}) {
			return errPeer
		}
		return m.bus.check(ctx, true)
	})
	if err != nil || activation.CheckLive(ctx) != nil || m.check(ctx) != nil {
		return fail()
	}
	if m.record.Phase != "correlated" && m.save("correlated") != nil {
		return fail()
	}
	r.activation = activation
	return Binding{Identity: Identity{BootID: m.record.BootID, BusID: m.record.BusID, Owner: m.record.Owner, UUID: m.record.UUID, ActivePath: m.record.ActivePath, Interface: m.record.Interface}, ConnectionPath: dbus.ObjectPath(m.record.ConnectionPath), PluginOwner: m.record.PluginOwner}, nil
}
