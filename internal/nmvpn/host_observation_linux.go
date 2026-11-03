//go:build linux

package nmvpn

import (
	"context"
	"reflect"
	"regexp"
	"sort"

	"github.com/godbus/dbus/v5"
)

const (
	hostMaxParentDevices     = 32
	hostMaxActiveConnections = 256
	hostMaxObjectPath        = 128
)

var hostParentDevicePattern = regexp.MustCompile(`^/org/freedesktop/NetworkManager/Devices/[0-9]+$`)

// HostObservationSnapshot is diagnostic data from an initial activation, not
// authority to publish, declare readiness, or clean up. Binding.Identity.Interface
// is the requested name, not an observed VPN TUN. ParentDevices are participating
// parent/physical devices; their paths establish no owned link or worker identity.
type HostObservationSnapshot struct {
	Binding       Binding
	State         uint32
	Default       bool
	Default6      bool
	IP4Config     dbus.ObjectPath
	IP6Config     dbus.ObjectPath
	ParentDevices []dbus.ObjectPath
}

// HostObservation is an immutable, historical observation. It deliberately has
// no live-check, readiness, binding, cleanup, or host-authority methods. It cannot
// implement a Broker or replace the native HostAuthority/HostBinding boundary.
type HostObservation struct{ snapshot *HostObservationSnapshot }

// Snapshot returns an independent copy. A zero/nil observation is not evidence.
// A successful copy does not refresh or revalidate this historical observation.
func (o *HostObservation) Snapshot() (HostObservationSnapshot, error) {
	if o == nil || o.snapshot == nil {
		return HostObservationSnapshot{}, errPeer
	}
	snapshot := *o.snapshot
	snapshot.ParentDevices = append([]dbus.ObjectPath{}, snapshot.ParentDevices...)
	return snapshot, nil
}

// ObserveHost makes one read-only observation attempt after Correlate succeeds
// for this exact authenticated Connect. It accepts only ACTIVATING (1), before
// this plugin has sent Config, with false default flags and '/' config paths.
// Requiring ACTIVATED here would depend on the configuration this preflight must
// precede. Unsupported/missing values and any observed changes fail closed.
//
// Two matching readbacks are NOT an atomic snapshot or a networking lease. In
// particular, '/' config paths during ACTIVATING do not prove config absence,
// false default flags do not exclude /1 or policy routes, and this does not read
// global NM policy, dispatchers, routes, DNS, processes, or VPN device identity.
// Only the named ActiveConnection fields are requested. Additive metadata is
// deliberately unobserved; this is not a whole-policy validator. GetSettings
// uses the same closed profile/envelope equivalence as the receipt path, never
// Device.GetAppliedConnection (a parent device is not this VPN's applied policy).
//
// Calls target only the already pinned unique owner, without bus discovery or
// service activation. Failure retains local quarantine and closes this plugin's
// bus; it never deactivates, deletes, or otherwise mutates NM networking.
// Property types and state: https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Connection.Active.html
func (r *ActivationReceipt) ObserveHost(ctx context.Context, activation *Activation) (*HostObservation, error) {
	if r == nil || r.manager == nil {
		return nil, errPeer
	}
	m := r.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.plugin == nil || m.bus == nil || nilValue(m.journal) || m.boot == nil {
		return nil, errPeer
	}
	fail := func() (*HostObservation, error) { return nil, m.quarantine() }
	if m.hostObservationClaimed {
		return fail()
	}
	m.hostObservationClaimed = true
	if r.checkObservation(ctx, activation) != nil || m.check(ctx) != nil {
		return fail()
	}
	var first, second hostObservationReadback
	err := m.bus.run(ctx, func(ctx context.Context) error {
		// Do not call Correlate, m.check, or another bus.run while bus.mu is held.
		if m.bus.check(ctx, true) != nil || r.checkObservation(ctx, activation) != nil {
			return errPeer
		}
		var err error
		first, err = m.readHostObservation(ctx)
		if err != nil {
			return errPeer
		}
		second, err = m.readHostObservation(ctx)
		if err != nil || !reflect.DeepEqual(first, second) || r.checkObservation(ctx, activation) != nil {
			return errPeer
		}
		return m.bus.check(ctx, true)
	})
	if err != nil || r.checkObservation(ctx, activation) != nil || m.check(ctx) != nil {
		return fail()
	}
	return &HostObservation{snapshot: &second.snapshot}, nil
}

// checkObservation does no bus I/O. Its caller holds the manager mutex; the
// original activation/profile and manager plan are immutable after Start.
func (r *ActivationReceipt) checkObservation(ctx context.Context, activation *Activation) error {
	m := r.manager
	if ctx == nil || ctx.Err() != nil || !m.started || m.record.Phase != "correlated" || validateActivationRecord(m.record) != nil || activation == nil || activation != r.activation || activation.plugin != m.plugin || activation.ctx == nil || activation.CheckLive(ctx) != nil || m.plugin.bus != m.bus || m.bus.plugin.Load() != m.plugin || m.plugin.published.Load() != 0 {
		return errPeer
	}
	plan := m.plugin.plan
	if m.record.BootID != m.bootID || m.record.BusID != m.bus.pin.BusID || m.record.Owner != m.bus.pin.Owner || m.record.PluginOwner != m.bus.unique || m.record.UUID != plan.UUID || m.record.Interface != plan.Interface || m.record.Nonce != plan.Nonce || activation.Nonce() != m.record.Nonce || !equivalentProfiles(m.profile, activation.profile, Identity{UUID: m.record.UUID, Interface: m.record.Interface}) {
		return errPeer
	}
	return nil
}

type hostObservationReadback struct {
	snapshot          HostObservationSnapshot
	activeConnections []dbus.ObjectPath
}

// readHostObservation is called only inside one bus.run with m.mu held.
func (m *ActivationManager) readHostObservation(ctx context.Context) (hostObservationReadback, error) {
	var out hostObservationReadback
	properties := make(map[string]dbus.Variant, 10)
	for _, name := range []string{"Uuid", "Type", "Vpn", "Connection", "State", "Default", "Default6", "Devices", "Ip4Config", "Ip6Config"} {
		var value dbus.Variant
		if m.bus.call(ctx, m.record.Owner, dbus.ObjectPath(m.record.ActivePath), propertiesInterface+".Get", []any{ActiveInterface, name}, &value) != nil {
			return out, errPeer
		}
		properties[name] = value
	}
	snapshot, err := parseHostObservation(properties, m.record)
	if err != nil {
		return out, errPeer
	}
	var current map[string]map[string]dbus.Variant
	if m.bus.call(ctx, m.record.Owner, dbus.ObjectPath(m.record.ConnectionPath), SettingsInterface+".GetSettings", nil, &current) != nil {
		return out, errPeer
	}
	network, password, err := incomingProfile(current, m.plugin.plan)
	if err != nil || password != "" || !equivalentProfiles(m.profile, network, Identity{UUID: m.record.UUID, Interface: m.record.Interface}) {
		return out, errPeer
	}
	var active dbus.Variant
	if m.bus.call(ctx, m.record.Owner, NMPath, propertiesInterface+".Get", []any{NMName, "ActiveConnections"}, &active) != nil {
		return out, errPeer
	}
	paths, err := hostObservationPaths(active, activePattern, hostMaxActiveConnections)
	if err != nil {
		return out, errPeer
	}
	present := false
	for _, path := range paths {
		if string(path) == m.record.ActivePath {
			present = true
		}
	}
	if !present {
		return out, errPeer
	}
	return hostObservationReadback{snapshot: snapshot, activeConnections: paths}, nil
}

func parseHostObservation(properties map[string]dbus.Variant, record ActivationRecord) (HostObservationSnapshot, error) {
	var out HostObservationSnapshot
	if len(properties) != 10 || validateActivationRecord(record) != nil || record.Phase != "correlated" {
		return out, errPeer
	}
	for _, field := range []struct {
		name  string
		value any
	}{
		{"Uuid", record.UUID}, {"Type", "vpn"}, {"Vpn", true},
		{"Connection", dbus.ObjectPath(record.ConnectionPath)},
		{"State", uint32(1)}, {"Default", false}, {"Default6", false},
		{"Ip4Config", dbus.ObjectPath("/")}, {"Ip6Config", dbus.ObjectPath("/")},
	} {
		if !profileEqual(properties[field.name], field.value) {
			return out, errPeer
		}
	}
	parents, err := hostObservationPaths(properties["Devices"], hostParentDevicePattern, hostMaxParentDevices)
	if err != nil {
		return out, errPeer
	}
	out = HostObservationSnapshot{
		Binding: Binding{
			Identity:       Identity{BootID: record.BootID, BusID: record.BusID, Owner: record.Owner, UUID: record.UUID, ActivePath: record.ActivePath, Interface: record.Interface},
			ConnectionPath: dbus.ObjectPath(record.ConnectionPath), PluginOwner: record.PluginOwner,
		},
		State: 1, IP4Config: "/", IP6Config: "/", ParentDevices: parents,
	}
	return out, nil
}

func hostObservationPaths(value dbus.Variant, pattern *regexp.Regexp, limit int) ([]dbus.ObjectPath, error) {
	paths, ok := value.Value().([]dbus.ObjectPath)
	if !ok || value.Signature().String() != "ao" || len(paths) > limit {
		return nil, errPeer
	}
	seen := make(map[dbus.ObjectPath]bool, len(paths))
	out := make([]dbus.ObjectPath, 0, len(paths))
	for _, path := range paths {
		if len(path) > hostMaxObjectPath || !path.IsValid() || !pattern.MatchString(string(path)) || seen[path] {
			return nil, errPeer
		}
		seen[path] = true
		out = append(out, path)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}
