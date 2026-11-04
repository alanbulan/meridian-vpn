//go:build linux

package nmvpn

import (
	"context"
	"net/netip"
	"reflect"
	"regexp"
	"sort"

	"github.com/godbus/dbus/v5"
)

const ipv4ConfigInterface = "org.freedesktop.NetworkManager.IP4Config"

var ipv4ConfigPathPattern = regexp.MustCompile(`^/org/freedesktop/NetworkManager/IP4Config/[0-9]+$`)

// IPv4ObservedRoute is one direct, main-table route visible in NM's projection.
// Metric is observed, not approved: the profile can inherit a global default.
type IPv4ObservedRoute struct {
	Destination netip.Prefix
	Metric      uint32
}

// IPv4ObservationSnapshot is a bounded NM projection tied to the manager receipt
// and already-bound native offer. NM's IP4Config does not enumerate all kernel
// route types or RPDB rules, resolver state, global policy or dispatcher effects.
// This is never independent host ownership, readiness or network-absence proof.
type IPv4ObservationSnapshot struct {
	Binding       Binding
	IP4Config     dbus.ObjectPath
	ParentDevices []dbus.ObjectPath
	Address       netip.Prefix
	Routes        []IPv4ObservedRoute
	DNSPriority   int32
}

type IPv4Observation struct{ snapshot *IPv4ObservationSnapshot }

// Snapshot copies historical diagnostic data without refreshing its evidence.
func (o *IPv4Observation) Snapshot() (IPv4ObservationSnapshot, error) {
	if o == nil || o.snapshot == nil {
		return IPv4ObservationSnapshot{}, errPeer
	}
	out := *o.snapshot
	out.ParentDevices = append([]dbus.ObjectPath{}, out.ParentDevices...)
	out.Routes = append([]IPv4ObservedRoute{}, out.Routes...)
	return out, nil
}

// ObserveIPv4 performs one read-only post-publication observation on the exact
// retained pinned bus. It accepts ACTIVATED only after both plugin configuration
// signals and an immutable native binding. It never accepts caller-selected
// paths, offers or expected route sets. Invoke outside Broker callbacks: those
// callbacks already run under the bus lock. There is no retry or state polling.
//
// Matching sequential samples are not atomic or a guarantee against later
// changes. Missing, unknown, inaccessible or drifting evidence fails closed and
// quarantines locally, without deactivating or otherwise mutating NM networking.
// This observation does not satisfy HostBinding.CheckLive or ProveAbsent.
func (r *ActivationReceipt) ObserveIPv4(ctx context.Context, activation *Activation) (*IPv4Observation, error) {
	if r == nil || r.manager == nil {
		return nil, errPeer
	}
	m := r.manager
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.plugin == nil || m.bus == nil || nilValue(m.journal) || m.boot == nil {
		return nil, errPeer
	}
	fail := func() (*IPv4Observation, error) { return nil, m.quarantine() }
	if m.ipv4ObservationClaimed {
		return fail()
	}
	m.ipv4ObservationClaimed = true
	binding, offer, err := r.ipv4ObservationInput(ctx, activation)
	if err != nil || m.check(ctx) != nil {
		return fail()
	}
	check := func() error {
		current, currentOffer, err := r.ipv4ObservationInput(ctx, activation)
		if err != nil || current != binding || !reflect.DeepEqual(currentOffer, offer) {
			return errPeer
		}
		return nil
	}
	var first, second ipv4ObservationReadback
	err = m.bus.run(ctx, func(ctx context.Context) error {
		if m.bus.check(ctx, true) != nil || check() != nil {
			return errPeer
		}
		var err error
		first, err = m.readIPv4Observation(ctx, binding, offer)
		if err != nil {
			return errPeer
		}
		second, err = m.readIPv4Observation(ctx, binding, offer)
		if err != nil || !reflect.DeepEqual(first, second) || check() != nil {
			return errPeer
		}
		return m.bus.check(ctx, true)
	})
	if err != nil || check() != nil || m.check(ctx) != nil {
		return fail()
	}
	return &IPv4Observation{snapshot: &second.snapshot}, nil
}

// Caller holds m.mu. Activation's captured binding/offer are copied while its
// own mutex is held; neither a caller-created Binding nor a settings UUID is
// promoted to manager/native provenance.
func (r *ActivationReceipt) ipv4ObservationInput(ctx context.Context, a *Activation) (Binding, Offer, error) {
	m := r.manager
	if ctx == nil || ctx.Err() != nil || !m.started || m.record.Phase != "correlated" || validateActivationRecord(m.record) != nil || a == nil || a != r.activation || a.plugin != m.plugin || a.ctx == nil || a.CheckLive(ctx) != nil || m.plugin.bus != m.bus || m.bus.plugin.Load() != m.plugin || m.plugin.published.Load() != 2 {
		return Binding{}, Offer{}, errPeer
	}
	p := m.plugin.plan
	if m.record.BootID != m.bootID || m.record.BusID != m.bus.pin.BusID || m.record.Owner != m.bus.pin.Owner || m.record.PluginOwner != m.bus.unique || m.record.UUID != p.UUID || m.record.Interface != p.Interface || m.record.Nonce != p.Nonce || a.Nonce() != m.record.Nonce || !equivalentProfiles(m.profile, a.profile, Identity{UUID: m.record.UUID, Interface: m.record.Interface}) {
		return Binding{}, Offer{}, errPeer
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.usedOK || a.binding == nil {
		return Binding{}, Offer{}, errPeer
	}
	b := *a.binding
	want := Binding{
		Identity: Identity{BootID: m.record.BootID, BusID: m.record.BusID, Owner: m.record.Owner, UUID: m.record.UUID, ActivePath: m.record.ActivePath, Interface: m.record.Interface, Session: b.Identity.Session},
		ConnectionPath: dbus.ObjectPath(m.record.ConnectionPath), PluginOwner: m.record.PluginOwner,
	}
	o := copyOffer(a.offer)
	// Encode reuses the closed shape validation only. This inferred allowlist
	// cannot grant policy approval; approval belongs to the original publisher.
	_, err := Encode(o, Policy{Addresses: []netip.Prefix{o.Address}, Endpoints: []netip.Addr{o.Endpoint}, Routes: o.Routes})
	if b != want || o.Session != b.Identity.Session || o.Interface != b.Identity.Interface || err != nil || a.CheckLive(ctx) != nil {
		return Binding{}, Offer{}, errPeer
	}
	return b, o, nil
}

type ipv4ObservationReadback struct {
	snapshot          IPv4ObservationSnapshot
	activeConnections []dbus.ObjectPath
}

func (m *ActivationManager) readIPv4Observation(ctx context.Context, binding Binding, offer Offer) (ipv4ObservationReadback, error) {
	var out ipv4ObservationReadback
	active := make(map[string]dbus.Variant, 12)
	for _, name := range []string{"Uuid", "Type", "Vpn", "Connection", "State", "Default", "Default6", "Devices", "Ip4Config", "Ip6Config", "Dhcp4Config", "Dhcp6Config"} {
		var value dbus.Variant
		if m.bus.call(ctx, m.record.Owner, dbus.ObjectPath(m.record.ActivePath), propertiesInterface+".Get", []any{ActiveInterface, name}, &value) != nil {
			return out, errPeer
		}
		active[name] = value
	}
	path, parents, err := parseIPv4Active(active, binding)
	if err != nil {
		return out, errPeer
	}
	// Modern and legacy fields are independently read and must agree. Legacy
	// routes alone omit defaults and non-main tables in the reviewed NM source.
	props := make(map[string]dbus.Variant, 14)
	for _, name := range []string{"AddressData", "Addresses", "Gateway", "RouteData", "Routes", "NameserverData", "Nameservers", "Domains", "Searches", "DnsOptions", "DnsPriority", "WinsServerData", "WinsServers"} {
		var value dbus.Variant
		if m.bus.call(ctx, m.record.Owner, path, propertiesInterface+".Get", []any{ipv4ConfigInterface, name}, &value) != nil {
			return out, errPeer
		}
		props[name] = value
	}
	snapshot, err := parseIPv4Projection(props, offer)
	if err != nil {
		return out, errPeer
	}
	snapshot.Binding, snapshot.IP4Config, snapshot.ParentDevices = binding, path, parents
	var current map[string]map[string]dbus.Variant
	if m.bus.call(ctx, m.record.Owner, dbus.ObjectPath(m.record.ConnectionPath), SettingsInterface+".GetSettings", nil, &current) != nil {
		return out, errPeer
	}
	network, password, err := incomingProfile(current, m.plugin.plan)
	if err != nil || password != "" || !equivalentProfiles(m.profile, network, binding.Identity) {
		return out, errPeer
	}
	var members dbus.Variant
	if m.bus.call(ctx, m.record.Owner, NMPath, propertiesInterface+".Get", []any{NMName, "ActiveConnections"}, &members) != nil {
		return out, errPeer
	}
	paths, err := hostObservationPaths(members, activePattern, hostMaxActiveConnections)
	if err != nil {
		return out, errPeer
	}
	present := false
	for _, p := range paths {
		present = present || string(p) == binding.Identity.ActivePath
	}
	if !present {
		return out, errPeer
	}
	return ipv4ObservationReadback{snapshot: snapshot, activeConnections: paths}, nil
}

func parseIPv4Active(p map[string]dbus.Variant, b Binding) (dbus.ObjectPath, []dbus.ObjectPath, error) {
	if len(p) != 12 {
		return "", nil, errPeer
	}
	for _, f := range []struct {
		name string
		want any
	}{
		{"Uuid", b.Identity.UUID}, {"Type", "vpn"}, {"Vpn", true}, {"Connection", b.ConnectionPath},
		{"State", uint32(2)}, {"Default", false}, {"Default6", false},
		{"Ip6Config", dbus.ObjectPath("/")}, {"Dhcp4Config", dbus.ObjectPath("/")}, {"Dhcp6Config", dbus.ObjectPath("/")},
	} {
		if !profileEqual(p[f.name], f.want) {
			return "", nil, errPeer
		}
	}
	path, ok := p["Ip4Config"].Value().(dbus.ObjectPath)
	if !ok || p["Ip4Config"].Signature().String() != "o" || len(path) > hostMaxObjectPath || !path.IsValid() || !ipv4ConfigPathPattern.MatchString(string(path)) {
		return "", nil, errPeer
	}
	parents, err := hostObservationPaths(p["Devices"], hostParentDevicePattern, hostMaxParentDevices)
	return path, parents, err
}

func parseIPv4Projection(p map[string]dbus.Variant, offer Offer) (IPv4ObservationSnapshot, error) {
	var out IPv4ObservationSnapshot
	if len(p) != 13 || !offer.Address.IsValid() || !offer.Address.Addr().Is4() || offer.Address.Bits() < 1 || len(offer.Routes) > 98 {
		return out, errPeer
	}
	for _, f := range []struct{ name, signature string }{
		{"NameserverData", "aa{sv}"}, {"Nameservers", "au"}, {"Domains", "as"}, {"Searches", "as"}, {"DnsOptions", "as"}, {"WinsServerData", "as"}, {"WinsServers", "au"},
	} {
		if !profileEmpty(p[f.name], f.signature) {
			return out, errPeer
		}
	}
	priority, ok := p["DnsPriority"].Value().(int32)
	if !ok || p["DnsPriority"].Signature().String() != "i" || !profileEqual(p["Gateway"], "") {
		return out, errPeer
	}
	addresses, ok := p["AddressData"].Value().([]map[string]dbus.Variant)
	if !ok || p["AddressData"].Signature().String() != "aa{sv}" || len(addresses) != 1 || len(addresses[0]) != 2 || !profileEqual(addresses[0]["address"], offer.Address.Addr().String()) || !profileEqual(addresses[0]["prefix"], uint32(offer.Address.Bits())) {
		return out, errPeer
	}
	// Prefix/metric are ordinary uint32 values. Only IP addresses use the
	// in_addr memory representation; D-Bus's message endianness is separate.
	if !profileEqual(p["Addresses"], [][]uint32{{nmIPv4(offer.Address.Addr()), uint32(offer.Address.Bits()), 0}}) {
		return out, errPeer
	}
	routes, ok := p["RouteData"].Value().([]map[string]dbus.Variant)
	if !ok || p["RouteData"].Signature().String() != "aa{sv}" || len(routes) >= 100 {
		return out, errPeer
	}
	legacy, ok := p["Routes"].Value().([][]uint32)
	if !ok || p["Routes"].Signature().String() != "aau" || len(legacy) != len(routes) {
		return out, errPeer
	}
	expected := make(map[netip.Prefix]bool, len(offer.Routes))
	for _, route := range offer.Routes {
		if !route.IsValid() || !route.Addr().Is4() || route.Bits() == 0 || route != route.Masked() || expected[route] || route.Contains(offer.Endpoint) {
			return out, errPeer
		}
		expected[route] = true
	}
	seen := make(map[netip.Prefix]bool, len(routes))
	observed := make([]IPv4ObservedRoute, 0, len(routes))
	for _, route := range routes {
		if len(route) != 3 && len(route) != 4 {
			return out, errPeer
		}
		for key := range route {
			if key != "dest" && key != "prefix" && key != "metric" && key != "table" {
				return out, errPeer
			}
		}
		if table, present := route["table"]; present && !profileEqual(table, uint32(254)) {
			return out, errPeer
		}
		destination, ok := route["dest"].Value().(string)
		bits, bitsOK := route["prefix"].Value().(uint32)
		metric, metricOK := route["metric"].Value().(uint32)
		if !ok || route["dest"].Signature().String() != "s" || len(destination) > 15 || !bitsOK || route["prefix"].Signature().String() != "u" || bits < 1 || bits > 32 || !metricOK || route["metric"].Signature().String() != "u" {
			return out, errPeer
		}
		address, err := netip.ParseAddr(destination)
		if err != nil || !address.Is4() || address.String() != destination {
			return out, errPeer
		}
		prefix := netip.PrefixFrom(address, int(bits))
		// A directly connected subnet may be added by NM/the kernel. It is
		// separately bounded to this exact address; never accept arbitrary extras.
		if prefix != prefix.Masked() || seen[prefix] || prefix.Contains(offer.Endpoint) || (!expected[prefix] && prefix != offer.Address.Masked()) {
			return out, errPeer
		}
		seen[prefix] = true
		observed = append(observed, IPv4ObservedRoute{Destination: prefix, Metric: metric})
	}
	for prefix := range expected {
		if !seen[prefix] {
			return out, errPeer
		}
	}
	// Compare sets, not server iteration order. Duplicates remain an error.
	legacySeen := make(map[netip.Prefix]bool, len(legacy))
	for _, tuple := range legacy {
		if len(tuple) != 4 || tuple[2] != 0 {
			return out, errPeer
		}
		matched := false
		for _, route := range observed {
			if tuple[0] == nmIPv4(route.Destination.Addr()) && tuple[1] == uint32(route.Destination.Bits()) && tuple[3] == route.Metric && !legacySeen[route.Destination] {
				legacySeen[route.Destination], matched = true, true
				break
			}
		}
		if !matched {
			return out, errPeer
		}
	}
	sort.Slice(observed, func(i, j int) bool { return observed[i].Destination.String() < observed[j].Destination.String() })
	out.Address, out.Routes, out.DNSPriority = offer.Address, observed, priority
	return out, nil
}
