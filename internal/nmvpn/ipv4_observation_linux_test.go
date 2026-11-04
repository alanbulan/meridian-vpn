//go:build linux

package nmvpn

import (
	"context"
	"encoding/binary"
	"math/bits"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

// Source-derived NM 1.52.1 shape, not a live-daemon capture. The serializer
// includes metric, omits table for main, and omits a zero next-hop. Legacy
// addresses/next-hops preserve in_addr bytes; prefix/metric are ordinary uint32.
func ipv4ProjectionFixture() (Offer, map[string]dbus.Variant) {
	o, _ := configFixture()
	routes := []map[string]dbus.Variant{}
	legacy := [][]uint32{}
	for _, p := range append(append([]netip.Prefix{}, o.Routes...), o.Address.Masked()) {
		routes = append(routes, map[string]dbus.Variant{"dest": dbus.MakeVariant(p.Addr().String()), "prefix": dbus.MakeVariant(uint32(p.Bits())), "metric": dbus.MakeVariant(uint32(50))})
		legacy = append(legacy, []uint32{nmIPv4(p.Addr()), uint32(p.Bits()), 0, 50})
	}
	return o, map[string]dbus.Variant{
		"AddressData": dbus.MakeVariant([]map[string]dbus.Variant{{"address": dbus.MakeVariant(o.Address.Addr().String()), "prefix": dbus.MakeVariant(uint32(o.Address.Bits()))}}),
		"Addresses":   dbus.MakeVariant([][]uint32{{nmIPv4(o.Address.Addr()), uint32(o.Address.Bits()), 0}}),
		"Gateway":     dbus.MakeVariant(""), "RouteData": dbus.MakeVariant(routes), "Routes": dbus.MakeVariant(legacy),
		"NameserverData": dbus.MakeVariant([]map[string]dbus.Variant{}), "Nameservers": dbus.MakeVariant([]uint32{}),
		"Domains": dbus.MakeVariant([]string{}), "Searches": dbus.MakeVariant([]string{}), "DnsOptions": dbus.MakeVariant([]string{}),
		"DnsPriority": dbus.MakeVariant(int32(50)), "WinsServerData": dbus.MakeVariant([]string{}), "WinsServers": dbus.MakeVariant([]uint32{}),
	}
}

func ipv4ActiveFixture() (Binding, map[string]dbus.Variant) {
	record, p := hostObservationFixture()
	p["State"] = dbus.MakeVariant(uint32(2))
	p["Ip4Config"] = dbus.MakeVariant(dbus.ObjectPath("/org/freedesktop/NetworkManager/IP4Config/7"))
	p["Dhcp4Config"], p["Dhcp6Config"] = dbus.MakeVariant(dbus.ObjectPath("/")), dbus.MakeVariant(dbus.ObjectPath("/"))
	return Binding{Identity: Identity{UUID: record.UUID}, ConnectionPath: dbus.ObjectPath(record.ConnectionPath)}, p
}

func TestIPv4ObservationProjectionAndCopies(t *testing.T) {
	o, p := ipv4ProjectionFixture()
	s, err := parseIPv4Projection(p, o)
	if err != nil || s.Address != o.Address || len(s.Routes) != 2 || s.DNSPriority != 50 {
		t.Fatal("valid source-derived projection rejected", err)
	}
	s.ParentDevices = []dbus.ObjectPath{"/org/freedesktop/NetworkManager/Devices/1"}
	observation := &IPv4Observation{snapshot: &s}
	first, err := observation.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	first.Routes[0].Metric = 999
	first.ParentDevices[0] = "/replacement"
	second, err := observation.Snapshot()
	if err != nil || second.Routes[0].Metric != 50 || second.ParentDevices[0] != s.ParentDevices[0] {
		t.Fatal("mutable historical data escaped")
	}
	for _, empty := range []*IPv4Observation{nil, {}} {
		if _, err := empty.Snapshot(); err == nil {
			t.Fatal("empty observation accepted")
		}
	}
	for _, empty := range []*ActivationReceipt{nil, {}, {manager: &ActivationManager{}}} {
		if _, err := empty.ObserveIPv4(context.Background(), nil); err == nil {
			t.Fatal("empty receipt accepted")
		}
	}
	// Independent ordering is irrelevant; explicit main-table annotation is
	// equivalent in this projection, but is not a grant of global policy approval.
	legacy := p["Routes"].Value().([][]uint32)
	legacy[0], legacy[1] = legacy[1], legacy[0]
	p["RouteData"].Value().([]map[string]dbus.Variant)[0]["table"] = dbus.MakeVariant(uint32(254))
	if got, err := parseIPv4Projection(p, o); err != nil || !reflect.DeepEqual(got.Routes, s.Routes) {
		t.Fatal("valid ordering/main-table equivalence rejected")
	}
	// The connected prefix is optional, not an invented mandatory VPN route.
	o, p = ipv4ProjectionFixture()
	p["RouteData"] = dbus.MakeVariant(p["RouteData"].Value().([]map[string]dbus.Variant)[:1])
	p["Routes"] = dbus.MakeVariant(p["Routes"].Value().([][]uint32)[:1])
	if _, err := parseIPv4Projection(p, o); err != nil {
		t.Fatal("projection without automatic connected route rejected")
	}
}

func TestIPv4ObservationRejectsMissingAndUnsupportedProjection(t *testing.T) {
	_, fields := ipv4ProjectionFixture()
	for name := range fields {
		t.Run("missing-"+name, func(t *testing.T) {
			o, p := ipv4ProjectionFixture()
			delete(p, name)
			if _, err := parseIPv4Projection(p, o); err == nil {
				t.Fatal("missing field accepted")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(map[string]dbus.Variant)
	}{
		{"extra-field", func(p map[string]dbus.Variant) { p["Unknown"] = dbus.MakeVariant(true) }},
		{"address-type", func(p map[string]dbus.Variant) { p["AddressData"] = dbus.MakeVariant([]string{}) }},
		{"address-missing", func(p map[string]dbus.Variant) { p["AddressData"] = dbus.MakeVariant([]map[string]dbus.Variant{}) }},
		{"address-extra", func(p map[string]dbus.Variant) {
			p["AddressData"].Value().([]map[string]dbus.Variant)[0]["label"] = dbus.MakeVariant("meridian0")
		}},
		{"address-peer", func(p map[string]dbus.Variant) {
			p["AddressData"].Value().([]map[string]dbus.Variant)[0]["peer"] = dbus.MakeVariant("10.20.30.8")
		}},
		{"address-value", func(p map[string]dbus.Variant) {
			p["AddressData"].Value().([]map[string]dbus.Variant)[0]["address"] = dbus.MakeVariant("10.20.30.8")
		}},
		{"address-prefix", func(p map[string]dbus.Variant) {
			p["AddressData"].Value().([]map[string]dbus.Variant)[0]["prefix"] = dbus.MakeVariant(int32(24))
		}},
		{"legacy-address", func(p map[string]dbus.Variant) { p["Addresses"].Value().([][]uint32)[0][0]++ }},
		{"legacy-address-prefix", func(p map[string]dbus.Variant) { p["Addresses"].Value().([][]uint32)[0][1] = bits.ReverseBytes32(24) }},
		{"gateway", func(p map[string]dbus.Variant) { p["Gateway"] = dbus.MakeVariant("10.20.30.1") }},
		{"dns", func(p map[string]dbus.Variant) {
			p["NameserverData"] = dbus.MakeVariant([]map[string]dbus.Variant{{"address": dbus.MakeVariant("10.0.0.53")}})
		}},
		{"legacy-dns", func(p map[string]dbus.Variant) { p["Nameservers"] = dbus.MakeVariant([]uint32{1}) }},
		{"dns-priority-type", func(p map[string]dbus.Variant) { p["DnsPriority"] = dbus.MakeVariant(uint32(50)) }},
		{"domains", func(p map[string]dbus.Variant) { p["Domains"] = dbus.MakeVariant([]string{"corp.example"}) }},
		{"searches", func(p map[string]dbus.Variant) { p["Searches"] = dbus.MakeVariant([]string{"corp.example"}) }},
		{"dns-options", func(p map[string]dbus.Variant) { p["DnsOptions"] = dbus.MakeVariant([]string{"rotate"}) }},
		{"wins", func(p map[string]dbus.Variant) { p["WinsServerData"] = dbus.MakeVariant([]string{"10.0.0.54"}) }},
		{"legacy-wins", func(p map[string]dbus.Variant) { p["WinsServers"] = dbus.MakeVariant([]uint32{1}) }},
		{"route-type", func(p map[string]dbus.Variant) { p["RouteData"] = dbus.MakeVariant([]string{}) }},
		{"route-missing", func(p map[string]dbus.Variant) {
			p["RouteData"] = dbus.MakeVariant([]map[string]dbus.Variant{})
			p["Routes"] = dbus.MakeVariant([][]uint32{})
		}},
		{"route-duplicate", func(p map[string]dbus.Variant) { r := p["RouteData"].Value().([]map[string]dbus.Variant); r[1] = r[0] }},
		{"legacy-missing", func(p map[string]dbus.Variant) { p["Routes"] = dbus.MakeVariant([][]uint32{}) }},
		{"legacy-duplicate", func(p map[string]dbus.Variant) { r := p["Routes"].Value().([][]uint32); r[1] = r[0] }},
		{"legacy-shape", func(p map[string]dbus.Variant) { p["Routes"].Value().([][]uint32)[0] = []uint32{1, 2, 3} }},
		{"legacy-hop", func(p map[string]dbus.Variant) { p["Routes"].Value().([][]uint32)[0][2] = 1 }},
		{"legacy-metric", func(p map[string]dbus.Variant) { p["Routes"].Value().([][]uint32)[0][3] = 51 }},
		{"legacy-endian", func(p map[string]dbus.Variant) {
			r := p["Routes"].Value().([][]uint32)[0]
			r[0] = bits.ReverseBytes32(r[0])
		}},
		{"route-limit", func(p map[string]dbus.Variant) {
			p["RouteData"] = dbus.MakeVariant(make([]map[string]dbus.Variant, 100))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, p := ipv4ProjectionFixture()
			tc.change(p)
			if _, err := parseIPv4Projection(p, o); err == nil {
				t.Fatal("unsupported projection accepted")
			}
		})
	}
}

func TestIPv4ObservationRejectsRouteAttributes(t *testing.T) {
	for _, tc := range []struct {
		name, key string
		value     any
	}{
		{"unknown", "type", "unicast"}, {"hop", "next-hop", "10.20.30.1"}, {"zero-hop", "next-hop", "0.0.0.0"},
		{"other-table", "table", uint32(100)}, {"table-type", "table", int32(254)},
		{"missing-metric", "metric", nil}, {"metric-type", "metric", int32(50)},
		{"default", "prefix", uint32(0)}, {"long-prefix", "prefix", uint32(33)}, {"prefix-type", "prefix", int32(16)},
		{"changed-route", "dest", "10.51.0.0"}, {"host-bits", "dest", "10.50.0.1"}, {"v6", "dest", "::"},
		{"long", "dest", strings.Repeat("1", 256)}, {"text-type", "dest", uint32(1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, p := ipv4ProjectionFixture()
			route := p["RouteData"].Value().([]map[string]dbus.Variant)[0]
			if tc.value == nil {
				delete(route, tc.key)
			} else {
				route[tc.key] = dbus.MakeVariant(tc.value)
			}
			if _, err := parseIPv4Projection(p, o); err == nil {
				t.Fatal("unsupported route attribute accepted")
			}
		})
	}
}

func TestIPv4ObservationActiveIdentity(t *testing.T) {
	b, p := ipv4ActiveFixture()
	if path, parents, err := parseIPv4Active(p, b); err != nil || path != "/org/freedesktop/NetworkManager/IP4Config/7" || len(parents) != 2 {
		t.Fatal("valid activated identity rejected")
	}
	for key := range p {
		t.Run("missing-"+key, func(t *testing.T) {
			b, p := ipv4ActiveFixture()
			delete(p, key)
			if _, _, err := parseIPv4Active(p, b); err == nil {
				t.Fatal("missing field accepted")
			}
		})
	}
	for _, tc := range []struct {
		name, key string
		value     any
	}{
		{"activating", "State", uint32(1)}, {"state-type", "State", int32(2)}, {"default", "Default", true}, {"default6", "Default6", true},
		{"no-ipv4", "Ip4Config", dbus.ObjectPath("/")}, {"foreign-config", "Ip4Config", dbus.ObjectPath("/org/freedesktop/NetworkManager/IP6Config/7")},
		{"path-type", "Ip4Config", "/org/freedesktop/NetworkManager/IP4Config/7"}, {"long-path", "Ip4Config", dbus.ObjectPath("/org/freedesktop/NetworkManager/IP4Config/" + strings.Repeat("1", 129))},
		{"ipv6", "Ip6Config", dbus.ObjectPath("/org/freedesktop/NetworkManager/IP6Config/1")}, {"dhcp4", "Dhcp4Config", dbus.ObjectPath("/org/freedesktop/NetworkManager/DHCP4Config/1")},
		{"dhcp6", "Dhcp6Config", dbus.ObjectPath("/org/freedesktop/NetworkManager/DHCP6Config/1")}, {"uuid", "Uuid", "different"}, {"type", "Type", "ethernet"}, {"vpn", "Vpn", false},
		{"connection", "Connection", dbus.ObjectPath("/org/freedesktop/NetworkManager/Settings/2")}, {"parents", "Devices", []dbus.ObjectPath{"/"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, p := ipv4ActiveFixture()
			p[tc.key] = dbus.MakeVariant(tc.value)
			if _, _, err := parseIPv4Active(p, b); err == nil {
				t.Fatal("unsupported active identity accepted")
			}
		})
	}
}

func TestIPv4ObservationLegacyByteOrder(t *testing.T) {
	o, p := ipv4ProjectionFixture()
	bytes := o.Address.Addr().As4()
	if got := p["Addresses"].Value().([][]uint32)[0]; got[0] != binary.NativeEndian.Uint32(bytes[:]) || got[1] != 24 || got[2] != 0 {
		t.Fatal("legacy fixture byte-order mismatch")
	}
	if _, err := parseIPv4Projection(p, o); err != nil {
		t.Fatal(err)
	}
}

func TestIPv4ObservationRouteProjectionLimit(t *testing.T) {
	for _, count := range []int{98, 99} {
		o, p := ipv4ProjectionFixture()
		o.Routes = nil
		routes := []map[string]dbus.Variant{}
		legacy := [][]uint32{}
		for i := 0; i < count; i++ {
			prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 100, byte(i), 0}), 24)
			o.Routes = append(o.Routes, prefix)
		}
		for _, prefix := range append(append([]netip.Prefix{}, o.Routes...), o.Address.Masked()) {
			routes = append(routes, map[string]dbus.Variant{"dest": dbus.MakeVariant(prefix.Addr().String()), "prefix": dbus.MakeVariant(uint32(prefix.Bits())), "metric": dbus.MakeVariant(uint32(50))})
			legacy = append(legacy, []uint32{nmIPv4(prefix.Addr()), uint32(prefix.Bits()), 0, 50})
		}
		p["RouteData"], p["Routes"] = dbus.MakeVariant(routes), dbus.MakeVariant(legacy)
		_, err := parseIPv4Projection(p, o)
		if (count == 98 && err != nil) || (count == 99 && err == nil) {
			t.Fatal("route export boundary not enforced", count, err)
		}
	}
}
