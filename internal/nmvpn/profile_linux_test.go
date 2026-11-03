//go:build linux

package nmvpn

import (
	"reflect"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

func profileFixture() (map[string]map[string]dbus.Variant, Identity) {
	id := Identity{UUID: "12345678-1234-1234-1234-123456789abc", Interface: "meridian0"}
	return map[string]map[string]dbus.Variant{
		"connection": {"uuid": dbus.MakeVariant(id.UUID), "type": dbus.MakeVariant("vpn")},
		"vpn": {"service-type": dbus.MakeVariant(PluginService)},
		"ipv4": {"method": dbus.MakeVariant("auto"), "never-default": dbus.MakeVariant(true), "ignore-auto-dns": dbus.MakeVariant(true)},
		"ipv6": {"method": dbus.MakeVariant("disabled")},
	}, id
}

func TestValidateProfileMinimalAndImmutable(t *testing.T) {
	s, id := profileFixture()
	before, _ := profileFixture()
	if err := ValidateProfile(s, id); err != nil { t.Fatal(err) }
	if !reflect.DeepEqual(s, before) { t.Fatal("validator changed input") }
	for section, values := range before {
		for key := range values {
			x, id := profileFixture()
			delete(x[section], key)
			if ValidateProfile(x, id) == nil { t.Fatalf("accepted missing %s.%s", section, key) }
		}
	}
}

func TestValidateProfileApprovedEmptyAndDefaultTypes(t *testing.T) {
	s, id := profileFixture()
	for key, value := range map[string]interface{}{
		"id": "Work VPN", "timestamp": uint64(42), "read-only": true, "autoconnect": false,
		"interface-name": id.Interface, "permissions": []string{}, "secondaries": []string{},
		"zone": "", "controller": "", "master": "", "port-type": "", "slave-type": "",
		"multi-connect": int32(0), "autoconnect-priority": int32(0),
	} { s["connection"][key] = dbus.MakeVariant(value) }
	for key, value := range map[string]interface{}{
		"persistent": false, "timeout": uint32(0), "data": map[string]string{}, "secrets": map[string]string{},
	} { s["vpn"][key] = dbus.MakeVariant(value) }
	for _, family := range []string{"ipv4", "ipv6"} {
		for key, value := range map[string]interface{}{
			"ignore-auto-routes": false, "gateway": "", "route-table": uint32(0),
			"route-metric": int64(-1), "dns-priority": int32(0),
			"dns-data": []string{}, "dns-search": []string{}, "dns-options": []string{},
			"route-data": []map[string]dbus.Variant{}, "address-data": []map[string]dbus.Variant{}, "routing-rules": []map[string]dbus.Variant{},
		} { s[family][key] = dbus.MakeVariant(value) }
	}
	s["ipv4"]["dns"] = dbus.MakeVariant([]uint32{})
	s["ipv4"]["addresses"] = dbus.MakeVariant([][]uint32{})
	s["ipv4"]["routes"] = dbus.MakeVariant([][]uint32{})
	s["ipv6"]["dns"] = dbus.MakeVariant([][]byte{})
	s["ipv6"]["addresses"] = dbus.MakeVariant([]struct { Address []byte; Prefix uint32; Gateway []byte }{})
	s["ipv6"]["routes"] = dbus.MakeVariant([]struct { Address []byte; Prefix uint32; Gateway []byte; Metric uint32 }{})
	s["proxy"] = map[string]dbus.Variant{"method": dbus.MakeVariant(int32(0))}
	if err := ValidateProfile(s, id); err != nil { t.Fatal(err) }
	// Actual decoded D-Bus structs are represented by []interface{} in godbus.
	for key, signature := range map[string]string{"addresses": "a(ayuay)", "routes": "a(ayuayu)"} {
		s["ipv6"][key] = dbus.MakeVariantWithSignature([][]interface{}{}, dbus.ParseSignatureMust(signature))
	}
	if err := ValidateProfile(s, id); err != nil { t.Fatal(err) }
}

func TestValidateProfileRejectsChangesAndWrongTypes(t *testing.T) {
	cases := []struct { section, key string; value interface{} }{
		{"connection", "uuid", "12345678-1234-1234-1234-123456789abd"},
		{"connection", "type", "wireguard"}, {"connection", "interface-name", "other0"},
		{"connection", "id", strings.Repeat("x", 257)}, {"connection", "id", "bad\x00name"},
		{"connection", "id", "\xff"}, {"connection", "timestamp", int64(0)},
		{"connection", "permissions", []string{"user:other:"}}, {"connection", "secondaries", []string{"another-profile"}},
		{"connection", "zone", "trusted"}, {"connection", "multi-connect", int32(3)},
		{"connection", "stable-id", "dynamic"}, {"connection", "unknown", false},
		{"vpn", "service-type", "org.freedesktop.NetworkManager.other"},
		{"vpn", "persistent", true}, {"vpn", "persistent", uint32(0)},
		{"vpn", "data", map[string]string{"endpoint": "secret.invalid"}},
		{"vpn", "secrets", map[string]string{"password": "DO-NOT-LEAK"}},
		{"vpn", "data", map[string]dbus.Variant{}}, {"vpn", "timeout", int32(0)},
		{"vpn", "user-name", "user"},
		{"ipv4", "method", "manual"}, {"ipv4", "never-default", false},
		{"ipv4", "never-default", uint32(1)}, {"ipv4", "ignore-auto-dns", false},
		{"ipv4", "ignore-auto-routes", true}, {"ipv4", "gateway", "192.0.2.1"},
		{"ipv4", "route-table", uint32(123)}, {"ipv4", "route-table", int32(0)},
		{"ipv4", "route-metric", int64(0)}, {"ipv4", "dns-priority", int32(-1)},
		{"ipv4", "dns", []uint32{1}}, {"ipv4", "dns", []string{}},
		{"ipv4", "dns-data", []string{"192.0.2.1"}}, {"ipv4", "dns-data", []map[string]dbus.Variant{}},
		{"ipv4", "dns-search", []string{"~."}}, {"ipv4", "dns-options", []string{"rotate"}},
		{"ipv4", "routes", [][]uint32{{0, 0, 0, 0}}},
		{"ipv4", "addresses", [][]uint32{{1, 24, 0}}},
		{"ipv4", "route-data", []map[string]dbus.Variant{{"dest": dbus.MakeVariant("0.0.0.0")}}},
		{"ipv4", "address-data", []map[string]dbus.Variant{{}}},
		{"ipv4", "routing-rules", []map[string]dbus.Variant{{}}},
		{"ipv4", "replace-local-rule", int32(1)}, {"ipv4", "dhcp-client-id", "x"},
		{"ipv6", "method", "ignore"}, {"ipv6", "method", "auto"},
		{"ipv6", "dns", [][]byte{{1}}}, {"ipv6", "dns", []uint32{}},
		{"ipv6", "routes", [][]uint32{}}, {"ipv6", "gateway", "::1"},
		{"ipv6", "address-data", []map[string]dbus.Variant{{}}},
		{"ipv6", "route-data", []map[string]dbus.Variant{{}}},
		{"proxy", "method", int32(1)}, {"proxy", "method", uint32(0)},
		{"proxy", "pac-url", "https://secret.invalid"}, {"unknown", "method", false},
	}
	for _, tc := range cases {
		t.Run(tc.section+"/"+tc.key, func(t *testing.T) {
			s, id := profileFixture()
			if s[tc.section] == nil { s[tc.section] = map[string]dbus.Variant{} }
			s[tc.section][tc.key] = dbus.MakeVariant(tc.value)
			err := ValidateProfile(s, id)
			if err == nil { t.Fatal("accepted unsupported profile") }
			if err.Error() != "unsupported or unapproved NM VPN profile" { t.Fatal("non-generic error") }
			if !reflect.DeepEqual(s[tc.section][tc.key].Value(), tc.value) { t.Fatal("mutated rejected input") }
		})
	}
}

func TestValidateProfileRejectsMalformedVariantsAndIdentity(t *testing.T) {
	for _, v := range []dbus.Variant{
		{}, dbus.MakeVariantWithSignature("auto", dbus.ParseSignatureMust("u")),
		dbus.MakeVariantWithSignature(uint32(0), dbus.ParseSignatureMust("s")),
	} {
		s, id := profileFixture()
		s["ipv4"]["method"] = v
		if ValidateProfile(s, id) == nil { t.Fatal("accepted malformed variant") }
	}
	s, id := profileFixture()
	for _, badID := range []Identity{{}, {UUID: id.UUID, Interface: "lo"}, {UUID: id.UUID, Interface: "toolonginterfacename"}} {
		if ValidateProfile(s, badID) == nil { t.Fatal("accepted invalid identity") }
	}
	if ValidateProfile(nil, id) == nil { t.Fatal("accepted nil profile") }
	s["proxy"] = map[string]dbus.Variant{}
	if ValidateProfile(s, id) == nil { t.Fatal("accepted proxy without method") }
}

func TestValidateProfileBoundsAndEmptyTypeSpoofing(t *testing.T) {
	for _, extra := range []string{"802-3-ethernet", "user", "wireguard"} {
		s, id := profileFixture()
		s[extra] = map[string]dbus.Variant{}
		if ValidateProfile(s, id) == nil { t.Fatal("accepted unknown empty section") }
	}
	for _, test := range []struct { family, key, sig string; value interface{} }{
		{"ipv4", "dns", "au", []string{}},
		{"ipv4", "route-data", "aa{sv}", []string{}},
		{"ipv6", "routes", "a(ayuayu)", []uint32{}},
		{"ipv6", "routes", "a(ayuayu)", [][]interface{}{{}}},
		{"ipv6", "addresses", "a(ayuay)", []struct { A []byte; P int32; G []byte }{}},
	} {
		s, id := profileFixture()
		s[test.family][test.key] = dbus.MakeVariantWithSignature(test.value, dbus.ParseSignatureMust(test.sig))
		if ValidateProfile(s, id) == nil { t.Fatal("accepted spoofed or nonempty array") }
	}
	s, id := profileFixture()
	for i := 0; i < 33; i++ { s["connection"][strings.Repeat("x", i+1)] = dbus.MakeVariant(false) }
	if ValidateProfile(s, id) == nil { t.Fatal("accepted oversized dictionary") }
}
