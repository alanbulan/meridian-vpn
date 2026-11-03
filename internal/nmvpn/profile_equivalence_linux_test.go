//go:build linux

package nmvpn

import (
	"reflect"
	"testing"

	"github.com/godbus/dbus/v5"
)

type profileDefaultCase struct {
	section, key string
	value        interface{}
}

func equivalentProfileDefaults() []profileDefaultCase {
	cases := []profileDefaultCase{
		{"connection", "timestamp", uint64(123)},
		{"connection", "read-only", false},
		{"connection", "read-only", true},
		{"connection", "interface-name", ""},
		{"connection", "zone", ""},
		{"connection", "controller", ""},
		{"connection", "master", ""},
		{"connection", "port-type", ""},
		{"connection", "slave-type", ""},
		{"connection", "multi-connect", int32(0)},
		{"connection", "autoconnect-priority", int32(0)},
		{"connection", "permissions", []string{}},
		{"connection", "secondaries", []string{}},
		{"vpn", "persistent", false},
		{"vpn", "timeout", uint32(0)},
		{"vpn", "data", map[string]string{}},
		{"vpn", "secrets", map[string]string{}},
		{"ipv6", "never-default", false},
		{"ipv6", "ignore-auto-dns", false},
		{"ipv4", "dns", []uint32{}},
		{"ipv4", "addresses", [][]uint32{}},
		{"ipv4", "routes", [][]uint32{}},
		{"ipv6", "dns", [][]byte{}},
		{"ipv6", "addresses", []struct {
			Address []byte
			Prefix  uint32
			Gateway []byte
		}{}},
		{"ipv6", "routes", []struct {
			Address []byte
			Prefix  uint32
			Gateway []byte
			Metric  uint32
		}{}},
		{"proxy", "method", int32(0)},
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, property := range []profileDefaultCase{
			{family, "ignore-auto-routes", false},
			{family, "gateway", ""},
			{family, "route-table", uint32(0)},
			{family, "route-metric", int64(-1)},
			{family, "dns-priority", int32(0)},
			{family, "dns-data", []string{}},
			{family, "dns-search", []string{}},
			{family, "route-data", []map[string]dbus.Variant{}},
			{family, "address-data", []map[string]dbus.Variant{}},
			{family, "routing-rules", []map[string]dbus.Variant{}},
		} {
			cases = append(cases, property)
		}
	}
	return cases
}

func setProfileProperty(s map[string]map[string]dbus.Variant, section, key string, value dbus.Variant) {
	if s[section] == nil {
		s[section] = make(map[string]dbus.Variant)
	}
	s[section][key] = value
}

func TestEquivalentProfilesDefaults(t *testing.T) {
	base, id := profileFixture()
	combined, _ := profileFixture()
	for _, tc := range equivalentProfileDefaults() {
		t.Run(tc.section+"/"+tc.key, func(t *testing.T) {
			actual, _ := profileFixture()
			setProfileProperty(actual, tc.section, tc.key, dbus.MakeVariant(tc.value))
			before := cloneSafeProfile(actual)
			if !equivalentProfiles(base, actual, id) || !equivalentProfiles(actual, base, id) {
				t.Fatal("explicit default is not symmetrically equivalent")
			}
			if !reflect.DeepEqual(actual, before) {
				t.Fatal("comparison mutated input")
			}
			canonical := canonicalValidatedProfile(actual)
			if !reflect.DeepEqual(canonical, canonicalValidatedProfile(canonical)) || !reflect.DeepEqual(canonical, base) {
				t.Fatal("canonical form is not minimal and idempotent")
			}
		})
		setProfileProperty(combined, tc.section, tc.key, dbus.MakeVariant(tc.value))
	}
	middle, _ := profileFixture()
	middle["vpn"]["timeout"] = dbus.MakeVariant(uint32(0))
	for _, a := range []map[string]map[string]dbus.Variant{base, middle, combined} {
		for _, b := range []map[string]map[string]dbus.Variant{base, middle, combined} {
			if !equivalentProfiles(a, b, id) {
				t.Fatal("combined defaults violate reflexivity, symmetry or transitivity")
			}
		}
	}
	if !reflect.DeepEqual(canonicalValidatedProfile(combined), base) {
		t.Fatal("combined canonical form differs")
	}
}

func TestEquivalentProfilesRejectsDefaultsWithWrongTypesAndSignatures(t *testing.T) {
	base, id := profileFixture()
	for _, tc := range equivalentProfileDefaults() {
		t.Run(tc.section+"/"+tc.key, func(t *testing.T) {
			for _, bad := range []dbus.Variant{
				{},
				dbus.MakeVariantWithSignature(tc.value, dbus.ParseSignatureMust("v")),
				dbus.MakeVariantWithSignature(int16(0), dbus.SignatureOf(tc.value)),
			} {
				actual, _ := profileFixture()
				setProfileProperty(actual, tc.section, tc.key, bad)
				if equivalentProfiles(base, actual, id) || equivalentProfiles(actual, base, id) || equivalentProfiles(actual, actual, id) {
					t.Fatal("invalid input became equivalent before validation")
				}
			}
		})
	}
}

func TestEquivalentProfilesRejectsNondefaults(t *testing.T) {
	base, id := profileFixture()
	for _, tc := range equivalentProfileDefaults() {
		if tc.section == "connection" && (tc.key == "timestamp" || tc.key == "read-only") {
			continue // These are ignored bookkeeping, not default-only fields.
		}
		t.Run(tc.section+"/"+tc.key, func(t *testing.T) {
			value := reflect.ValueOf(tc.value)
			changed := reflect.New(value.Type()).Elem()
			switch value.Kind() {
			case reflect.Bool:
				changed.SetBool(!value.Bool())
			case reflect.String:
				changed.SetString("nondefault")
			case reflect.Int32, reflect.Int64:
				changed.SetInt(value.Int() + 1)
			case reflect.Uint32:
				changed.SetUint(value.Uint() + 1)
			case reflect.Slice:
				changed.Set(reflect.MakeSlice(value.Type(), 1, 1))
			case reflect.Map:
				changed.Set(reflect.MakeMap(value.Type()))
				changed.SetMapIndex(reflect.ValueOf("unexpected"), reflect.ValueOf("value"))
			default:
				t.Fatalf("untested default type: %s", value.Type())
			}
			a, _ := profileFixture()
			setProfileProperty(a, tc.section, tc.key, dbus.MakeVariant(changed.Interface()))
			if equivalentProfiles(base, a, id) || equivalentProfiles(a, base, id) {
				t.Fatal("nondefault value collapsed into absence")
			}
		})
	}
}

func TestEquivalentProfilesPreservesMeaningfulProperties(t *testing.T) {
	base, id := profileFixture()
	for _, tc := range []profileDefaultCase{
		{"connection", "id", "Work VPN"},
		{"connection", "id", ""},
		{"connection", "interface-name", id.Interface},
		{"connection", "autoconnect", false},
		{"connection", "autoconnect", true},
		{"ipv6", "never-default", true},
		{"ipv6", "ignore-auto-dns", true},
		{"ipv4", "dns-options", []string{}},
		{"ipv6", "dns-options", []string{}},
	} {
		t.Run(tc.section+"/"+tc.key, func(t *testing.T) {
			actual, _ := profileFixture()
			setProfileProperty(actual, tc.section, tc.key, dbus.MakeVariant(tc.value))
			if ValidateProfile(actual, id) != nil || !equivalentProfiles(actual, actual, id) {
				t.Fatal("valid nondefault does not match itself")
			}
			if equivalentProfiles(base, actual, id) || equivalentProfiles(actual, base, id) {
				t.Fatal("meaningful property collapsed into absence")
			}
		})
	}
	for _, key := range []string{"never-default", "ignore-auto-dns"} {
		a, _ := profileFixture()
		b, _ := profileFixture()
		a["ipv6"][key] = dbus.MakeVariant(false)
		b["ipv6"][key] = dbus.MakeVariant(true)
		if equivalentProfiles(a, b, id) || equivalentProfiles(b, a, id) {
			t.Fatal("IPv6 false and true conflated")
		}
	}
	a, _ := profileFixture()
	b, _ := profileFixture()
	a["connection"]["autoconnect"] = dbus.MakeVariant(false)
	b["connection"]["autoconnect"] = dbus.MakeVariant(true)
	if equivalentProfiles(a, b, id) || equivalentProfiles(b, a, id) {
		t.Fatal("autoconnect change accepted")
	}
	a["connection"]["interface-name"] = dbus.MakeVariant("")
	b["connection"]["autoconnect"] = dbus.MakeVariant(false)
	b["connection"]["interface-name"] = dbus.MakeVariant(id.Interface)
	if equivalentProfiles(a, b, id) || equivalentProfiles(b, a, id) {
		t.Fatal("bound interface conflated with unbound")
	}
}

func TestEquivalentProfilesEmptyRepresentations(t *testing.T) {
	base, id := profileFixture()
	for _, family := range []string{"ipv4", "ipv6"} {
		a, _ := profileFixture()
		b, _ := profileFixture()
		a[family]["dns-options"] = dbus.MakeVariant([]string(nil))
		b[family]["dns-options"] = dbus.MakeVariant([]string{})
		if !equivalentProfiles(a, b, id) || !equivalentProfiles(b, a, id) {
			t.Fatal("present nil/empty dns-options differ")
		}
		if equivalentProfiles(a, base, id) || equivalentProfiles(base, a, id) {
			t.Fatal("present nil dns-options collapsed into absence")
		}
		if a[family]["dns-options"].Value().([]string) != nil {
			t.Fatal("comparison changed nil input slice")
		}
	}
	for _, tc := range equivalentProfileDefaults() {
		value := reflect.ValueOf(tc.value)
		if value.Kind() != reflect.Map && value.Kind() != reflect.Slice {
			continue
		}
		a, _ := profileFixture()
		setProfileProperty(a, tc.section, tc.key, dbus.MakeVariant(reflect.Zero(value.Type()).Interface()))
		if !equivalentProfiles(base, a, id) || !equivalentProfiles(a, base, id) {
			t.Fatalf("typed nil default differs: %s.%s", tc.section, tc.key)
		}
		if !reflect.ValueOf(a[tc.section][tc.key].Value()).IsNil() {
			t.Fatal("comparison changed nil input container")
		}
	}
	for key, signature := range map[string]string{"addresses": "a(ayuay)", "routes": "a(ayuayu)"} {
		for _, decoded := range [][][]interface{}{nil, {}} {
			a, _ := profileFixture()
			a["ipv6"][key] = dbus.MakeVariantWithSignature(decoded, dbus.ParseSignatureMust(signature))
			if !equivalentProfiles(base, a, id) || !equivalentProfiles(a, base, id) {
				t.Fatal("decoded empty legacy IPv6 array differs")
			}
			for _, wrong := range []string{"aau", "a(ayuay)", "a(ayuayu)"} {
				if wrong == signature {
					continue
				}
				a["ipv6"][key] = dbus.MakeVariantWithSignature(decoded, dbus.ParseSignatureMust(wrong))
				if equivalentProfiles(base, a, id) || equivalentProfiles(a, base, id) {
					t.Fatal("legacy IPv6 array wrong signature accepted")
				}
			}
		}
	}
	for _, proxy := range []map[string]dbus.Variant{nil, {}, {"method": dbus.MakeVariant(int32(0))}} {
		a, _ := profileFixture()
		a["proxy"] = proxy
		if !equivalentProfiles(a, base, id) || !equivalentProfiles(base, a, id) {
			t.Fatal("empty/default proxy differs")
		}
	}
}

func TestEquivalentProfilesRejectsUnsafeInputs(t *testing.T) {
	base, id := profileFixture()
	for _, tc := range []profileDefaultCase{
		{"connection", "zone", "trusted"},
		{"connection", "multi-connect", int32(1)},
		{"connection", "autoconnect-priority", int32(1)},
		{"connection", "permissions", []string{"user:other:"}},
		{"connection", "secondaries", []string{"other"}},
		{"vpn", "persistent", true},
		{"vpn", "timeout", uint32(1)},
		{"vpn", "data", map[string]string{"unexpected": "value"}},
		{"vpn", "secrets", map[string]string{"password": "value"}},
		{"ipv4", "route-table", uint32(1)},
		{"ipv4", "route-metric", int64(0)},
		{"ipv4", "dns-priority", int32(1)},
		{"ipv4", "ignore-auto-routes", true},
		{"ipv4", "gateway", "192.0.2.1"},
		{"ipv4", "dns", []uint32{1}},
		{"ipv4", "routes", [][]uint32{{1}}},
		{"ipv4", "addresses", [][]uint32{{1}}},
		{"ipv6", "dns", [][]byte{{1}}},
		{"ipv6", "routes", [][]interface{}{{[]byte{}, uint32(0), []byte{}, uint32(0)}}},
		{"ipv6", "dns-options", []string{"rotate"}},
		{"ipv4", "route-data", []map[string]dbus.Variant{{}}},
		{"ipv6", "address-data", []map[string]dbus.Variant{{}}},
		{"ipv4", "routing-rules", []map[string]dbus.Variant{{}}},
		{"proxy", "method", int32(1)},
		{"proxy", "unexpected", false},
		{"connection", "unexpected", []string{}},
		{"unknown", "method", false},
	} {
		t.Run(tc.section+"/"+tc.key, func(t *testing.T) {
			a, _ := profileFixture()
			// The decoded legacy tuple needs its actual D-Bus signature.
			v := dbus.MakeVariant(tc.value)
			if tc.section == "ipv6" && tc.key == "routes" {
				v = dbus.MakeVariantWithSignature(tc.value, dbus.ParseSignatureMust("a(ayuayu)"))
			}
			setProfileProperty(a, tc.section, tc.key, v)
			if equivalentProfiles(base, a, id) || equivalentProfiles(a, base, id) || equivalentProfiles(a, a, id) {
				t.Fatal("unsafe input accepted or erased")
			}
			if !reflect.DeepEqual(a[tc.section][tc.key].Value(), tc.value) {
				t.Fatal("rejected input mutated")
			}
		})
	}
	for _, a := range []map[string]map[string]dbus.Variant{nil, {}, {"connection": nil}} {
		if equivalentProfiles(base, a, id) || equivalentProfiles(a, base, id) || equivalentProfiles(a, a, id) {
			t.Fatal("nil or incomplete profile accepted")
		}
	}
	a, _ := profileFixture()
	a["unknown"] = nil
	if equivalentProfiles(base, a, id) || equivalentProfiles(a, base, id) {
		t.Fatal("unknown nil section accepted")
	}
	for _, bad := range []dbus.Variant{
		dbus.MakeVariantWithSignature(nil, dbus.ParseSignatureMust("as")),
		dbus.MakeVariantWithSignature(map[string]string(nil), dbus.ParseSignatureMust("as")),
		dbus.MakeVariantWithSignature([]interface{}(nil), dbus.ParseSignatureMust("as")),
	} {
		a, _ := profileFixture()
		a["connection"]["permissions"] = bad
		if equivalentProfiles(base, a, id) || equivalentProfiles(a, base, id) {
			t.Fatal("unsafe nil or spoofed container accepted")
		}
	}
}

func TestCanonicalValidatedProfilePreservesUnlistedValues(t *testing.T) {
	// Deliberately bypass validation to guard future grammar extensions. These
	// values are not currently accepted, but normalization must never erase them.
	input, _ := profileFixture()
	makeValues := func() []dbus.Variant {
		return []dbus.Variant{
			dbus.MakeVariant([]string{"retain"}),
			dbus.MakeVariant(map[string]string{"retain": "value"}),
			dbus.MakeVariant([]map[string]dbus.Variant{{"retain": dbus.MakeVariant(true)}}),
			dbus.MakeVariantWithSignature([][]interface{}{{[]byte{1}, uint32(64), []byte{2}}}, dbus.ParseSignatureMust("a(ayuay)")),
		}
	}
	original := makeValues()
	for i, value := range makeValues() {
		input["ipv4"]["future-property"] = value
		out := canonicalValidatedProfile(input)
		if !reflect.DeepEqual(out["ipv4"]["future-property"], original[i]) || !reflect.DeepEqual(input["ipv4"]["future-property"], original[i]) {
			t.Fatal("unlisted retained value or signature changed")
		}
		delete(out["ipv4"], "future-property")
		if !reflect.DeepEqual(input["ipv4"]["future-property"], original[i]) {
			t.Fatal("canonicalization retained input property map")
		}
	}
}
