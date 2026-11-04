package macosvpn

import (
	"reflect"
	"strings"
	"testing"
)

// Entirely synthetic CoreFoundation values; no framework/profile/credential read.
func inspectionAPIFixture(t *testing.T) (*nativeConnection, map[uintptr]string, *[]uintptr) {
	n, text, released := evidenceFixture(t)
	a := n.a
	for id, s := range map[uintptr]string{63: "PPP", 64: "L2TP", 65: "vpn.example.com", 66: "MSCHAP2", 67: "SharedSecret"} {
		text[id] = s
	}
	oldType := a.typeID
	a.typeID = func(v uintptr) uintptr {
		switch v {
		case 60, 61, 71:
			return a.dictionaryTypeID()
		case 62:
			return a.arrayTypeID()
		case 72:
			return 14
		}
		return oldType(v)
	}
	oldValue := a.dictionaryValue
	a.dictionaryValue = func(dict, key uintptr) uintptr {
		k := text[key]
		// Explicitly forbid credential or unbounded dictionary enumeration. No raw
		// dictionary is exported and no other field may be requested by this fixture.
		switch dict {
		case 60:
			switch k {
			case "CommRemoteAddress":
				return 65
			case "AuthProtocol":
				return 62
			}
			t.Fatalf("unapproved PPP field: %s", k)
		case 61:
			if k == "AuthenticationMethod" {
				return 67
			}
			t.Fatalf("unapproved IPsec field: %s", k)
		case 2:
			if k == "PPP" {
				return 71
			}
		case 71:
			if k == "ConnectTime" {
				return 72
			}
			t.Fatalf("unapproved generation field: %s", k)
		}
		return oldValue(dict, key)
	}
	oldCount := a.arrayCount
	a.arrayCount = func(v uintptr) int {
		if v == 62 {
			return 1
		}
		return oldCount(v)
	}
	oldArray := a.arrayValue
	a.arrayValue = func(v uintptr, i int) uintptr {
		if v == 62 {
			if i != 0 {
				t.Fatal("unbounded auth array")
			}
			return 66
		}
		return oldArray(v, i)
	}
	a.preferencesCreate = func(alloc, name, prefs uintptr) uintptr {
		if alloc != 0 || prefs != 0 || text[name] != "Meridian read-only service configuration" {
			t.Fatal("preferences parameters")
		}
		return 80
	}
	a.serviceCopy = func(prefs, id uintptr) uintptr {
		if prefs != 80 || text[id] != "service-id" {
			t.Fatal("wrong selected service")
		}
		return 90
	}
	a.serviceEnabled = func(service uintptr) uint8 {
		if service != 90 {
			t.Fatal("wrong service")
		}
		return 1
	}
	a.serviceInterface = func(service uintptr) uintptr {
		if service != 90 {
			t.Fatal("wrong service")
		}
		return 30
	}
	a.interfaceType = func(iface uintptr) uintptr {
		switch iface {
		case 30:
			return 63
		case 40:
			return 64
		}
		t.Fatal("wrong interface")
		return 0
	}
	a.lowerInterface = func(iface uintptr) uintptr {
		if iface != 30 {
			t.Fatal("wrong parent interface")
		}
		return 40
	}
	a.interfaceConfiguration = func(iface uintptr) uintptr {
		if iface != 30 {
			t.Fatal("wrong PPP interface")
		}
		return 60
	}
	a.interfaceExtendedConfiguration = func(iface, key uintptr) uintptr {
		if iface != 30 || text[key] != "IPSec" {
			t.Fatal("wrong extended configuration")
		}
		return 61
	}
	a.numberTypeID = func() uintptr { return 14 }
	a.numberIsFloatType = func(v uintptr) uint8 {
		if v != 72 {
			t.Fatal("number type check")
		}
		return 0
	}
	a.numberGetValue = func(v uintptr, kind int, out *int64) uint8 {
		if v != 72 || kind != 4 {
			t.Fatal("CFNumber ABI")
		}
		*out = 123
		return 1
	}
	a.start = func(uintptr, uintptr, uint8) uint8 { t.Fatal("inspection attempted start"); return 0 }
	a.stop = func(uintptr, uint8) uint8 { t.Fatal("inspection attempted stop"); return 0 }
	return n, text, released
}
func trackInspectionOwnership(a *nativeAPI) map[uintptr]int {
	owned := trackEvidenceOwnership(a)
	oldPrefs := a.preferencesCreate
	a.preferencesCreate = func(x, y, z uintptr) uintptr {
		v := oldPrefs(x, y, z)
		if v != 0 {
			owned[v]++
		}
		return v
	}
	oldService := a.serviceCopy
	a.serviceCopy = func(x, y uintptr) uintptr {
		v := oldService(x, y)
		if v != 0 {
			owned[v]++
		}
		return v
	}
	return owned
}
func TestNativeServiceInspectionAllowlistAndOwnership(t *testing.T) {
	n, _, released := inspectionAPIFixture(t)
	owned := trackInspectionOwnership(n.a)
	out, err := n.readConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, diagnosticConfig()) {
		t.Fatalf("unexpected summary: %+v", out)
	}
	generation, err := n.readConnectTime()
	if err != nil || generation != 123 {
		t.Fatalf("generation: %d %v", generation, err)
	}
	assertBalancedCF(t, owned, *released)
}
func TestNativeInspectionFailuresReleaseOwnedReferences(t *testing.T) {
	cases := []struct {
		name   string
		inject func(*nativeConnection, map[uintptr]string)
	}{
		{"no preferences", func(n *nativeConnection, _ map[uintptr]string) {
			n.a.preferencesCreate = func(uintptr, uintptr, uintptr) uintptr { return 0 }
		}},
		{"no service", func(n *nativeConnection, _ map[uintptr]string) {
			n.a.serviceCopy = func(uintptr, uintptr) uintptr { return 0 }
		}},
		{"disabled", func(n *nativeConnection, _ map[uintptr]string) { n.a.serviceEnabled = func(uintptr) uint8 { return 0 } }},
		{"wrong upper type", func(_ *nativeConnection, s map[uintptr]string) { s[63] = "Ethernet" }},
		{"wrong lower type", func(_ *nativeConnection, s map[uintptr]string) { s[64] = "IPSec" }},
		{"missing PPP config", func(n *nativeConnection, _ map[uintptr]string) {
			n.a.interfaceConfiguration = func(uintptr) uintptr { return 0 }
		}},
		{"wrong PPP config type", func(n *nativeConnection, _ map[uintptr]string) {
			n.a.interfaceConfiguration = func(uintptr) uintptr { return 65 }
		}},
		{"missing IPsec config", func(n *nativeConnection, _ map[uintptr]string) {
			n.a.interfaceExtendedConfiguration = func(uintptr, uintptr) uintptr { return 0 }
		}},
		{"bad gateway", func(_ *nativeConnection, s map[uintptr]string) { s[65] = "https://vpn.example.com" }},
		{"embedded NUL gateway", func(_ *nativeConnection, s map[uintptr]string) { s[65] = "vpn.example.com\x00suffix" }},
		{"embedded NUL auth", func(_ *nativeConnection, s map[uintptr]string) { s[66] = "PAP\x00suffix" }},
		{"embedded NUL IPsec auth", func(_ *nativeConnection, s map[uintptr]string) { s[67] = "SharedSecret\x00suffix" }},
		{"non-ASCII gateway", func(_ *nativeConnection, s map[uintptr]string) { s[65] = "vрn.example.com" }},
		{"embedded NUL upper type", func(_ *nativeConnection, s map[uintptr]string) { s[63] = "PPP\x00suffix" }},
		{"oversized gateway", func(_ *nativeConnection, s map[uintptr]string) { s[65] = strings.Repeat("a", 128) }},
		{"unknown PPP auth", func(_ *nativeConnection, s map[uintptr]string) { s[66] = "custom" }},
		{"unknown IPsec auth", func(_ *nativeConnection, s map[uintptr]string) { s[67] = "custom" }},
		{"too many auth values", func(n *nativeConnection, _ map[uintptr]string) {
			n.a.arrayCount = func(uintptr) int { return 17 }
			n.a.arrayValue = func(uintptr, int) uintptr { t.Fatal("oversized array read"); return 0 }
		}},
	}
	for _, key := range []string{"Meridian read-only service configuration", "service-id", "CommRemoteAddress", "AuthProtocol", "IPSec", "AuthenticationMethod"} {
		key := key
		cases = append(cases, struct {
			name   string
			inject func(*nativeConnection, map[uintptr]string)
		}{"allocation " + key, func(n *nativeConnection, _ map[uintptr]string) {
			old := n.a.createString
			n.a.createString = func(a uintptr, s string, e uint32) uintptr {
				if s == key {
					return 0
				}
				return old(a, s, e)
			}
		}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, text, released := inspectionAPIFixture(t)
			tc.inject(n, text)
			owned := trackInspectionOwnership(n.a)
			if _, err := n.readConfiguration(); err == nil {
				t.Fatal("accepted failure")
			}
			assertBalancedCF(t, owned, *released)
		})
	}
}
func TestNativeGenerationStrictNumbersAndOwnership(t *testing.T) {
	cases := []struct {
		name   string
		inject func(*nativeConnection)
	}{
		{"missing extended status", func(n *nativeConnection) { n.a.copyExtendedStatus = func(uintptr) uintptr { return 0 } }},
		{"missing generation", func(n *nativeConnection) {
			old := n.a.dictionaryValue
			n.a.dictionaryValue = func(d, k uintptr) uintptr {
				if d == 71 {
					return 0
				}
				return old(d, k)
			}
		}},
		{"wrong number type", func(n *nativeConnection) { n.a.numberTypeID = func() uintptr { return 99 } }},
		{"float", func(n *nativeConnection) {
			n.a.numberIsFloatType = func(uintptr) uint8 { return 1 }
			n.a.numberGetValue = func(uintptr, int, *int64) uint8 { t.Fatal("converted float"); return 0 }
		}},
		{"conversion failed", func(n *nativeConnection) { n.a.numberGetValue = func(uintptr, int, *int64) uint8 { return 0 } }},
		{"zero", func(n *nativeConnection) {
			n.a.numberGetValue = func(_ uintptr, _ int, v *int64) uint8 { *v = 0; return 1 }
		}},
		{"negative", func(n *nativeConnection) {
			n.a.numberGetValue = func(_ uintptr, _ int, v *int64) uint8 { *v = -1; return 1 }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, _, released := inspectionAPIFixture(t)
			tc.inject(n)
			owned := trackInspectionOwnership(n.a)
			if _, err := n.readConnectTime(); err == nil {
				t.Fatal("accepted generation failure")
			}
			assertBalancedCF(t, owned, *released)
		})
	}
}
