//go:build linux

package nmvpn

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

func resolvedVariant(signature string, value any) dbus.Variant {
	return dbus.MakeVariantWithSignature(value, dbus.ParseSignatureMust(signature))
}

func resolvedManagerFixture() map[string]dbus.Variant {
	p := resolvedCommonFixture()
	p["DNS"] = resolvedVariant("a(iiay)", [][]any{{int32(0), int32(2), []byte{192, 0, 2, 53}}, {int32(2), int32(2), []byte{10, 0, 0, 53}}})
	p["DNSEx"] = resolvedVariant("a(iiayqs)", [][]any{{int32(0), int32(2), []byte{192, 0, 2, 53}, uint16(853), "dns.example"}, {int32(2), int32(2), []byte{10, 0, 0, 53}, uint16(0), ""}})
	p["FallbackDNS"] = resolvedVariant("a(iiay)", [][]any{{int32(0), int32(2), []byte{198, 51, 100, 53}}})
	p["FallbackDNSEx"] = resolvedVariant("a(iiayqs)", [][]any{{int32(0), int32(2), []byte{198, 51, 100, 53}, uint16(0), ""}})
	p["Domains"] = resolvedVariant("a(isb)", [][]any{{int32(0), "example", false}, {int32(2), "corp.example", true}, {int32(2), ".", true}})
	p["DNSStubListener"], p["ResolvConfMode"] = dbus.MakeVariant("yes"), dbus.MakeVariant("stub")
	return p
}

func resolvedLinkFixture() map[string]dbus.Variant {
	p := resolvedCommonFixture()
	p["DNS"] = resolvedVariant("a(iay)", [][]any{{int32(2), []byte{10, 0, 0, 53}}})
	p["DNSEx"] = resolvedVariant("a(iayqs)", [][]any{{int32(2), []byte{10, 0, 0, 53}, uint16(0), ""}})
	p["Domains"] = resolvedVariant("a(sb)", [][]any{{"corp.example", true}, {".", true}})
	p["DefaultRoute"], p["ScopesMask"] = dbus.MakeVariant(true), dbus.MakeVariant(uint64(1))
	return p
}

func resolvedCommonFixture() map[string]dbus.Variant {
	return map[string]dbus.Variant{
		"LLMNR": dbus.MakeVariant("resolve"), "MulticastDNS": dbus.MakeVariant("no"),
		"DNSOverTLS": dbus.MakeVariant("opportunistic"), "DNSSEC": dbus.MakeVariant("allow-downgrade"),
		"DNSSECSupported": dbus.MakeVariant(true), "DNSSECNegativeTrustAnchors": dbus.MakeVariant([]string{"local", "10.in-addr.arpa"}),
	}
}

func resolvedFullFixture(manager bool) map[string]dbus.Variant {
	p := resolvedLinkFixture()
	p["CurrentDNSServer"] = resolvedVariant("(iay)", []any{int32(0), []byte{}})
	p["CurrentDNSServerEx"] = resolvedVariant("(iayqs)", []any{int32(0), []byte{}, uint16(0), ""})
	if manager {
		p = resolvedManagerFixture()
		p["LLMNRHostname"] = dbus.MakeVariant("test-host")
		p["CurrentDNSServer"] = resolvedVariant("(iiay)", []any{int32(0), int32(0), []byte{}})
		p["CurrentDNSServerEx"] = resolvedVariant("(iiayqs)", []any{int32(0), int32(0), []byte{}, uint16(0), ""})
		p["TransactionStatistics"] = resolvedVariant("(tt)", []any{uint64(0), uint64(42)})
		p["CacheStatistics"] = resolvedVariant("(ttt)", []any{uint64(0), uint64(42), uint64(7)})
		p["DNSSECStatistics"] = resolvedVariant("(tttt)", []any{uint64(0), uint64(0), uint64(0), uint64(0)})
	}
	return p
}

func TestResolvedSchemaPreservesPolicyAndCopies(t *testing.T) {
	managerProperties, linkProperties := resolvedManagerFixture(), resolvedLinkFixture()
	manager, err := parseResolvedManager(managerProperties)
	if err != nil {
		t.Fatal(err)
	}
	link, err := parseResolvedLink(linkProperties, 2, resolvedLinkPath(2))
	if err != nil {
		t.Fatal(err)
	}
	if manager.DNS[0].Address != netip.MustParseAddr("192.0.2.53") || manager.DNS[0].Port != 853 || manager.DNS[0].ServerName != "dns.example" || manager.DNS[1] != link.DNS[0] || link.Domains[1].Name != "." || !link.Domains[1].RouteOnly || !link.DefaultRoute || link.ScopesMask != 1 {
		t.Fatal("policy data was lost")
	}
	if !reflect.DeepEqual(manager.Modes.NegativeTrustAnchors, []string{"10.in-addr.arpa", "local"}) {
		t.Fatal("NTA set not canonicalized")
	}
	managerProperties["DNSEx"].Value().([][]any)[0][2].([]byte)[0] = 1
	managerProperties["DNSSECNegativeTrustAnchors"].Value().([]string)[0] = "changed"
	if manager.DNS[0].Address.String() != "192.0.2.53" || manager.Modes.NegativeTrustAnchors[1] != "local" {
		t.Fatal("retained input buffers")
	}
	o := &ResolvedObservation{snapshot: &ResolvedObservationSnapshot{Manager: manager, Links: []ResolvedLinkSnapshot{link}}}
	first, _ := o.Snapshot()
	first.Manager.DNS[0].Port = 7
	first.Manager.FallbackDNS[0].Port = 7
	first.Manager.Domains[0].Name = "changed"
	first.Manager.Modes.NegativeTrustAnchors[0] = "changed"
	first.Links[0].DNS[0].Port = 7
	first.Links[0].Domains[0].Name = "changed"
	first.Links[0].Modes.NegativeTrustAnchors[0] = "changed"
	again, err := o.Snapshot()
	if err != nil || !reflect.DeepEqual(again.Manager, manager) || !reflect.DeepEqual(again.Links[0], link) {
		t.Fatal("public snapshot leaked mutable state")
	}
	for _, empty := range []*ResolvedObservation{nil, {}} {
		if _, err := empty.Snapshot(); err == nil {
			t.Fatal("zero observation accepted")
		}
	}
}

func TestResolvedSchemaClosedProperties(t *testing.T) {
	for _, manager := range []bool{false, true} {
		base := resolvedFullFixture(manager)
		if _, err := resolvedPolicyProperties(base, manager); err != nil {
			t.Fatal(err)
		}
		for key := range base {
			t.Run(key+"-missing", func(t *testing.T) {
				p := resolvedFullFixture(manager)
				delete(p, key)
				if _, err := resolvedPolicyProperties(p, manager); err == nil {
					t.Fatal("missing property accepted")
				}
			})
		}
		p := resolvedFullFixture(manager)
		p["FutureRoutingPolicy"] = dbus.MakeVariant(true)
		if _, err := resolvedPolicyProperties(p, manager); err == nil {
			t.Fatal("unknown property accepted")
		}
		p = resolvedFullFixture(manager)
		delete(p, "CurrentDNSServer")
		p["FutureRoutingPolicy"] = dbus.MakeVariant(true)
		if _, err := resolvedPolicyProperties(p, manager); err == nil {
			t.Fatal("unknown property substituted for required one")
		}
	}
	for _, key := range []string{"TransactionStatistics", "CacheStatistics", "DNSSECStatistics", "CurrentDNSServer", "CurrentDNSServerEx", "LLMNRHostname"} {
		p := resolvedFullFixture(true)
		p[key] = dbus.MakeVariant(uint32(0))
		if _, err := resolvedPolicyProperties(p, true); err == nil {
			t.Fatalf("unsupported telemetry %s accepted", key)
		}
	}
	p := resolvedFullFixture(true)
	p["TransactionStatistics"] = resolvedVariant("(tt)", []any{int64(0), uint64(0)})
	if _, err := resolvedPolicyProperties(p, true); err == nil {
		t.Fatal("signature-only numeric coercion accepted")
	}
}

func TestResolvedSchemaRejectsUnsupportedPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		value       dbus.Variant
	}{
		{"llmnr-empty", "LLMNR", dbus.MakeVariant("")}, {"mdns-future", "MulticastDNS", dbus.MakeVariant("future")},
		{"tls-type", "DNSOverTLS", dbus.MakeVariant(true)}, {"tls-empty", "DNSOverTLS", dbus.MakeVariant("")},
		{"dnssec-future", "DNSSEC", dbus.MakeVariant("future")}, {"supported-type", "DNSSECSupported", dbus.MakeVariant(uint32(1))},
		{"anchors-duplicate", "DNSSECNegativeTrustAnchors", dbus.MakeVariant([]string{"local", "LOCAL"})},
		{"anchors-empty", "DNSSECNegativeTrustAnchors", dbus.MakeVariant([]string{""})},
		{"anchors-oversize", "DNSSECNegativeTrustAnchors", dbus.MakeVariant(make([]string, resolvedMaxEntries+1))},
		{"mode-future", "ResolvConfMode", dbus.MakeVariant("future")}, {"stub-future", "DNSStubListener", dbus.MakeVariant("future")},
		{"dns-no-ex", "DNSEx", dbus.Variant{}}, {"dns-wrong-signature", "DNSEx", resolvedVariant("av", [][]any{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := resolvedManagerFixture()
			p[tc.field] = tc.value
			if _, err := parseResolvedManager(p); err == nil {
				t.Fatal("unsupported policy accepted")
			}
		})
	}
	for _, key := range resolvedManagerFields {
		p := resolvedManagerFixture()
		delete(p, key)
		if _, err := parseResolvedManager(p); err == nil {
			t.Fatalf("missing %s accepted", key)
		}
	}
	for _, mask := range []any{uint32(1), int64(1), uint64(32), uint64(1 << 63)} {
		p := resolvedLinkFixture()
		p["ScopesMask"] = dbus.MakeVariant(mask)
		if _, err := parseResolvedLink(p, 2, resolvedLinkPath(2)); err == nil {
			t.Fatal("unknown scope/type accepted")
		}
	}
	for _, path := range []dbus.ObjectPath{"/", "/org/freedesktop/resolve1/link/_02", "/org/freedesktop/resolve1/link/_3", "/org/freedesktop/resolve1/link/_-2"} {
		if _, err := parseResolvedLink(resolvedLinkFixture(), 2, path); err == nil {
			t.Fatal("wrong GetLink path accepted")
		}
	}
}

func TestResolvedSchemaRejectsDNSConfusion(t *testing.T) {
	for _, row := range [][]any{
		{int32(-1), int32(2), []byte{1, 2, 3, 4}, uint16(0), ""},
		{uint32(0), int32(2), []byte{1, 2, 3, 4}, uint16(0), ""},
		{int32(0), int32(0), []byte{1, 2, 3, 4}, uint16(0), ""},
		{int32(0), int32(10), []byte{1, 2, 3, 4}, uint16(0), ""},
		{int32(0), int32(2), []byte{0, 0, 0, 0}, uint16(0), ""},
		{int32(0), int32(2), []byte{224, 0, 0, 1}, uint16(0), ""},
		{int32(0), int32(10), netip.MustParseAddr("::ffff:1.2.3.4").AsSlice(), uint16(0), ""},
		{int32(0), int32(10), netip.MustParseAddr("fe80::53").AsSlice(), uint16(0), ""},
		{int32(0), int32(2), []byte{1, 2, 3, 4}, uint32(53), ""},
		{int32(0), int32(2), []byte{1, 2, 3, 4}, uint16(0), "bad name"},
	} {
		legacy := resolvedVariant("a(iiay)", [][]any{row[:3]})
		extended := resolvedVariant("a(iiayqs)", [][]any{row})
		if _, err := resolvedDNSPair(legacy, extended, 0, true); err == nil {
			t.Fatalf("bad row accepted: %#v", row)
		}
	}
	p := resolvedManagerFixture()
	p["DNSEx"].Value().([][]any)[0][2] = []byte{1, 2, 3, 4}
	if _, err := parseResolvedManager(p); err == nil {
		t.Fatal("legacy/extended mismatch accepted")
	}
	row := []any{int32(0), int32(2), []byte{1, 2, 3, 4}, uint16(0), ""}
	if _, err := resolvedDNSPair(resolvedVariant("a(iiay)", [][]any{row[:3], row[:3]}), resolvedVariant("a(iiayqs)", [][]any{row, row}), 0, true); err == nil {
		t.Fatal("duplicate extended server accepted")
	}
	if _, err := resolvedDNSPair(resolvedVariant("a(iiay)", make([][]any, resolvedMaxEntries+1)), resolvedVariant("a(iiayqs)", make([][]any, resolvedMaxEntries+1)), 0, true); err == nil {
		t.Fatal("oversized DNS accepted")
	}
	// Same IP with distinct TLS ports/names is not a duplicate extended server.
	other := []any{int32(0), int32(2), []byte{1, 2, 3, 4}, uint16(853), "dns.example"}
	if _, err := resolvedDNSPair(resolvedVariant("a(iiay)", [][]any{row[:3], other[:3]}), resolvedVariant("a(iiayqs)", [][]any{row, other}), 0, true); err != nil {
		t.Fatal(err)
	}
}

func TestResolvedSchemaDomainsAndOrder(t *testing.T) {
	for _, name := range []string{"", "example.", "a..b", "a b", "~example", strings.Repeat("a", 64), "-a.example", "a-.example", "é.example", `bad\032name`} {
		if _, err := resolvedDomains(resolvedVariant("a(sb)", [][]any{{name, true}}), 2, false); err == nil {
			t.Fatalf("unsupported domain %q accepted", name)
		}
	}
	for _, rows := range [][][]any{{{".", false}}, {{"a", true}, {"A", false}}, {{"a", uint32(1)}}} {
		if _, err := resolvedDomains(resolvedVariant("a(sb)", rows), 2, false); err == nil {
			t.Fatal("ambiguous domain accepted")
		}
	}
	out, err := resolvedDomains(resolvedVariant("a(sb)", [][]any{{"z.example", false}, {"a.example", false}}), 2, false)
	if err != nil || out[0].Name != "z.example" || out[1].Name != "a.example" {
		t.Fatal("search domain preference order changed")
	}
}

// Exercise godbus's real codec without a listener, host bus or resolver. Locally
// constructed typed structs and the decoded []any representation must agree.
func TestResolvedSchemaActualGodbusWireShapes(t *testing.T) {
	type dns struct {
		Index, Family int32
		Address       []byte
	}
	type dnsEx struct {
		Index, Family int32
		Address       []byte
		Port          uint16
		Name          string
	}
	type domain struct {
		Index int32
		Name  string
		Route bool
	}
	type current struct {
		Index, Family int32
		Address       []byte
	}
	type currentEx struct {
		Index, Family int32
		Address       []byte
		Port          uint16
		Name          string
	}
	p := resolvedFullFixture(true)
	p["DNS"] = dbus.MakeVariant([]dns{{0, 2, []byte{192, 0, 2, 53}}, {2, 2, []byte{10, 0, 0, 53}}})
	p["DNSEx"] = dbus.MakeVariant([]dnsEx{{0, 2, []byte{192, 0, 2, 53}, 853, "dns.example"}, {2, 2, []byte{10, 0, 0, 53}, 0, ""}})
	p["FallbackDNS"] = dbus.MakeVariant([]dns{{0, 2, []byte{198, 51, 100, 53}}})
	p["FallbackDNSEx"] = dbus.MakeVariant([]dnsEx{{0, 2, []byte{198, 51, 100, 53}, 0, ""}})
	p["Domains"] = dbus.MakeVariant([]domain{{0, "example", false}, {2, "corp.example", true}, {2, ".", true}})
	p["CurrentDNSServer"] = dbus.MakeVariant(current{0, 0, []byte{}})
	p["CurrentDNSServerEx"] = dbus.MakeVariant(currentEx{0, 0, []byte{}, 0, ""})
	p["TransactionStatistics"] = dbus.MakeVariant(struct{ A, B uint64 }{0, 42})
	p["CacheStatistics"] = dbus.MakeVariant(struct{ A, B, C uint64 }{0, 42, 7})
	p["DNSSECStatistics"] = dbus.MakeVariant(struct{ A, B, C, D uint64 }{})
	all := make(map[string]dbus.Variant, len(p))
	for name, value := range p {
		m := &dbus.Message{Type: dbus.TypeSignal, Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldPath: dbus.MakeVariant(dbus.ObjectPath("/fixture")), dbus.FieldInterface: dbus.MakeVariant("test.Fixture"), dbus.FieldMember: dbus.MakeVariant("Value"), dbus.FieldSignature: dbus.MakeVariant(dbus.ParseSignatureMust("v")),
		}, Body: []any{value}}
		var buffer bytes.Buffer
		if err := m.EncodeTo(&buffer, binary.LittleEndian); err != nil {
			t.Fatal(err)
		}
		decoded, err := dbus.DecodeMessage(&buffer)
		if err != nil {
			t.Fatal(err)
		}
		variant, ok := decoded.Body[0].(dbus.Variant)
		if !ok {
			t.Fatalf("unexpected single-property variant: %T", decoded.Body[0])
		}
		all[name] = variant
	}
	policy, err := resolvedPolicyProperties(all, true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseResolvedManager(policy)
	want, wantErr := parseResolvedManager(resolvedManagerFixture())
	if err != nil || wantErr != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("wire schema lost policy: %v", err)
	}
}
