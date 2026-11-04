package macosvpn

import (
	"strings"
	"testing"
	"unsafe"
)

// All pointers are synthetic IDs and all native calls are replaced. No Apple
// framework is loaded, and no real configuration is read or changed.
func evidenceFixture(t *testing.T) (*nativeConnection, map[uintptr]string, *[]uintptr) {
	t.Helper()
	strings := map[uintptr]string{1: "service-id", 5: "10.8.0.2", 8: "ppp7"}
	arrays := map[uintptr][]uintptr{4: {5}, 9: {5}}
	dictionaries := map[uintptr]map[string]uintptr{2: {"IPv4": 3}, 3: {"Addresses": 4}, 7: {"InterfaceName": 8, "Addresses": 9}}
	released := []uintptr{}
	next := uintptr(100)
	a := &nativeAPI{
		release: func(v uintptr) { released = append(released, v) },
		createString: func(alloc uintptr, text string, enc uint32) uintptr {
			if alloc != 0 || enc != utf8Encoding {
				t.Fatal("CF string ABI")
			}
			next++
			strings[next] = text
			return next
		},
		stringLength: func(v uintptr) int { return len(strings[v]) },
		stringCString: func(v uintptr, p *byte, n int, enc uint32) uint8 {
			text, ok := strings[v]
			if !ok || len(text)+1 > n {
				return 0
			}
			out := unsafe.Slice(p, n)
			copy(out, text)
			out[len(text)] = 0
			return 1
		},
	}
	a.evidenceAPI = evidenceAPI{
		typeID: func(v uintptr) uintptr {
			if _, ok := strings[v]; ok {
				return 11
			}
			if _, ok := arrays[v]; ok {
				return 12
			}
			if _, ok := dictionaries[v]; ok {
				return 13
			}
			return 99
		},
		stringTypeID: func() uintptr { return 11 }, arrayTypeID: func() uintptr { return 12 }, dictionaryTypeID: func() uintptr { return 13 },
		dictionaryValue: func(dict, key uintptr) uintptr { return dictionaries[dict][strings[key]] },
		arrayCount:      func(v uintptr) int { return len(arrays[v]) }, arrayValue: func(v uintptr, i int) uintptr { return arrays[v][i] },
		copyServiceID: func(ref uintptr) uintptr {
			if ref != 50 {
				t.Fatal("connection reference")
			}
			return 1
		},
		copyExtendedStatus: func(ref uintptr) uintptr {
			if ref != 50 {
				t.Fatal("connection reference")
			}
			return 2
		},
		storeCreate: func(alloc, name, callback, ctx uintptr) uintptr {
			if alloc != 0 || strings[name] == "" || callback != 0 || ctx != 0 {
				t.Fatal("store ABI")
			}
			return 6
		},
		storeCopyValue: func(store, key uintptr) uintptr {
			if store != 6 || strings[key] != "State:/Network/Service/service-id/IPv4" {
				t.Fatal("wrong service lookup")
			}
			return 7
		},
	}
	return &nativeConnection{a: a, ref: 50, serviceID: "service-id"}, strings, &released
}
func TestNativeInterfaceEvidenceReadAndOwnership(t *testing.T) {
	n, _, released := evidenceFixture(t)
	raw, err := n.readSystemEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifyEvidence(raw, validInterface); err != nil {
		t.Fatal(err)
	}
	counts := map[uintptr]int{}
	for _, v := range *released {
		counts[v]++
	}
	// Owned Copy/Create references must be released exactly once. Borrowed
	// dictionary/array members must never be released independently.
	for _, v := range []uintptr{1, 2, 6, 7} {
		if counts[v] != 1 {
			t.Fatalf("owned reference %d released %d times", v, counts[v])
		}
	}
	for _, v := range []uintptr{3, 4, 5, 8, 9} {
		if counts[v] != 0 {
			t.Fatalf("released borrowed reference %d", v)
		}
	}
	for v := range counts {
		if counts[v] != 1 {
			t.Fatalf("double release: %d", v)
		}
	}
}
func TestNativeEvidenceRejectsWrongIdentityBeforeNetworkRead(t *testing.T) {
	n, text, _ := evidenceFixture(t)
	text[1] = "another-service"
	n.a.copyExtendedStatus = func(uintptr) uintptr { t.Fatal("read wrong service"); return 0 }
	if _, err := n.readSystemEvidence(); err == nil {
		t.Fatal("accepted wrong identity")
	}
}
func TestNativeEvidenceRejectsMalformedCFTypesAndSizes(t *testing.T) {
	n, _, _ := evidenceFixture(t)
	n.a.copyExtendedStatus = func(uintptr) uintptr { return 5 } // CFString, not dictionary
	if _, err := n.readSystemEvidence(); err == nil {
		t.Fatal("accepted malformed dictionary")
	}
	n, _, _ = evidenceFixture(t)
	n.a.arrayCount = func(uintptr) int { return 17 }
	n.a.arrayValue = func(uintptr, int) uintptr { t.Fatal("read oversized array"); return 0 }
	if _, err := n.readSystemEvidence(); err == nil {
		t.Fatal("accepted oversized array")
	}
	n, _, _ = evidenceFixture(t)
	n.a.arrayValue = func(uintptr, int) uintptr { return 3 } // CFDictionary, not string
	if _, err := n.readSystemEvidence(); err == nil {
		t.Fatal("accepted non-string address")
	}
}

// Capture every successful Copy/Create return, then require one CFRelease per
// owned reference even when a later native operation fails. Borrowed values are
// not counted as owned. Setup failures are injected before installing tracking.
func trackEvidenceOwnership(a *nativeAPI) map[uintptr]int {
	owned := map[uintptr]int{}
	record := func(v uintptr) uintptr {
		if v != 0 {
			owned[v]++
		}
		return v
	}
	cs := a.createString
	a.createString = func(x uintptr, s string, e uint32) uintptr { return record(cs(x, s, e)) }
	id := a.copyServiceID
	a.copyServiceID = func(v uintptr) uintptr { return record(id(v)) }
	ext := a.copyExtendedStatus
	a.copyExtendedStatus = func(v uintptr) uintptr { return record(ext(v)) }
	create := a.storeCreate
	a.storeCreate = func(x, y, z, w uintptr) uintptr { return record(create(x, y, z, w)) }
	copyValue := a.storeCopyValue
	a.storeCopyValue = func(x, y uintptr) uintptr { return record(copyValue(x, y)) }
	return owned
}
func assertBalancedCF(t *testing.T, owned map[uintptr]int, released []uintptr) {
	t.Helper()
	counts := map[uintptr]int{}
	for _, v := range released {
		counts[v]++
	}
	for v, n := range owned {
		if counts[v] != n {
			t.Fatalf("CF reference %d: owned %d, released %d", v, n, counts[v])
		}
	}
	for v, n := range counts {
		if owned[v] != n {
			t.Fatalf("released unowned CF reference %d (%d releases)", v, n)
		}
	}
}
func TestNativeEvidenceFailurePathsReleaseAllOwnedCF(t *testing.T) {
	cases := []struct {
		name   string
		inject func(*nativeConnection, map[uintptr]string)
	}{
		{"no service ID", func(n *nativeConnection, _ map[uintptr]string) {
			n.a.copyServiceID = func(uintptr) uintptr { return 0 }
		}},
		{"mismatched service ID", func(_ *nativeConnection, s map[uintptr]string) { s[1] = "different-service" }},
		{"no extended status", func(n *nativeConnection, _ map[uintptr]string) {
			n.a.copyExtendedStatus = func(uintptr) uintptr { return 0 }
		}},
		{"wrong extended type", func(n *nativeConnection, _ map[uintptr]string) {
			n.a.copyExtendedStatus = func(uintptr) uintptr { return 5 }
		}},
		{"IPv4 key allocation", func(n *nativeConnection, _ map[uintptr]string) {
			old := n.a.createString
			n.a.createString = func(a uintptr, s string, e uint32) uintptr {
				if s == "IPv4" {
					return 0
				}
				return old(a, s, e)
			}
		}},
		{"address key allocation", func(n *nativeConnection, _ map[uintptr]string) {
			old := n.a.createString
			n.a.createString = func(a uintptr, s string, e uint32) uintptr {
				if s == "Addresses" {
					return 0
				}
				return old(a, s, e)
			}
		}},
		{"name allocation", func(n *nativeConnection, _ map[uintptr]string) {
			old := n.a.createString
			n.a.createString = func(a uintptr, s string, e uint32) uintptr {
				if s == "Meridian read-only VPN inspection" {
					return 0
				}
				return old(a, s, e)
			}
		}},
		{"no store", func(n *nativeConnection, _ map[uintptr]string) {
			n.a.storeCreate = func(uintptr, uintptr, uintptr, uintptr) uintptr { return 0 }
		}},
		{"state key allocation", func(n *nativeConnection, _ map[uintptr]string) {
			old := n.a.createString
			n.a.createString = func(a uintptr, s string, e uint32) uintptr {
				if s == "State:/Network/Service/service-id/IPv4" {
					return 0
				}
				return old(a, s, e)
			}
		}},
		{"no state", func(n *nativeConnection, _ map[uintptr]string) {
			n.a.storeCopyValue = func(uintptr, uintptr) uintptr { return 0 }
		}},
		{"wrong state type", func(n *nativeConnection, _ map[uintptr]string) {
			n.a.storeCopyValue = func(uintptr, uintptr) uintptr { return 5 }
		}},
		{"negative array length", func(n *nativeConnection, _ map[uintptr]string) { n.a.arrayCount = func(uintptr) int { return -1 } }},
		{"empty array", func(n *nativeConnection, _ map[uintptr]string) { n.a.arrayCount = func(uintptr) int { return 0 } }},
		{"oversized array", func(n *nativeConnection, _ map[uintptr]string) { n.a.arrayCount = func(uintptr) int { return 17 } }},
		{"null array member", func(n *nativeConnection, _ map[uintptr]string) {
			n.a.arrayValue = func(uintptr, int) uintptr { return 0 }
		}},
		{"wrong array member type", func(n *nativeConnection, _ map[uintptr]string) {
			n.a.arrayValue = func(uintptr, int) uintptr { return 3 }
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, text, released := evidenceFixture(t)
			tc.inject(n, text)
			owned := trackEvidenceOwnership(n.a)
			if _, err := n.readSystemEvidence(); err == nil {
				t.Fatal("failure injection was accepted")
			}
			assertBalancedCF(t, owned, *released)
		})
	}
}
func TestNativeStringBufferAndArrayBoundaries(t *testing.T) {
	n, text, released := evidenceFixture(t)
	// The fixed buffer has 128 bytes, including its terminating NUL.
	text[5] = strings.Repeat("a", maxServiceIDBytes)
	if got := n.a.stringValue(5); len(got) != maxServiceIDBytes {
		t.Fatal("valid C-string boundary rejected")
	}
	text[5] = strings.Repeat("a", maxServiceIDBytes+1)
	if _, err := n.a.stringArray(4); err == nil {
		t.Fatal("accepted unrepresentable string")
	}
	text[5] = "10.8.0.2"
	n.a.arrayCount = func(uintptr) int { return 16 }
	n.a.arrayValue = func(uintptr, int) uintptr { return 5 }
	values, err := n.a.stringArray(4)
	if err != nil || len(values) != 16 {
		t.Fatalf("valid array boundary: %v", err)
	}
	// Duplicate address policy is enforced later by verifyEvidence, not CF parsing.
	if _, err := ipv4Set(values); err == nil {
		t.Fatal("duplicate boundary values bypassed policy")
	}
	if len(*released) != 0 {
		t.Fatal("borrowed array or string was released")
	}
}
