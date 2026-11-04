package macosvpn

import (
	"testing"
	"unsafe"
)

// These tests exercise the ABI wrapper with fake C-function bindings. They do
// not load frameworks, read actual profiles or connect a real system service.
func testAPI(t *testing.T, upper, lower string) (*nativeAPI, *[]uintptr) {
	t.Helper()
	released := []uintptr{}
	next := uintptr(0)
	a := &nativeAPI{
		release: func(p uintptr) { released = append(released, p) },
		createString: func(alloc uintptr, s string, encoding uint32) uintptr {
			if alloc != 0 || encoding != utf8Encoding {
				t.Fatal("string ABI")
			}
			next++
			return next
		},
		preferencesCreate: func(alloc, name, prefs uintptr) uintptr {
			if alloc != 0 || name != 1 || prefs != 0 {
				t.Fatal("preferences ABI")
			}
			return 10
		},
		serviceCopy: func(prefs, id uintptr) uintptr {
			if prefs != 10 || id != 2 {
				t.Fatal("service ABI")
			}
			return 20
		},
		serviceEnabled:   func(uintptr) uint8 { return 1 },
		serviceInterface: func(uintptr) uintptr { return 30 },
		interfaceType:    func(v uintptr) uintptr { return v },
		lowerInterface:   func(uintptr) uintptr { return 40 },
		stringLength: func(v uintptr) int {
			if v == 40 {
				return len(lower)
			}
			return len(upper)
		},
		stringCString: func(v uintptr, p *byte, n int, encoding uint32) uint8 {
			text := upper
			if v == 40 {
				text = lower
			}
			if len(text)+1 > n {
				return 0
			}
			b := unsafe.Slice(p, n)
			copy(b, text)
			b[len(text)] = 0
			return 1
		},
		createConnection: func(alloc, id, callback, ctx uintptr) uintptr {
			if alloc != 0 || id != 2 || callback != 0 || ctx != 0 {
				t.Fatal("connection ABI")
			}
			return 50
		},
		status: func(uintptr) int32 { return int32(Disconnected) },
		start: func(ref, opts uintptr, linger uint8) uint8 {
			if ref != 50 || opts != 0 || linger != 0 {
				t.Fatal("start must not override credentials or linger")
			}
			return 1
		},
		stop: func(ref uintptr, force uint8) uint8 {
			if ref != 50 || force != 0 {
				t.Fatal("stop must not force others off")
			}
			return 1
		},
	}
	return a, &released
}

func TestNativeServiceTypeRejectedBeforeConnection(t *testing.T) {
	for _, types := range [][2]string{{"Ethernet", "L2TP"}, {"PPP", "PPTP"}, {"PPP", "IPSec"}, {"", ""}} {
		a, released := testAPI(t, types[0], types[1])
		a.createConnection = func(uintptr, uintptr, uintptr, uintptr) uintptr { t.Fatal("opened non-L2TP service"); return 0 }
		if _, err := openWithAPI(a, "service-id"); err == nil {
			t.Fatal("accepted wrong service type")
		}
		if len(*released) != 4 {
			t.Fatalf("leaked CF objects: %v", *released)
		}
	}
}
func TestNativeL2TPABIAndRelease(t *testing.T) {
	a, released := testAPI(t, "PPP", "L2TP")
	n, err := openWithAPI(a, "service-id")
	if err != nil {
		t.Fatal(err)
	}
	if len(*released) != 4 {
		t.Fatal("CF temporary objects leaked")
	}
	if n.status() != Disconnected {
		t.Fatal("status ABI")
	}
	if err = n.start(); err != nil {
		t.Fatal(err)
	}
	if err = n.stop(); err != nil {
		t.Fatal(err)
	}
	n.close()
	n.close()
	if len(*released) != 5 || (*released)[4] != 50 {
		t.Fatal("CF connection double release or leak")
	}
}
func TestNativeDisabledServiceRejected(t *testing.T) {
	a, _ := testAPI(t, "PPP", "L2TP")
	a.serviceEnabled = func(uintptr) uint8 { return 0 }
	a.createConnection = func(uintptr, uintptr, uintptr, uintptr) uintptr { t.Fatal("opened disabled service"); return 0 }
	if _, err := openWithAPI(a, "service-id"); err == nil {
		t.Fatal("accepted disabled service")
	}
}

func TestNativeOpenFailurePathsReleaseAllOwnedCF(t *testing.T) {
	cases := []struct {
		name   string
		inject func(*nativeAPI)
	}{
		{"name allocation", func(a *nativeAPI) { a.createString = func(uintptr, string, uint32) uintptr { return 0 } }},
		{"preferences allocation", func(a *nativeAPI) { a.preferencesCreate = func(uintptr, uintptr, uintptr) uintptr { return 0 } }},
		{"ID allocation", func(a *nativeAPI) {
			old := a.createString
			calls := 0
			a.createString = func(x uintptr, s string, e uint32) uintptr {
				calls++
				if calls == 2 {
					return 0
				}
				return old(x, s, e)
			}
		}},
		{"service missing", func(a *nativeAPI) { a.serviceCopy = func(uintptr, uintptr) uintptr { return 0 } }},
		{"disabled service", func(a *nativeAPI) { a.serviceEnabled = func(uintptr) uint8 { return 0 } }},
		{"interface missing", func(a *nativeAPI) { a.serviceInterface = func(uintptr) uintptr { return 0 } }},
		{"lower interface missing", func(a *nativeAPI) { a.lowerInterface = func(uintptr) uintptr { return 0 } }},
		{"connection allocation", func(a *nativeAPI) { a.createConnection = func(uintptr, uintptr, uintptr, uintptr) uintptr { return 0 } }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, released := testAPI(t, "PPP", "L2TP")
			tc.inject(a)
			owned := map[uintptr]int{}
			record := func(v uintptr) uintptr {
				if v != 0 {
					owned[v]++
				}
				return v
			}
			cs := a.createString
			a.createString = func(x uintptr, s string, e uint32) uintptr { return record(cs(x, s, e)) }
			prefs := a.preferencesCreate
			a.preferencesCreate = func(x, y, z uintptr) uintptr { return record(prefs(x, y, z)) }
			service := a.serviceCopy
			a.serviceCopy = func(x, y uintptr) uintptr { return record(service(x, y)) }
			conn := a.createConnection
			a.createConnection = func(x, y, z, w uintptr) uintptr { return record(conn(x, y, z, w)) }
			if _, err := openWithAPI(a, "service-id"); err == nil {
				t.Fatal("failure injection was accepted")
			}
			assertBalancedCF(t, owned, *released)
		})
	}
}
