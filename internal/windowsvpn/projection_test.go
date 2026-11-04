package windowsvpn

import (
	"testing"
	"unsafe"
)

func fixtureProjection(_ uintptr, p *nativePPPIPv4, _ *uint32) uint32 {
	putUTF16(p.Address[:], "10.20.30.40")
	return 0
}

func TestPPPIPv4SDKLayout(t *testing.T) {
	var p nativePPPIPv4
	if pppIPv4Size != 80 || unsafe.Offsetof(p.Error) != 4 || unsafe.Offsetof(p.Address) != 8 || unsafe.Offsetof(p.ServerAddress) != 40 || unsafe.Offsetof(p.Options) != 72 || unsafe.Offsetof(p.ServerOptions) != 76 {
		t.Fatal("RASPPPIPW layout mismatch")
	}
}
func TestPPPIPv4RejectsIncompleteProjection(t *testing.T) {
	for name, mutate := range map[string]func(*nativePPPIPv4, *uint32) uint32{
		"API error":         func(*nativePPPIPv4, *uint32) uint32 { return 731 },
		"negotiation error": func(p *nativePPPIPv4, _ *uint32) uint32 { p.Error = 720; return 0 },
		"wrong size":        func(p *nativePPPIPv4, _ *uint32) uint32 { p.Size = 0; return 0 },
		"short result":      func(_ *nativePPPIPv4, s *uint32) uint32 { *s = 8; return 0 },
		"oversized result":  func(_ *nativePPPIPv4, s *uint32) uint32 { *s = 100; return 0 },
		"unterminated": func(p *nativePPPIPv4, _ *uint32) uint32 {
			for i := range p.Address {
				p.Address[i] = '1'
			}
			return 0
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readPPPIPv4(71, func(_ uintptr, p *nativePPPIPv4, s *uint32) uint32 { fixtureProjection(0, p, s); return mutate(p, s) })
			if err == nil {
				t.Fatal("bad projection accepted")
			}
		})
	}
	for _, value := range []string{"", "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "169.254.1.2", "::1", "2001:db8::1", "10.01.2.3"} {
		t.Run(value, func(t *testing.T) {
			_, err := readPPPIPv4(71, func(_ uintptr, p *nativePPPIPv4, _ *uint32) uint32 { putUTF16(p.Address[:], value); return 0 })
			if err == nil {
				t.Fatal("invalid local address accepted")
			}
		})
	}
	if _, err := readPPPIPv4(0, fixtureProjection); err == nil {
		t.Fatal("null handle accepted")
	}
	if _, err := readPPPIPv4(71, nil); err == nil {
		t.Fatal("missing procedure accepted")
	}
}

func TestHandleIPv4BindsExactDirectHandleWithoutExclusivity(t *testing.T) {
	entry := fixtureEvidence(t)
	record := fixtureConnection()
	other := record
	other.handle++
	other.correlation[0]++
	statusCalls, projectionCalls := 0, 0
	got, err := inspectHandleIPv4(entry, record.handle, fixedConnections(record, other), func(h uintptr, s *nativeConnectionStatus) uint32 {
		statusCalls++
		if h != record.handle {
			t.Fatal("used another reference")
		}
		return fixtureStatus(h, s)
	}, func(h uintptr, p *nativePPPIPv4, s *uint32) uint32 {
		projectionCalls++
		if h != record.handle || p.Size != 80 || *s != 80 {
			t.Fatal("wrong projection request")
		}
		return fixtureProjection(h, p, s)
	}, unchangedEntry)
	if err != nil || got.handle != record.handle || got.entryGUID != record.guid || got.correlation != record.correlation || got.address.String() != "10.20.30.40" || got.gateway != "vpn.example.test" || statusCalls != 2 || projectionCalls != 2 {
		t.Fatal("exact handle evidence failed", err)
	}
	// Evidence intentionally has no interface field: no guessed mapping from
	// same address, logon LUID, underlying dwIfIndex or shared-reference flags.
}

func TestHandleIPv4RejectsRacesAndMismatches(t *testing.T) {
	entry := fixtureEvidence(t)
	r := fixtureConnection()
	for _, kind := range []string{"missing handle", "changed correlation", "changed logon session", "changed address", "later disconnect", "wrong gateway", "profile drift"} {
		t.Run(kind, func(t *testing.T) {
			before, after := r, r
			var enum enumConnectionsFunc
			switch kind {
			case "missing handle":
				before.handle++
				after = before
			case "changed correlation":
				after.correlation[0]++
			case "changed logon session":
				after.luid[0]++
			}
			enum = changingConnections([]connectionRecord{before}, []connectionRecord{after})
			n, m, q := 0, 0, 0
			_, err := inspectHandleIPv4(entry, r.handle, enum, func(h uintptr, s *nativeConnectionStatus) uint32 {
				n++
				fixtureStatus(h, s)
				if kind == "later disconnect" && n == 2 {
					s.State = 0x2001
				}
				if kind == "wrong gateway" {
					clear(s.PhoneNumber[:])
					putUTF16(s.PhoneNumber[:], "other.example.test")
				}
				return 0
			}, func(h uintptr, p *nativePPPIPv4, s *uint32) uint32 {
				m++
				fixtureProjection(h, p, s)
				if kind == "changed address" && m == 2 {
					clear(p.Address[:])
					putUTF16(p.Address[:], "10.20.30.41")
				}
				return 0
			}, func(EntryEvidence) error {
				q++
				if kind == "profile drift" && q == 2 {
					return ErrVerification
				}
				return nil
			})
			if err == nil {
				t.Fatal("unstable evidence accepted")
			}
		})
	}
}

func TestHandleIPv4RejectsBoundaryFailures(t *testing.T) {
	for _, kind := range []string{"enumeration failure", "status failure", "malformed status", "wrong device", "wrong profile", "nil enumeration", "nil status", "nil projection", "nil revalidation"} {
		t.Run(kind, func(t *testing.T) {
			entry := fixtureEvidence(t)
			record := fixtureConnection()
			enumerate := fixedConnections(record)
			status := getConnectionStatusFunc(fixtureStatus)
			projection := projectionIPv4Func(fixtureProjection)
			revalidate := func(EntryEvidence) error { return nil }
			switch kind {
			case "enumeration failure":
				enumerate = func([]uint32, *uint32, *uint32) uint32 { return 5 }
			case "status failure":
				status = func(uintptr, *nativeConnectionStatus) uint32 { return 6 }
			case "malformed status":
				status = func(h uintptr, s *nativeConnectionStatus) uint32 {
					fixtureStatus(h, s)
					for i := range s.PhoneNumber {
						s.PhoneNumber[i] = 'x'
					}
					return 0
				}
			case "wrong device":
				status = func(h uintptr, s *nativeConnectionStatus) uint32 {
					fixtureStatus(h, s)
					clear(s.DeviceName[:])
					putUTF16(s.DeviceName[:], "other")
					return 0
				}
			case "wrong profile":
				record.guid[0]++
				enumerate = fixedConnections(record)
			case "nil enumeration":
				enumerate = nil
			case "nil status":
				status = nil
			case "nil projection":
				projection = nil
			case "nil revalidation":
				revalidate = nil
			}
			if _, err := inspectHandleIPv4(entry, record.handle, enumerate, status, projection, revalidate); err == nil {
				t.Fatal("invalid boundary accepted")
			}
		})
	}
}
