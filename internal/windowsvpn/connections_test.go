package windowsvpn

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
	"unsafe"
)

func fixtureEvidence(t *testing.T) EntryEvidence {
	t.Helper()
	evidence, err := inspectEntryProperties(propertiesReader(fixtureProperties()), fixtureEntry(), "vpn.example.test")
	if err != nil { t.Fatal(err) }
	return evidence
}
func fixtureConnection() connectionRecord {
	r := connectionRecord{handle: 0x11223344, name: fixtureEntry().Name, phonebook: fixtureEntry().PhonebookPath, deviceType: "vpn", deviceName: "WAN Miniport (L2TP)", guid: fixtureProperties().GUID}
	r.correlation[0] = 2
	r.luid[0] = 1
	return r
}
func encodeConnection(r connectionRecord, l connectionLayout) []byte {
	b := make([]byte, l.size)
	binary.LittleEndian.PutUint32(b, uint32(l.size))
	if l.pointerBytes == 8 { binary.LittleEndian.PutUint64(b[4:], uint64(r.handle)) } else { binary.LittleEndian.PutUint32(b[4:], uint32(r.handle)) }
	for offset, text := range map[int]string{l.name: r.name, l.deviceType: r.deviceType, l.deviceName: r.deviceName, l.phonebook: r.phonebook} {
		for i, c := range utf16.Encode([]rune(text)) { binary.LittleEndian.PutUint16(b[offset+i*2:], c) }
	}
	binary.LittleEndian.PutUint32(b[l.subEntry:], r.subEntry)
	binary.LittleEndian.PutUint32(b[l.flags:], r.flags)
	copy(b[l.guid:], r.guid[:]); copy(b[l.correlation:], r.correlation[:]); copy(b[l.luid:], r.luid[:])
	return b
}
func writeConnections(records []connectionRecord, buffer []uint32, size, count *uint32) uint32 {
	l, _ := rasConnectionLayout(int(unsafe.Sizeof(uintptr(0))))
	needed := uint32(len(records)*l.size)
	if *size < needed { *size = needed; return rasBufferTooSmall }
	for i, r := range records { copy(wordBytes(buffer)[i*l.size:], encodeConnection(r, l)) }
	*size, *count = needed, uint32(len(records))
	return 0
}
func fixedConnections(records ...connectionRecord) enumConnectionsFunc {
	return func(buffer []uint32, size, count *uint32) uint32 { return writeConnections(records, buffer, size, count) }
}
func changingConnections(before, after []connectionRecord) enumConnectionsFunc {
	successes := 0
	return func(buffer []uint32, size, count *uint32) uint32 {
		records := before; if successes != 0 { records = after }
		code := writeConnections(records, buffer, size, count)
		if code == 0 { successes++ }
		return code
	}
}
func fixtureStatus(_ uintptr, status *nativeConnectionStatus) uint32 {
	status.State = rasConnected
	putUTF16(status.DeviceType[:], "vpn")
	putUTF16(status.DeviceName[:], "WAN Miniport (L2TP)")
	putUTF16(status.PhoneNumber[:], "vpn.example.test")
	return 0
}
func unchangedEntry(EntryEvidence) error { return nil }

func TestConnectionSDKLayouts(t *testing.T) {
	for _, pointerBytes := range []int{4, 8} {
		l, ok := rasConnectionLayout(pointerBytes)
		if !ok || l.size != 1380+pointerBytes || l.name != 4+pointerBytes || l.phonebook != 810+pointerBytes || l.subEntry != 1332+pointerBytes || l.guid != 1336+pointerBytes || l.flags != 1352+pointerBytes || l.luid != 1356+pointerBytes || l.correlation != 1364+pointerBytes { t.Fatalf("packed pointer layout mismatch: %+v", l) }
		r := fixtureConnection()
		got, ok := decodeConnection(encodeConnection(r, l), l)
		if !ok || got != r { t.Fatalf("packed decode failed for %d-byte pointer", pointerBytes) }
	}
	if _, ok := rasConnectionLayout(16); ok { t.Fatal("unknown pointer width accepted") }
	var s nativeConnectionStatus
	if connectionStatusSize != 608 || unsafe.Offsetof(s.State) != 4 || unsafe.Offsetof(s.Error) != 8 || unsafe.Offsetof(s.DeviceType) != 12 || unsafe.Offsetof(s.DeviceName) != 46 || unsafe.Offsetof(s.PhoneNumber) != 304 || unsafe.Offsetof(s.Local) != 564 || unsafe.Offsetof(s.Remote) != 584 || unsafe.Offsetof(s.Substate) != 604 { t.Fatal("RASCONNSTATUSW SDK layout mismatch") }
}

func TestConnectionEnumerationBoundsAndDecode(t *testing.T) {
	one := fixtureConnection(); two := one; two.handle++
	calls := 0
	records, err := enumerateConnections(func(b []uint32, s, c *uint32) uint32 { calls++; l, _ := rasConnectionLayout(int(unsafe.Sizeof(uintptr(0)))); if b[0] != uint32(l.size) { t.Fatal("uninitialized ABI size") }; return writeConnections([]connectionRecord{one, two}, b, s, c) })
	if err != nil || calls != 2 || len(records) != 2 || records[1] != two { t.Fatalf("growth failed: %d, %v", calls, err) }
	for name, call := range map[string]enumConnectionsFunc{
		"API error": func([]uint32, *uint32, *uint32) uint32 { return 5 },
		"huge allocation": func(_ []uint32, s, _ *uint32) uint32 { *s = maxConnectionBuffer+1; return rasBufferTooSmall },
		"short allocation": func(_ []uint32, s, _ *uint32) uint32 { *s = 1; return rasBufferTooSmall },
		"malformed empty size": func(_ []uint32, s, c *uint32) uint32 { *s = 1; *c = 0; return 0 },
		"count beyond bytes": func(_ []uint32, s, c *uint32) uint32 { *s = 0; *c = 1; return 0 },
		"huge count": func(_ []uint32, _, c *uint32) uint32 { *c = maxConnectionCount+1; return 0 },
		"oversized success": func(_ []uint32, s, _ *uint32) uint32 { *s++; return 0 },
		"duplicate handle": fixedConnections(one, one),
		"nil": nil,
	} { t.Run(name, func(t *testing.T) { if _, err := enumerateConnections(call); err != ErrConnectionObservation { t.Fatal(err) } }) }
	calls = 0
	_, err = enumerateConnections(func(_ []uint32, s, _ *uint32) uint32 { calls++; *s += 4; return rasBufferTooSmall })
	if err != ErrConnectionObservation || calls != 3 { t.Fatalf("unbounded retry %d", calls) }
	l, _ := rasConnectionLayout(int(unsafe.Sizeof(uintptr(0))))
	for name, mutate := range map[string]func([]byte){
		"zero handle": func(b []byte) { clear(b[4:4+l.pointerBytes]) },
		"wrong size": func(b []byte) { binary.LittleEndian.PutUint32(b, 1) },
		"empty name": func(b []byte) { clear(b[l.name:l.name+514]) },
		"invalid UTF16": func(b []byte) { binary.LittleEndian.PutUint16(b[l.name:], 0xd800) },
		"unterminated path": func(b []byte) { for i:=0; i<260; i++ { binary.LittleEndian.PutUint16(b[l.phonebook+i*2:], 'a') } },
	} { t.Run(name, func(t *testing.T) { b := encodeConnection(one, l); mutate(b); if _, ok := decodeConnection(b, l); ok { t.Fatal("malformed connection accepted") } }) }
}

func TestConnectionObservationNeverAcquiresOwnership(t *testing.T) {
	e := fixtureEvidence(t)
	r := fixtureConnection(); r.flags = 0x0c // OwnerKnown/OwnerMatch is NOT process ownership.
	statusCalls, propertyCalls := 0, 0
	snapshot, err := observeConnections(e, fixedConnections(r), func(h uintptr, s *nativeConnectionStatus) uint32 {
		statusCalls++; if h != r.handle || s.Size != connectionStatusSize { t.Fatal("wrong observed handle/size") }; return fixtureStatus(h, s)
	}, func(got EntryEvidence) error { propertyCalls++; if got != e { t.Fatal("wrong profile snapshot") }; return nil })
	if err != nil || snapshot.ObservedConnections() != 1 || snapshot.DialBlocker() != ErrExistingConnection || statusCalls != 1 || propertyCalls != 2 { t.Fatalf("observation failed: %v", err) }
	statusCalls = 0
	empty, err := observeConnections(e, fixedConnections(), func(uintptr, *nativeConnectionStatus) uint32 { statusCalls++; return 0 }, unchangedEntry)
	if err != nil || empty.ObservedConnections() != 0 || empty.DialBlocker() != ErrExclusivityUnproven || statusCalls != 0 { t.Fatalf("empty observation became authorization: %v", err) }
	if (ConnectionSnapshot{}).DialBlocker() == nil { t.Fatal("zero snapshot permits dial") }
}

func TestConnectionObservationRejectsRaceAndReplacement(t *testing.T) {
	e := fixtureEvidence(t); r := fixtureConnection()
	for name, mutate := range map[string]func(*connectionRecord){
		"reused handle new correlation": func(r *connectionRecord) { r.correlation[0]++ },
		"different handle": func(r *connectionRecord) { r.handle++ },
		"different logon": func(r *connectionRecord) { r.luid[0]++ },
		"different GUID": func(r *connectionRecord) { r.guid[0]++ },
		"renamed entry": func(r *connectionRecord) { r.name += " new" },
		"different phonebook": func(r *connectionRecord) { r.phonebook = `C:\other.pbk` },
		"device changed": func(r *connectionRecord) { r.deviceName += " new" },
		"flags changed": func(r *connectionRecord) { r.flags = 1 },
	} { t.Run(name, func(t *testing.T) { changed := r; mutate(&changed); _, err := observeConnections(e, changingConnections([]connectionRecord{r}, []connectionRecord{changed}), fixtureStatus, unchangedEntry); if err != ErrConnectionObservation { t.Fatalf("race accepted: %v", err) } }) }
	for _, pair := range [][2][]connectionRecord{{{r}, {}}, {{}, {r}}} {
		if _, err := observeConnections(e, changingConnections(pair[0], pair[1]), fixtureStatus, unchangedEntry); err != ErrConnectionObservation { t.Fatal("appearance/disappearance accepted") }
	}
	for failureCall := 1; failureCall <= 2; failureCall++ {
		calls := 0
		_, err := observeConnections(e, fixedConnections(r), fixtureStatus, func(EntryEvidence) error { calls++; if calls == failureCall { return ErrEntryProperties }; return nil })
		if err != ErrConnectionObservation { t.Fatal("profile drift accepted") }
	}
}

func TestConnectionStatusChecksBothErrorsAndIdentity(t *testing.T) {
	for name, mutate := range map[string]func(*nativeConnectionStatus) uint32{
		"API failure": func(*nativeConnectionStatus) uint32 { return 6 },
		"connection error": func(s *nativeConnectionStatus) uint32 { s.Error = 691; return 0 },
		"disconnected": func(s *nativeConnectionStatus) uint32 { s.State = 0x2001; return 0 },
		"unknown state": func(s *nativeConnectionStatus) uint32 { s.State = 0xfeed; return 0 },
		"wrong size": func(s *nativeConnectionStatus) uint32 { s.Size--; return 0 },
		"wrong device": func(s *nativeConnectionStatus) uint32 { s.DeviceType[0] = 'x'; return 0 },
		"wrong device name": func(s *nativeConnectionStatus) uint32 { s.DeviceName[0] = 'x'; return 0 },
		"wrong target": func(s *nativeConnectionStatus) uint32 { s.PhoneNumber[0] = 'x'; return 0 },
		"invalid UTF16": func(s *nativeConnectionStatus) uint32 { s.PhoneNumber[0] = 0xd800; return 0 },
	} { t.Run(name, func(t *testing.T) { _, err := observeConnections(fixtureEvidence(t), fixedConnections(fixtureConnection()), func(h uintptr, s *nativeConnectionStatus) uint32 { fixtureStatus(h, s); return mutate(s) }, unchangedEntry); if err != ErrConnectionObservation { t.Fatalf("bad status accepted: %v", err) } }) }
}

func TestConnectionSelectionRejectsAmbiguity(t *testing.T) {
	e := fixtureEvidence(t)
	for name, mutate := range map[string]func(*connectionRecord){
		"same entry wrong GUID": func(r *connectionRecord) { r.guid[0]++ },
		"same GUID wrong path": func(r *connectionRecord) { r.phonebook = `C:\other.pbk` },
		"same GUID wrong name": func(r *connectionRecord) { r.name = "Other" },
		"missing GUID": func(r *connectionRecord) { r.guid = [16]byte{} },
		"missing path": func(r *connectionRecord) { r.phonebook = ""; r.guid = [16]byte{} },
		"missing correlation": func(r *connectionRecord) { r.correlation = [16]byte{} },
		"unsupported device": func(r *connectionRecord) { r.deviceType = "modem" },
		"multilink": func(r *connectionRecord) { r.subEntry = 2 },
		"unknown scope flags": func(r *connectionRecord) { r.flags = 0x1000 },
	} { t.Run(name, func(t *testing.T) { r := fixtureConnection(); mutate(&r); if _, err := observeConnections(e, fixedConnections(r), fixtureStatus, unchangedEntry); err != ErrConnectionObservation { t.Fatal("ambiguous identity accepted") } }) }
	other := fixtureConnection(); other.phonebook = `C:\other.pbk`; other.guid[0]++
	s, err := observeConnections(e, fixedConnections(other), func(uintptr, *nativeConnectionStatus) uint32 { t.Fatal("queried unrelated connection"); return 0 }, unchangedEntry)
	if err != nil || s.ObservedConnections() != 0 || s.DialBlocker() == nil { t.Fatal("confused distinct phonebooks or permitted dial") }
	if _, err := observeConnections(EntryEvidence{}, fixedConnections(), fixtureStatus, unchangedEntry); err != ErrConnectionObservation { t.Fatal("zero profile evidence accepted") }
}

func TestConnectionObservationFailuresStayBlocked(t *testing.T) {
	e := fixtureEvidence(t)
	for name, run := range map[string]func() (ConnectionSnapshot, error){
		"nil enumeration": func() (ConnectionSnapshot, error) { return observeConnections(e, nil, fixtureStatus, unchangedEntry) },
		"nil status": func() (ConnectionSnapshot, error) { return observeConnections(e, fixedConnections(), nil, unchangedEntry) },
		"nil revalidation": func() (ConnectionSnapshot, error) { return observeConnections(e, fixedConnections(), fixtureStatus, nil) },
		"enumeration error": func() (ConnectionSnapshot, error) { return observeConnections(e, func([]uint32, *uint32, *uint32) uint32 { return 5 }, fixtureStatus, unchangedEntry) },
		"second enumeration error": func() (ConnectionSnapshot, error) {
			calls := 0
			return observeConnections(e, func(b []uint32, s, c *uint32) uint32 { calls++; if calls == 2 { return 6 }; return writeConnections(nil, b, s, c) }, fixtureStatus, unchangedEntry)
		},
	} { t.Run(name, func(t *testing.T) { s, err := run(); if err != ErrConnectionObservation || s.DialBlocker() == nil { t.Fatal("failed observation allowed dial") } }) }
	tooMany := make([]connectionRecord, maxSelectedConnections+1)
	for i := range tooMany { tooMany[i] = fixtureConnection(); tooMany[i].handle += uintptr(i); tooMany[i].correlation[0] += byte(i) }
	if _, err := observeConnections(e, fixedConnections(tooMany...), func(uintptr, *nativeConnectionStatus) uint32 { t.Fatal("queried unbounded selected list"); return 0 }, unchangedEntry); err != ErrConnectionObservation { t.Fatal("too many selected handles accepted") }
}

func TestConnectionOrderDoesNotPretendOwnership(t *testing.T) {
	e := fixtureEvidence(t)
	one := fixtureConnection(); two := one; two.handle++; two.correlation[0]++
	s, err := observeConnections(e, changingConnections([]connectionRecord{one, two}, []connectionRecord{two, one}), fixtureStatus, unchangedEntry)
	if err != nil || s.ObservedConnections() != 2 || s.DialBlocker() != ErrExistingConnection { t.Fatalf("stable reordered list failed: %v", err) }
}
