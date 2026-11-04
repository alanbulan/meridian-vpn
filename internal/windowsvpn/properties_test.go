package windowsvpn

import (
	"testing"
	"unicode/utf16"
	"unsafe"
)

func putUTF16(dst []uint16, value string) { copy(dst, utf16.Encode([]rune(value))) }
func fixtureEntry() PhonebookEntry { return PhonebookEntry{Name: "Selected VPN", PhonebookPath: `C:\Users\fixture\rasphone.pbk`} }
func fixtureProperties() nativeEntryProperties {
	raw := nativeEntryProperties{Size: entryPropertiesSize, Type: 2, VPNStrategy: 3, FramingProtocol: 1, NetProtocols: 4, Options: 0x20000000, Options2: 0x10, EncryptionType: 1}
	putUTF16(raw.DeviceType[:], "vpn")
	putUTF16(raw.LocalPhoneNumber[:], "vpn.example.test")
	raw.GUID[0] = 1
	return raw
}
func propertiesReader(raw nativeEntryProperties) getEntryPropertiesFunc {
	return func(_ PhonebookEntry, buffer []uint32, size *uint32) uint32 {
		*(*nativeEntryProperties)(unsafe.Pointer(&buffer[0])) = raw
		*size = entryPropertiesSize
		return 0
	}
}

func TestEntryPropertiesSDKLayout(t *testing.T) {
	var raw nativeEntryProperties
	if entryPropertiesSize != 6724 { t.Fatalf("RASENTRYW size %d", entryPropertiesSize) }
	for name, pair := range map[string][2]uintptr{
		"Options": {unsafe.Offsetof(raw.Options), 4}, "Gateway": {unsafe.Offsetof(raw.LocalPhoneNumber), 38},
		"Alternates": {unsafe.Offsetof(raw.AlternateOffset), 296}, "Framing": {unsafe.Offsetof(raw.FramingProtocol), 328},
		"Script": {unsafe.Offsetof(raw.Script), 332}, "AutodialDLL": {unsafe.Offsetof(raw.AutodialDLL), 852},
		"AutodialFunc": {unsafe.Offsetof(raw.AutodialFunc), 1372}, "Device": {unsafe.Offsetof(raw.DeviceType), 1892},
		"SubEntries": {unsafe.Offsetof(raw.SubEntries), 3468}, "Type": {unsafe.Offsetof(raw.Type), 3496},
		"Encryption": {unsafe.Offsetof(raw.EncryptionType), 3500}, "CustomAuth": {unsafe.Offsetof(raw.CustomAuthKey), 3504},
		"GUID": {unsafe.Offsetof(raw.GUID), 3508}, "CustomDialDLL": {unsafe.Offsetof(raw.CustomDialDLL), 3524},
		"VPNStrategy": {unsafe.Offsetof(raw.VPNStrategy), 4044}, "Options2": {unsafe.Offsetof(raw.Options2), 4048},
		"Options3": {unsafe.Offsetof(raw.Options3), 4052}, "PrerequisitePBK": {unsafe.Offsetof(raw.PrerequisitePBK), 4572},
		"PrerequisiteEntry": {unsafe.Offsetof(raw.PrerequisiteEntry), 5092}, "IDi": {unsafe.Offsetof(raw.IDi), 5680},
		"IDr": {unsafe.Offsetof(raw.IDr), 6194}, "IMS": {unsafe.Offsetof(raw.IsIMSConfig), 6708},
		"Last": {unsafe.Offsetof(raw.DisableIKEv2Fragmentation), 6720},
	} { if pair[0] != pair[1] { t.Errorf("%s offset %d, want %d", name, pair[0], pair[1]) } }
}

func TestEntryPropertiesExactSelectionAndSnapshot(t *testing.T) {
	entry := fixtureEntry()
	raw := fixtureProperties()
	calls := 0
	evidence, err := inspectEntryProperties(func(got PhonebookEntry, buffer []uint32, size *uint32) uint32 {
		calls++
		if got != entry || buffer[0] != entryPropertiesSize || *size != entryPropertiesSize { t.Fatal("wrong explicit entry or initialized size") }
		return propertiesReader(raw)(got, buffer, size)
	}, entry, "VPN.EXAMPLE.TEST")
	if err != nil || calls != 1 || evidence.Entry() != entry || evidence.Gateway() != "vpn.example.test" { t.Fatalf("inspection failed: %v", err) }
	if err := revalidateEntryProperties(propertiesReader(raw), evidence); err != nil { t.Fatal(err) }
	for name, mutate := range map[string]func(*nativeEntryProperties){
		"replacement GUID": func(r *nativeEntryProperties) { r.GUID[0]++ },
		"DNS": func(r *nativeEntryProperties) { r.DNS[0]++ },
		"route": func(r *nativeEntryProperties) { r.Options |= 0x10 },
		"metric": func(r *nativeEntryProperties) { r.IPv4InterfaceMetric++ },
	} { t.Run(name, func(t *testing.T) { changed := raw; mutate(&changed); if revalidateEntryProperties(propertiesReader(changed), evidence) == nil { t.Fatal("changed profile accepted") } }) }
	if revalidateEntryProperties(propertiesReader(raw), EntryEvidence{}) == nil { t.Fatal("zero evidence accepted") }
}

func TestEntryPropertiesRejectsUnsafeOrAmbiguousProfiles(t *testing.T) {
	for name, mutate := range map[string]func(*nativeEntryProperties){
		"wrong ABI": func(r *nativeEntryProperties) { r.Size-- },
		"not VPN": func(r *nativeEntryProperties) { r.Type = 1 },
		"modem": func(r *nativeEntryProperties) { r.DeviceType = [17]uint16{}; putUTF16(r.DeviceType[:], "modem") },
		"fallback protocol": func(r *nativeEntryProperties) { r.VPNStrategy = 4 },
		"automatic protocol": func(r *nativeEntryProperties) { r.VPNStrategy = 0 },
		"no MSCHAP2": func(r *nativeEntryProperties) { r.Options = 0 },
		"weaker auth": func(r *nativeEntryProperties) { r.Options |= 0x00040000 },
		"broad auth": func(r *nativeEntryProperties) { r.Options |= 0x00000400 },
		"logon credentials": func(r *nativeEntryProperties) { r.Options |= 0x4000 },
		"custom script flag": func(r *nativeEntryProperties) { r.Options |= 0x80000000 },
		"credential cache": func(r *nativeEntryProperties) { r.Options2 |= 0x02000000 },
		"auto reconnect": func(r *nativeEntryProperties) { r.Options2 |= 0x100 },
		"no PSK mode": func(r *nativeEntryProperties) { r.Options2 = 0 },
		"unknown options": func(r *nativeEntryProperties) { r.Options3 = 1 },
		"optional encryption": func(r *nativeEntryProperties) { r.EncryptionType = 3 },
		"missing GUID": func(r *nativeEntryProperties) { r.GUID = [16]byte{} },
		"alternates": func(r *nativeEntryProperties) { r.AlternateOffset = entryPropertiesSize },
		"multilink": func(r *nativeEntryProperties) { r.SubEntries = 2 },
		"custom auth": func(r *nativeEntryProperties) { r.CustomAuthKey = 1 },
		"script": func(r *nativeEntryProperties) { r.Script[0] = 'x' },
		"custom dialer": func(r *nativeEntryProperties) { r.CustomDialDLL[0] = 'x' },
		"prerequisite": func(r *nativeEntryProperties) { r.PrerequisiteEntry[0] = 'x' },
		"hidden dialer": func(r *nativeEntryProperties) { r.CustomDialDLL[20] = 'x' },
		"invalid UTF16": func(r *nativeEntryProperties) { r.LocalPhoneNumber[0] = 0xd800 },
		"unterminated target": func(r *nativeEntryProperties) { for i := range r.LocalPhoneNumber { r.LocalPhoneNumber[i] = 'a' } },
		"different target": func(r *nativeEntryProperties) { r.LocalPhoneNumber[0] = 'x' },
		"unknown framing": func(r *nativeEntryProperties) { r.FramingProtocol = 2 },
		"unknown network protocol": func(r *nativeEntryProperties) { r.NetProtocols |= 2 },
	} { t.Run(name, func(t *testing.T) { raw := fixtureProperties(); mutate(&raw); if _, err := inspectEntryProperties(propertiesReader(raw), fixtureEntry(), "vpn.example.test"); err != ErrEntryProperties { t.Fatalf("unsafe entry returned %v", err) } }) }
}

func TestEntryPropertiesBoundsAndErrors(t *testing.T) {
	for name, call := range map[string]getEntryPropertiesFunc{
		"API error": func(PhonebookEntry, []uint32, *uint32) uint32 { return 623 },
		"short success": func(_ PhonebookEntry, _ []uint32, size *uint32) uint32 { *size = 0; return 0 },
		"oversized success": func(_ PhonebookEntry, _ []uint32, size *uint32) uint32 { *size++; return 0 },
		"oversized retry": func(_ PhonebookEntry, _ []uint32, size *uint32) uint32 { *size = maxPropertiesBuffer + 1; return rasBufferTooSmall },
		"short retry": func(_ PhonebookEntry, _ []uint32, size *uint32) uint32 { *size = 1; return rasBufferTooSmall },
		"nil": nil,
	} { t.Run(name, func(t *testing.T) { if _, err := inspectEntryProperties(call, fixtureEntry(), "vpn.example.test"); err != ErrEntryProperties { t.Fatal(err) } }) }
	calls := 0
	_, err := inspectEntryProperties(func(_ PhonebookEntry, _ []uint32, size *uint32) uint32 { calls++; *size += 4; return rasBufferTooSmall }, fixtureEntry(), "vpn.example.test")
	if err != ErrEntryProperties || calls != 3 { t.Fatalf("unbounded retry: %d, %v", calls, err) }
	calls = 0
	_, err = inspectEntryProperties(func(e PhonebookEntry, b []uint32, s *uint32) uint32 { calls++; if calls == 1 { *s += 8; return rasBufferTooSmall }; return propertiesReader(fixtureProperties())(e, b, s) }, fixtureEntry(), "vpn.example.test")
	if err != nil || calls != 2 { t.Fatalf("bounded growth failed: %d, %v", calls, err) }
}

func TestEntryPropertiesRejectsInputsBeforeNativeCall(t *testing.T) {
	for _, path := range []string{"", `rasphone.pbk`, `C:rasphone.pbk`, `\\server\share\rasphone.pbk`, `\\?\C:\rasphone.pbk`, `C:\..\rasphone.pbk`, `C:\folder.\rasphone.pbk`, `C:\folder \rasphone.pbk`, `C:\rasphone.pbk:stream`, `C:\x\`, `C:\x.txt`, `C:\x\a\..\rasphone.pbk`} {
		entry := fixtureEntry(); entry.PhonebookPath = path
		_, err := inspectEntryProperties(func(PhonebookEntry, []uint32, *uint32) uint32 { t.Fatal("native call for rejected path"); return 0 }, entry, "vpn.example.test")
		if err != ErrEntryProperties { t.Fatalf("accepted invalid selection %q", path) }
	}
	for _, gateway := range []string{"", "vpn.example.test/path", "https://vpn.example.test", "vpn.example.test:443", "vpn\x00.example.test", "127.0.0.1", "::", "224.0.0.1", "127.1", "2130706433", "0177.0.0.1", "0x7f000001", "0x7f.0.0.1", "127.1."} {
		if _, err := inspectEntryProperties(func(PhonebookEntry, []uint32, *uint32) uint32 { t.Fatal("native call for rejected target"); return 0 }, fixtureEntry(), gateway); err != ErrEntryProperties { t.Fatalf("accepted invalid target %q", gateway) }
	}
	entry := fixtureEntry(); entry.Name = ""
	if _, err := inspectEntryProperties(propertiesReader(fixtureProperties()), entry, "vpn.example.test"); err != ErrEntryProperties { t.Fatal("default entry accepted") }
}


func TestEntryPropertiesPreservesAbsoluteDNSName(t *testing.T) {
	if _, err := inspectEntryProperties(propertiesReader(fixtureProperties()), fixtureEntry(), "vpn.example.test."); err != ErrEntryProperties { t.Fatal("absolute and search-relative DNS names conflated") }
	raw := fixtureProperties()
	raw.LocalPhoneNumber = [129]uint16{}
	putUTF16(raw.LocalPhoneNumber[:], "VPN.EXAMPLE.TEST.")
	if _, err := inspectEntryProperties(propertiesReader(raw), fixtureEntry(), "vpn.example.test."); err != nil { t.Fatal(err) }
}

func TestPhonebookPathRejectsReparseAndWrongTypes(t *testing.T) {
	path := fixtureEntry().PhonebookPath
	want := []string{`C:\`, `C:\Users`, `C:\Users\fixture`, path}
	for rejected := -1; rejected < len(want); rejected++ {
		calls := 0
		ok := checkPhonebookPath(path, func(got string) (uint32, error) {
			if calls >= len(want) || got != want[calls] { t.Fatalf("wrong component %q", got) }
			i := calls; calls++
			if i == rejected { return 0x400, nil }
			if i < len(want)-1 { return 0x10, nil }
			return 0, nil
		})
		if ok != (rejected == -1) { t.Fatalf("reparse point %d accepted", rejected) }
	}
	if checkPhonebookPath(path, func(string) (uint32, error) { return 0, nil }) { t.Fatal("non-directory ancestor accepted") }
	if checkPhonebookPath(path, func(string) (uint32, error) { return 0x10, nil }) { t.Fatal("directory phonebook accepted") }
	if checkPhonebookPath(path, func(string) (uint32, error) { return 0, ErrEntryProperties }) { t.Fatal("attribute failure accepted") }
}


func TestEntryPropertiesRequiresEncryption(t *testing.T) {
	for _, encryption := range []uint32{0, 1, 2, 3, 4} {
		raw := fixtureProperties(); raw.EncryptionType = encryption
		_, err := inspectEntryProperties(propertiesReader(raw), fixtureEntry(), "vpn.example.test")
		if (err == nil) != (encryption == 1 || encryption == 2) { t.Fatalf("wrong encryption classification %d", encryption) }
	}
}
