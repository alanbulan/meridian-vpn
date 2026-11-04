package windowsvpn

import (
	"strings"
	"testing"
)

func TestPhonebookDeviceAliasesRejectedBeforeNativeRead(t *testing.T) {
	names := []string{"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
	for _, prefix := range []string{"COM", "LPT"} {
		for _, digit := range "123456789¹²³" {
			names = append(names, prefix+string(digit))
		}
	}
	for _, name := range names {
		for _, variant := range []string{name, strings.ToLower(name), name + ".extra", name + " "} {
			for _, path := range []string{`C:\` + variant + `.pbk`, `C:\` + variant + `\rasphone.pbk`} {
				assertPhonebookRejectedBeforeRead(t, path)
			}
		}
	}
}

func TestPhonebookControlCharactersRejectedBeforeNativeRead(t *testing.T) {
	for c := rune(0); c < 32; c++ {
		for _, path := range []string{`C:\profile` + string(c) + `.pbk`, `C:\folder` + string(c) + `\rasphone.pbk`} {
			assertPhonebookRejectedBeforeRead(t, path)
		}
	}
}

func assertPhonebookRejectedBeforeRead(t *testing.T, path string) {
	t.Helper()
	entry := fixtureEntry()
	entry.PhonebookPath = path
	_, err := inspectEntryProperties(func(PhonebookEntry, []uint32, *uint32) uint32 {
		t.Fatalf("native read attempted for invalid path %q", path)
		return 0
	}, entry, "vpn.example.test")
	if err != ErrEntryProperties {
		t.Fatalf("invalid phonebook path %q returned %v", path, err)
	}
}

func TestPhonebookOrdinaryNamesRemainSupported(t *testing.T) {
	for _, path := range []string{
		`C:\Users\VPN User\rasphone.pbk`,
		`d:\用户\.profiles\办公室.PBK`,
		`C:\console\auxiliary.pbk`,
		`C:\COM10\LPT0.pbk`,
		`C:\COM1-profile\NUL-backup.pbk`,
		`C:\COM⁴\LPT²-backup.pbk`,
	} {
		entry := fixtureEntry()
		entry.PhonebookPath = path
		evidence, err := inspectEntryProperties(propertiesReader(fixtureProperties()), entry, "vpn.example.test")
		if err != nil || evidence.Entry() != entry {
			t.Fatalf("ordinary path %q rejected or rewritten: %v", path, err)
		}
	}
}
