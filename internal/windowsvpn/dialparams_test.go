package windowsvpn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"
)

func TestDialParameterSDKLayout(t *testing.T) {
	for _, pointerBytes := range []int{4, 8} {
		layout, ok := rasDialParameterLayout(pointerBytes)
		if !ok || layout.entry != 4 || layout.phone != 518 || layout.callbackNumber != 776 ||
			layout.username != 1034 || layout.password != 1548 || layout.domain != 2062 ||
			layout.subEntry != 2096 || layout.callbackID != 2100 ||
			layout.interfaceIndex != 2100+pointerBytes || layout.encryptedPassword != 2104+pointerBytes ||
			layout.size != 2104+2*pointerBytes {
			t.Fatal("RASDIALPARAMSW layout differs from SDK assertion contract")
		}
	}
	for _, pointerBytes := range []int{0, 1, 16} {
		if _, ok := rasDialParameterLayout(pointerBytes); ok {
			t.Fatal("unsupported architecture accepted")
		}
	}
}

func TestDialParametersExactIdentityAndZeroDefaults(t *testing.T) {
	entry := fixtureEntry()
	entry.Name = "VPN 办公室 🛰"
	username, domain := "用户🛰", "域"
	password := []byte("test-only-密码🛰")
	original := bytes.Clone(password)
	layout, _ := rasDialParameterLayout(int(unsafe.Sizeof(uintptr(0))))
	err := withDialParameters(entry, username, domain, password, func(phonebook []uint16, parameters []uint32) error {
		if len(parameters)*4 != layout.size || parameters[0] != uint32(layout.size) {
			t.Fatal("wrong size or ABI version")
		}
		if got, ok := fixedUTF16(phonebook); !ok || got != entry.PhonebookPath {
			t.Fatal("phonebook changed or defaulted")
		}
		buffer := wordBytes(parameters)
		for _, field := range []struct{ start, count int; want string }{
			{layout.entry, 257, entry.Name}, {layout.username, 257, username},
			{layout.domain, 16, domain}, {layout.phone, 129, ""}, {layout.callbackNumber, 129, ""},
		} {
			got, ok := connectionUTF16(buffer, field.start, field.count)
			if !ok || got != field.want { t.Fatal("identity or forbidden override changed") }
		}
		// Synthetic test secret only; compare code units without logging them.
		want := utf16.Encode([]rune("test-only-密码🛰"))
		for i, unit := range want {
			if binary.LittleEndian.Uint16(buffer[layout.password+2*i:]) != unit { t.Fatal("password encoding mismatch") }
		}
		for _, b := range buffer[layout.password+2*len(want):layout.domain] {
			if b != 0 { t.Fatal("password is not zero terminated/padded") }
		}
		for _, b := range buffer[layout.domain+32:] {
			if b != 0 { t.Fatal("padding, callback ID, subentry, interface or encrypted pointer set") }
		}
		return nil
	})
	if err != nil || !bytes.Equal(password, original) { t.Fatal("marshalling failed or caller password changed") }
}

func TestDialParametersEraseBorrowedStorageOnEveryExit(t *testing.T) {
	for _, mode := range []string{"success", "error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			var retainedParameters []uint32
			var retainedPhonebook []uint16
			password := []byte("synthetic-secret")
			func() {
				defer func() {
					got := recover()
					if (got != nil) != (mode == "panic") { t.Fatal("unexpected panic behavior") }
				}()
				err := withDialParameters(fixtureEntry(), "fixture-user", "", password, func(p []uint16, b []uint32) error {
					// Deliberately retain test aliases solely to verify destruction.
					retainedPhonebook, retainedParameters = p, b
					if mode == "panic" { panic("synthetic consumer panic") }
					if mode == "error" { return errors.New("synthetic private detail") }
					return nil
				})
				if mode == "error" && err != ErrOperation { t.Fatal("consumer error was not redacted") }
				if mode == "success" && err != nil { t.Fatal(err) }
			}()
			if len(retainedParameters) == 0 || len(retainedPhonebook) == 0 { t.Fatal("consumer was not exercised") }
			for _, v := range retainedParameters { if v != 0 { t.Fatal("dial parameter memory survived exit") } }
			for _, v := range retainedPhonebook { if v != 0 { t.Fatal("phonebook memory survived exit") } }
			if !bytes.Equal(password, []byte("synthetic-secret")) { t.Fatal("caller-owned secret erased") }
		})
	}
}

func TestDialParametersRejectInputsBeforeConsumer(t *testing.T) {
	for _, tc := range []struct{ name, username, domain string; password []byte; entry PhonebookEntry }{
		{"empty user", "", "", []byte("x"), fixtureEntry()},
		{"oversized user", strings.Repeat("x", 257), "", []byte("x"), fixtureEntry()},
		{"invalid user UTF8", "\xff", "", []byte("x"), fixtureEntry()},
		{"user NUL", "a\x00b", "", []byte("x"), fixtureEntry()},
		{"saved domain", "user", "*", []byte("x"), fixtureEntry()},
		{"oversized domain", "user", strings.Repeat("x", 16), []byte("x"), fixtureEntry()},
		{"domain newline", "user", "a\nb", []byte("x"), fixtureEntry()},
		{"empty password", "user", "", nil, fixtureEntry()},
		{"oversized password", "user", "", bytes.Repeat([]byte("x"), 257), fixtureEntry()},
		{"surrogate overflow", "user", "", []byte(strings.Repeat("🛰", 129)), fixtureEntry()},
		{"invalid secret UTF8", "user", "", []byte{0xff}, fixtureEntry()},
		{"secret NUL", "user", "", []byte("a\x00b"), fixtureEntry()},
		{"secret newline", "user", "", []byte("a\nb"), fixtureEntry()},
		{"default entry", "user", "", []byte("x"), PhonebookEntry{}},
		{"default phonebook", "user", "", []byte("x"), PhonebookEntry{Name: "VPN"}},
		{"device phonebook", "user", "", []byte("x"), PhonebookEntry{Name: "VPN", PhonebookPath: `C:\NUL.pbk`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if withDialParameters(tc.entry, tc.username, tc.domain, tc.password, func([]uint16, []uint32) error {
				t.Fatal("invalid input reached consumer"); return nil
			}) != ErrOperation { t.Fatal("invalid input accepted") }
		})
	}
	if withDialParameters(fixtureEntry(), "user", "", []byte("x"), nil) != ErrOperation { t.Fatal("nil consumer accepted") }
}

func TestDialParametersMaximumUTF16Lengths(t *testing.T) {
	for _, password := range [][]byte{bytes.Repeat([]byte("x"), 256), []byte(strings.Repeat("🛰", 128))} {
		entry := fixtureEntry()
		entry.Name = strings.Repeat("n", 256)
		if err := withDialParameters(entry, strings.Repeat("u", 256), strings.Repeat("d", 15), password, func(_ []uint16, p []uint32) error {
			layout, _ := rasDialParameterLayout(int(unsafe.Sizeof(uintptr(0))))
			b := wordBytes(p)
			for _, offset := range []int{layout.entry+512, layout.username+512, layout.password+512, layout.domain+30} {
				if binary.LittleEndian.Uint16(b[offset:]) != 0 { t.Fatal("maximum field lacks terminator") }
			}
			return nil
		}); err != nil { t.Fatal(err) }
	}
}
