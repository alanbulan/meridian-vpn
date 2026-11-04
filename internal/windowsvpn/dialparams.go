package windowsvpn

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

// RASDIALPARAMSW uses four-byte SDK packing, including its pointer-sized tail.
// Use word storage, not a Go struct whose uintptr fields have x64 alignment.
// These offsets include the Windows 8+ szEncPassword pointer, always NULL here.
type dialParameterLayout struct {
	size, entry, phone, callbackNumber, username, password, domain int
	subEntry, callbackID, interfaceIndex, encryptedPassword int
}

func rasDialParameterLayout(pointerBytes int) (dialParameterLayout, bool) {
	if pointerBytes != 4 && pointerBytes != 8 {
		return dialParameterLayout{}, false
	}
	return dialParameterLayout{
		size: 2104 + 2*pointerBytes,
		entry: 4, phone: 518, callbackNumber: 776,
		username: 1034, password: 1548, domain: 2062,
		subEntry: 2096, callbackID: 2100,
		interfaceIndex: 2100 + pointerBytes, encryptedPassword: 2104 + pointerBytes,
	}, true
}

// withDialParameters is an offline, unexported marshalling boundary, not a
// dialer or permission to dial. The injected consumer borrows both buffers and
// MUST finish all uses before returning or panicking. It must not retain/copy
// credentials, invoke async native consumers or pass these buffers to RasDial.
// A real async driver needs independently proven native-buffer/callback lifetime
// management; return from RasDial alone is NOT a release point for its inputs.
//
// All owned storage is erased on return, error or panic. This is best-effort
// memory hygiene, not a guarantee against copies, swapping or crash dumps.
// No credentials are read from Windows, no PSK is accepted, and no OS API loads.
// The domain may be empty (server domain), but "*" (phonebook domain) is refused.
// Phone/callback overrides, subentry, callback ID, interface and encrypted-password
// pointer remain zero. The selected entry's phone number would be used by RAS;
// a future caller must separately validate/revalidate that profile and target.
func withDialParameters(entry PhonebookEntry, username, domain string, password []byte, consume func([]uint16, []uint32) error) error {
	layout, ok := rasDialParameterLayout(int(unsafe.Sizeof(uintptr(0))))
	if !ok || consume == nil || !validSelection(entry) ||
		len(username) > 1024 || !validText(username, 256) ||
		len(domain) > 60 || domain == "*" || (domain != "" && !validText(domain, 15)) ||
		len(password) == 0 || len(password) > 1024 || !utf8.Valid(password) ||
		bytes.ContainsAny(password, "\x00\r\n") || secretUnits(password) > 256 {
		return ErrOperation
	}
	parameters := make([]uint32, layout.size/4)
	phonebook := make([]uint16, 0, len(entry.PhonebookPath)+1)
	for _, r := range entry.PhonebookPath {
		phonebook = utf16.AppendRune(phonebook, r)
	}
	phonebook = append(phonebook, 0)
	defer func() {
		clear(parameters)
		clear(phonebook)
		runtime.KeepAlive(parameters)
		runtime.KeepAlive(phonebook)
	}()
	parameters[0] = uint32(layout.size)
	buffer := wordBytes(parameters)
	writeDialUTF16(buffer[layout.entry:layout.phone], []byte(entry.Name))
	writeDialUTF16(buffer[layout.username:layout.password], []byte(username))
	writeDialUTF16(buffer[layout.password:layout.domain], password)
	writeDialUTF16(buffer[layout.domain:layout.subEntry], []byte(domain))
	if consume(phonebook, parameters) != nil {
		// Native or injected errors must not leak credentials or local paths.
		return ErrOperation
	}
	return nil
}

// Inputs are validated and the destination zeroed before encoding. Password
// bytes are decoded directly: no immutable string or temporary rune/UTF-16 copy.
func writeDialUTF16(destination, value []byte) {
	offset := 0
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		value = value[size:]
		if r <= 0xffff {
			binary.LittleEndian.PutUint16(destination[offset:], uint16(r))
			offset += 2
		} else {
			hi, lo := utf16.EncodeRune(r)
			binary.LittleEndian.PutUint16(destination[offset:], uint16(hi))
			binary.LittleEndian.PutUint16(destination[offset+2:], uint16(lo))
			offset += 4
		}
	}
}
