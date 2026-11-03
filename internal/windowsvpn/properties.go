package windowsvpn

import (
	"errors"
	"net"
	"strings"
	"unsafe"
)

var ErrEntryProperties = errors.New("Windows RAS entry properties are unavailable or unsupported")

// EntryEvidence is an opaque, read-only snapshot of a selected, existing
// L2TP/PSK/MSCHAPv2 profile. It grants no ownership, connection permission or
// guarantee of IPsec, credential persistence, route/DNS safety or readiness.
// Never use it with the owned-entry Controller or delete its selected profile.
// Its contents may identify a person or organization; do not log or persist it.
type EntryEvidence struct {
	entry PhonebookEntry
	gateway string
	properties nativeEntryProperties
}

func (e EntryEvidence) Entry() PhonebookEntry { return e.entry }
func (e EntryEvidence) Gateway() string { return e.gateway }

// nativeEntryProperties mirrors pointer-free RASENTRYW for WINVER=0x0a00,
// with the SDK's four-byte packing. CI checks its layout against Windows SDK
// ras.h, not just a second Go declaration. No credentials are present.
type nativeEntryProperties struct {
	Size, Options, CountryID, CountryCode uint32
	AreaCode [11]uint16
	LocalPhoneNumber [129]uint16
	AlternateOffset uint32
	IP, DNS, DNSAlt, WINS, WINSAlt [4]byte
	FrameSize, NetProtocols, FramingProtocol uint32
	Script, AutodialDLL, AutodialFunc [260]uint16
	DeviceType [17]uint16
	DeviceName [129]uint16
	X25PadType [33]uint16
	X25Address, X25Facilities, X25UserData [201]uint16
	Channels, Reserved1, Reserved2 uint32
	SubEntries, DialMode, DialExtraPercent, DialExtraSampleSeconds uint32
	HangUpExtraPercent, HangUpExtraSampleSeconds, IdleDisconnectSeconds uint32
	Type, EncryptionType, CustomAuthKey uint32
	GUID [16]byte
	CustomDialDLL [260]uint16
	VPNStrategy, Options2, Options3 uint32
	DNSSuffix [256]uint16
	TCPWindowSize uint32
	PrerequisitePBK [260]uint16
	PrerequisiteEntry [257]uint16
	RedialCount, RedialPause uint32
	IPv6DNS, IPv6DNSAlt [16]byte
	IPv4InterfaceMetric, IPv6InterfaceMetric uint32
	IPv6Address [16]byte
	IPv6PrefixLength, NetworkOutageTime uint32
	IDi, IDr [257]uint16
	IsIMSConfig, IDiType, IDrType, DisableIKEv2Fragmentation uint32
}

const (
	entryPropertiesSize = uint32(unsafe.Sizeof(nativeEntryProperties{}))
	maxPropertiesBuffer = uint32(1024 * 1024)
	// Explicit allowlists: ambiguous authentication, custom behavior, logon
	// credentials, credential caching, automatic reconnection and new/unknown
	// options are rejected rather than silently accepted.
	allowedOptions = uint32(0x20000000 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000100 | 0x00000200 | 0x00010000 | 0x00200000 | 0x01000000 | 0x02000000 | 0x04000000)
	allowedOptions2 = uint32(0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000040 | 0x00001000 | 0x00002000 | 0x00010000 | 0x00020000 | 0x00080000 | 0x00100000)
)

type getEntryPropertiesFunc func(PhonebookEntry, []uint32, *uint32) uint32

func validSelection(entry PhonebookEntry) bool {
	p := entry.PhonebookPath
	// Require an explicit drive-absolute phonebook, never ambient/default,
	// UNC, device namespaces, alternate streams or relative paths. The system
	// wrapper additionally rejects mapped/network drives before reading RAS.
	if !validText(entry.Name, 256) || !validText(p, 260) || len(p) < 4 || p[1] != ':' || p[2] != '\\' || !((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) || strings.ContainsAny(p[3:], ":/*?\"<>|") {
		return false
	}
	for _, part := range strings.Split(p[3:], `\`) {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") { return false }
	}
	return strings.HasSuffix(strings.ToLower(p), ".pbk")
}

// Check each existing path component without intentionally following a reparse
// point. This is a preflight, not a filesystem lock: another process can still
// replace a component before RAS opens it, so no atomic local-only claim is made.
func checkPhonebookPath(path string, attributes func(string) (uint32, error)) bool {
	parts := strings.Split(path[3:], `\`)
	current := path[:3]
	for i := -1; i < len(parts); i++ {
		if i >= 0 { if i > 0 { current += `\` }; current += parts[i] }
		flags, err := attributes(current)
		if err != nil || flags & 0x400 != 0 { return false } // FILE_ATTRIBUTE_REPARSE_POINT
		isDirectory := flags & 0x10 != 0
		if isDirectory != (i < len(parts)-1) { return false }
	}
	return true
}

func canonicalGateway(value string) (string, bool) {
	if !validText(value, 128) { return "", false }
	if ip := net.ParseIP(value); ip != nil {
		if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() { return "", false }
		return ip.String(), true
	}
	value = strings.ToLower(value)
	labels := strings.Split(strings.TrimSuffix(value, "."), ".")
	numeric := true
	for _, label := range labels {
		digits := label
		base16 := strings.HasPrefix(digits, "0x")
		if base16 { digits = digits[2:] }
		if digits == "" { numeric = false }
		for _, c := range digits {
			if !(c >= '0' && c <= '9' || base16 && c >= 'a' && c <= 'f') { numeric = false }
		}
	}
	// Windows recognizes legacy numeric forms that net.ParseIP rejects. Do
	// not reinterpret these as DNS names (for example 127.1 or 0x7f000001).
	if numeric { return "", false }
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' { return "", false }
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') { return "", false }
		}
	}
	return value, true
}

func inspectEntryProperties(call getEntryPropertiesFunc, entry PhonebookEntry, expectedGateway string) (EntryEvidence, error) {
	gateway, ok := canonicalGateway(expectedGateway)
	if !ok || !validSelection(entry) || call == nil { return EntryEvidence{}, ErrEntryProperties }
	size := entryPropertiesSize
	for attempt := 0; attempt < 3; attempt++ {
		if size < entryPropertiesSize || size > maxPropertiesBuffer { break }
		buffer := make([]uint32, (size + 3) / 4)
		buffer[0] = entryPropertiesSize
		capacity := uint32(len(buffer)) * 4
		size = capacity
		code := call(entry, buffer, &size)
		if code == rasBufferTooSmall { continue }
		if code != 0 || size < entryPropertiesSize || size > capacity { break }
		raw := *(*nativeEntryProperties)(unsafe.Pointer(&buffer[0]))
		if raw.Size != entryPropertiesSize || !supportedEntry(raw, gateway) { break }
		return EntryEvidence{entry: entry, gateway: gateway, properties: raw}, nil
	}
	return EntryEvidence{}, ErrEntryProperties
}

func supportedEntry(raw nativeEntryProperties, gateway string) bool {
	device, ok := fixedUTF16(raw.DeviceType[:])
	if !ok || device != "vpn" || raw.Type != 2 || raw.VPNStrategy != 3 || raw.FramingProtocol != 1 { return false }
	if raw.Options & 0x20000000 == 0 || raw.Options & ^allowedOptions != 0 || raw.Options2 & 0x10 == 0 || raw.Options2 & ^allowedOptions2 != 0 || raw.Options3 != 0 { return false }
	if raw.EncryptionType != 1 && raw.EncryptionType != 2 { return false }
	if raw.NetProtocols == 0 || raw.NetProtocols & ^uint32(0x0c) != 0 || raw.AlternateOffset != 0 || raw.SubEntries > 1 || raw.DialMode > 1 || raw.CustomAuthKey != 0 || raw.Reserved1 != 0 || raw.Reserved2 != 0 || raw.GUID == [16]byte{} { return false }
	for _, field := range [][]uint16{raw.Script[:], raw.AutodialDLL[:], raw.AutodialFunc[:], raw.CustomDialDLL[:], raw.PrerequisitePBK[:], raw.PrerequisiteEntry[:], raw.X25PadType[:], raw.X25Address[:], raw.X25Facilities[:], raw.X25UserData[:], raw.IDi[:], raw.IDr[:]} {
		for _, c := range field { if c != 0 { return false } }
	}
	if raw.IsIMSConfig != 0 || raw.IDiType != 0 || raw.IDrType != 0 || raw.DisableIKEv2Fragmentation != 0 { return false }
	for _, field := range [][]uint16{raw.AreaCode[:], raw.DeviceName[:], raw.DNSSuffix[:]} {
		if _, ok := fixedUTF16(field); !ok { return false }
	}
	endpoint, ok := fixedUTF16(raw.LocalPhoneNumber[:])
	if !ok { return false }
	canonical, ok := canonicalGateway(endpoint)
	return ok && canonical == gateway
}

// Revalidation detects observed profile replacement or changes, including the
// read-only entry GUID and settings beyond the gateway. It is not an atomic
// lock: a future dialer must still address the read/dial race and bind its
// returned connection independently. A zero-value snapshot always fails closed.
func revalidateEntryProperties(call getEntryPropertiesFunc, previous EntryEvidence) error {
	current, err := inspectEntryProperties(call, previous.entry, previous.gateway)
	if err != nil || current.properties != previous.properties { return ErrEntryProperties }
	return nil
}
