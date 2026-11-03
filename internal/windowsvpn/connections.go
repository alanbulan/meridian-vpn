package windowsvpn

import (
	"encoding/binary"
	"errors"
	"sort"
	"strings"
	"unsafe"
)

var (
	ErrConnectionObservation = errors.New("Windows RAS connection evidence is unavailable or changed")
	ErrExistingConnection = errors.New("an existing Windows RAS connection was observed; adoption is blocked")
	ErrExclusivityUnproven = errors.New("Windows RAS connection exclusivity cannot be established; dialing is blocked")
)

// ConnectionSnapshot contains only the count of freshly observed, matching
// connections. It exposes no native handle or reference/cleanup capability.
// RAS enumeration does NOT acquire a reference and cannot see every in-flight
// dial. Neither an empty result nor RASCF_OwnerMatch proves process ownership.
// Even two identical observations are not an atomic reservation.
type ConnectionSnapshot struct { observed int }
func (s ConnectionSnapshot) ObservedConnections() int { return s.observed }

// DialBlocker deliberately never returns nil, including for the zero value.
// This package has no proven exclusive dial or safe borrowed-reference path.
func (s ConnectionSnapshot) DialBlocker() error {
	if s.observed > 0 { return ErrExistingConnection }
	return ErrExclusivityUnproven
}

// RASCONNW is packed to four bytes by ras.h, including on 64-bit Windows.
// Its HRASCONN field is at offset four, so a Go struct with uintptr would have
// the WRONG x64 layout. Marshal it from a four-byte-aligned word buffer instead.
type connectionLayout struct {
	size, pointerBytes, name, deviceType, deviceName, phonebook, subEntry, guid, flags, luid, correlation int
}
func rasConnectionLayout(pointerBytes int) (connectionLayout, bool) {
	if pointerBytes != 4 && pointerBytes != 8 { return connectionLayout{}, false }
	l := connectionLayout{pointerBytes: pointerBytes, name: 4 + pointerBytes}
	l.deviceType = l.name + 257*2
	l.deviceName = l.deviceType + 17*2
	l.phonebook = l.deviceName + 129*2
	l.subEntry = (l.phonebook + 260*2 + 3) & ^3
	l.guid = l.subEntry + 4
	l.flags = l.guid + 16
	l.luid = l.flags + 4
	l.correlation = l.luid + 8
	l.size = l.correlation + 16
	return l, true
}

type connectionRecord struct {
	handle uintptr
	name, phonebook, deviceType, deviceName string
	subEntry, flags uint32
	guid, correlation [16]byte
	luid [8]byte
}

type nativeTunnelEndpoint struct { Type uint32; Address [16]byte }
type nativeConnectionStatus struct {
	Size, State, Error uint32
	DeviceType [17]uint16
	DeviceName [129]uint16
	PhoneNumber [129]uint16
	Local, Remote nativeTunnelEndpoint
	Substate uint32
}
const (
	connectionStatusSize = uint32(unsafe.Sizeof(nativeConnectionStatus{}))
	maxConnectionBuffer = uint32(4 * 1024 * 1024)
	maxConnectionCount = uint32(1024)
	maxSelectedConnections = 8
	rasConnected = uint32(0x2000)
)

type enumConnectionsFunc func([]uint32, *uint32, *uint32) uint32
type getConnectionStatusFunc func(uintptr, *nativeConnectionStatus) uint32

func wordBytes(buffer []uint32) []byte {
	if len(buffer) == 0 { return nil }
	return unsafe.Slice((*byte)(unsafe.Pointer(&buffer[0])), len(buffer)*4)
}
func connectionUTF16(buffer []byte, start, count int) (string, bool) {
	value := make([]uint16, count)
	for i := range value { value[i] = binary.LittleEndian.Uint16(buffer[start+i*2:]) }
	return fixedUTF16(value)
}
func decodeConnection(buffer []byte, layout connectionLayout) (connectionRecord, bool) {
	if len(buffer) != layout.size || binary.LittleEndian.Uint32(buffer) != uint32(layout.size) { return connectionRecord{}, false }
	var record connectionRecord
	if layout.pointerBytes == 8 {
		v := binary.LittleEndian.Uint64(buffer[4:])
		if uint64(uintptr(v)) != v { return connectionRecord{}, false }
		record.handle = uintptr(v)
	} else { record.handle = uintptr(binary.LittleEndian.Uint32(buffer[4:])) }
	if record.handle == 0 { return connectionRecord{}, false }
	var ok bool
	if record.name, ok = connectionUTF16(buffer, layout.name, 257); !ok || record.name == "" { return connectionRecord{}, false }
	if record.deviceType, ok = connectionUTF16(buffer, layout.deviceType, 17); !ok { return connectionRecord{}, false }
	if record.deviceName, ok = connectionUTF16(buffer, layout.deviceName, 129); !ok { return connectionRecord{}, false }
	if record.phonebook, ok = connectionUTF16(buffer, layout.phonebook, 260); !ok { return connectionRecord{}, false }
	record.subEntry = binary.LittleEndian.Uint32(buffer[layout.subEntry:])
	record.flags = binary.LittleEndian.Uint32(buffer[layout.flags:])
	copy(record.guid[:], buffer[layout.guid:layout.guid+16])
	copy(record.luid[:], buffer[layout.luid:layout.luid+8])
	copy(record.correlation[:], buffer[layout.correlation:layout.correlation+16])
	return record, true
}

func enumerateConnections(call enumConnectionsFunc) ([]connectionRecord, error) {
	layout, ok := rasConnectionLayout(int(unsafe.Sizeof(uintptr(0))))
	if !ok || call == nil { return nil, ErrConnectionObservation }
	size := uint32(layout.size)
	for attempt := 0; attempt < 3; attempt++ {
		if size < uint32(layout.size) || size > maxConnectionBuffer { break }
		buffer := make([]uint32, (size + 3) / 4)
		buffer[0] = uint32(layout.size)
		size = uint32(len(buffer))*4
		var count uint32
		code := call(buffer, &size, &count)
		if code == rasBufferTooSmall { continue }
		if code != 0 { break }
		return decodeConnectionList(buffer, size, count, layout)
	}
	return nil, ErrConnectionObservation
}

func decodeConnectionList(buffer []uint32, size, count uint32, layout connectionLayout) ([]connectionRecord, error) {
	if (count == 0 && size != 0 && size < uint32(layout.size)) || size > uint32(len(buffer))*4 || count > maxConnectionCount || uint64(count)*uint64(layout.size) > uint64(size) { return nil, ErrConnectionObservation }
	result := make([]connectionRecord, 0, count)
	bytes := wordBytes(buffer)
	seen := make(map[uintptr]bool)
	for i := uint32(0); i < count; i++ {
		start := int(i)*layout.size
		record, ok := decodeConnection(bytes[start:start+layout.size], layout)
		if !ok || seen[record.handle] { return nil, ErrConnectionObservation }
		seen[record.handle] = true
		result = append(result, record)
	}
	return result, nil
}

func selectedConnections(records []connectionRecord, entry EntryEvidence) ([]connectionRecord, error) {
	selected := []connectionRecord{}
	for _, record := range records {
		nameMatch := strings.EqualFold(record.name, entry.entry.Name)
		pathMatch := strings.EqualFold(record.phonebook, entry.entry.PhonebookPath)
		guidMatch := record.guid == entry.properties.GUID
		if !guidMatch && !(nameMatch && pathMatch) {
			if nameMatch && (record.phonebook == "" || record.guid == [16]byte{}) { return nil, ErrConnectionObservation }
			continue
		}
		if !guidMatch || !nameMatch || !pathMatch || record.deviceType != "vpn" || record.subEntry > 1 || record.correlation == [16]byte{} || record.flags & ^uint32(0x0f) != 0 { return nil, ErrConnectionObservation }
		selected = append(selected, record)
		if len(selected) > maxSelectedConnections { return nil, ErrConnectionObservation }
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].handle < selected[j].handle })
	return selected, nil
}

func observeConnections(entry EntryEvidence, enumerate enumConnectionsFunc, status getConnectionStatusFunc, revalidate func(EntryEvidence) error) (ConnectionSnapshot, error) {
	if entry.properties.GUID == [16]byte{} || !validSelection(entry.entry) || !supportedEntry(entry.properties, entry.gateway) || enumerate == nil || status == nil || revalidate == nil { return ConnectionSnapshot{}, ErrConnectionObservation }
	if revalidate(entry) != nil { return ConnectionSnapshot{}, ErrConnectionObservation }
	before, err := enumerateConnections(enumerate)
	if err != nil { return ConnectionSnapshot{}, ErrConnectionObservation }
	selected, err := selectedConnections(before, entry)
	if err != nil { return ConnectionSnapshot{}, ErrConnectionObservation }
	for _, record := range selected {
		raw := nativeConnectionStatus{Size: connectionStatusSize}
		if status(record.handle, &raw) != 0 || raw.Size != connectionStatusSize || raw.Error != 0 || raw.State != rasConnected { return ConnectionSnapshot{}, ErrConnectionObservation }
		device, ok := fixedUTF16(raw.DeviceType[:]); if !ok || device != record.deviceType { return ConnectionSnapshot{}, ErrConnectionObservation }
		name, ok := fixedUTF16(raw.DeviceName[:]); if !ok || name != record.deviceName { return ConnectionSnapshot{}, ErrConnectionObservation }
		phone, ok := fixedUTF16(raw.PhoneNumber[:]); if !ok { return ConnectionSnapshot{}, ErrConnectionObservation }
		gateway, ok := canonicalGateway(phone); if !ok || gateway != entry.gateway { return ConnectionSnapshot{}, ErrConnectionObservation }
	}
	after, err := enumerateConnections(enumerate)
	if err != nil { return ConnectionSnapshot{}, ErrConnectionObservation }
	selectedAfter, err := selectedConnections(after, entry)
	if err != nil || len(selected) != len(selectedAfter) { return ConnectionSnapshot{}, ErrConnectionObservation }
	for i := range selected { if selected[i] != selectedAfter[i] { return ConnectionSnapshot{}, ErrConnectionObservation } }
	if revalidate(entry) != nil { return ConnectionSnapshot{}, ErrConnectionObservation }
	return ConnectionSnapshot{observed: len(selected)}, nil
}
