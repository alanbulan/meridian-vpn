package windowsvpn

import (
	"net/netip"
	"unsafe"
)

// Native RASPPPIPW from ras.h, four-byte packing, modern 80-byte form.
// PPP server address is an inner peer address, NOT the configured VPN gateway.
type nativePPPIPv4 struct {
	Size, Error            uint32
	Address, ServerAddress [16]uint16
	Options, ServerOptions uint32
}

const pppIPv4Size = uint32(unsafe.Sizeof(nativePPPIPv4{}))
const raspPPPIPv4 = uint32(0x8021)

type projectionIPv4Func func(uintptr, *nativePPPIPv4, *uint32) uint32

type handleIPv4Evidence struct {
	handle                 uintptr
	entryGUID, correlation [16]byte
	address                netip.Addr
	gateway                string
}

func readPPPIPv4(handle uintptr, call projectionIPv4Func) (netip.Addr, error) {
	if handle == 0 || call == nil {
		return netip.Addr{}, ErrVerification
	}
	raw := nativePPPIPv4{Size: pppIPv4Size}
	size := pppIPv4Size
	if call(handle, &raw, &size) != 0 || size != pppIPv4Size || raw.Size != pppIPv4Size || raw.Error != 0 {
		return netip.Addr{}, ErrVerification
	}
	value, ok := fixedUTF16(raw.Address[:])
	if !ok {
		return netip.Addr{}, ErrVerification
	}
	ip, err := netip.ParseAddr(value)
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsLoopback() {
		return netip.Addr{}, ErrVerification
	}
	return ip, nil
}

// inspectHandleIPv4 binds the direct handle to selected profile, correlation ID,
// connected status and PPP-assigned local IPv4 across two complete observations.
// It acquires no reference and supplies NO interface index, exclusivity, routing
// or native-quiescence claim. RASCONN.luid is a logon-session LUID, not NET_LUID.
func inspectHandleIPv4(entry EntryEvidence, handle uintptr, enumerate enumConnectionsFunc, status getConnectionStatusFunc, projection projectionIPv4Func, revalidate func(EntryEvidence) error) (handleIPv4Evidence, error) {
	fail := func() (handleIPv4Evidence, error) { return handleIPv4Evidence{}, ErrVerification }
	if handle == 0 || enumerate == nil || status == nil || projection == nil || revalidate == nil ||
		entry.properties.GUID == [16]byte{} || !validSelection(entry.entry) || !supportedEntry(entry.properties, entry.gateway) {
		return fail()
	}
	if revalidate(entry) != nil {
		return fail()
	}
	var first connectionRecord
	var firstIP netip.Addr
	for pass := 0; pass < 2; pass++ {
		records, err := enumerateConnections(enumerate)
		if err != nil {
			return fail()
		}
		selected, err := selectedConnections(records, entry)
		if err != nil {
			return fail()
		}
		var match connectionRecord
		found := false
		for _, record := range selected {
			if record.handle == handle {
				match = record
				found = true
			}
		}
		if !found {
			return fail()
		}
		raw := nativeConnectionStatus{Size: connectionStatusSize}
		if status(handle, &raw) != 0 || raw.Size != connectionStatusSize || raw.Error != 0 || raw.State != rasConnected {
			return fail()
		}
		device, ok := fixedUTF16(raw.DeviceType[:])
		if !ok || device != match.deviceType {
			return fail()
		}
		name, ok := fixedUTF16(raw.DeviceName[:])
		if !ok || name != match.deviceName {
			return fail()
		}
		phone, ok := fixedUTF16(raw.PhoneNumber[:])
		if !ok {
			return fail()
		}
		gateway, ok := canonicalGateway(phone)
		if !ok || gateway != entry.gateway {
			return fail()
		}
		ip, err := readPPPIPv4(handle, projection)
		if err != nil {
			return fail()
		}
		if pass == 0 {
			first = match
			firstIP = ip
		} else if match != first || ip != firstIP {
			return fail()
		}
	}
	if revalidate(entry) != nil {
		return fail()
	}
	return handleIPv4Evidence{handle, entry.properties.GUID, first.correlation, firstIP, entry.gateway}, nil
}
