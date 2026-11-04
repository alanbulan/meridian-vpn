package windowsvpn

import "net/netip"

// adapterIPv4 is a trusted IP Helper snapshot, not a RASCONN record. luid MUST
// be the adapter NET_LUID (never RASCONN's logon LUID). The dormant IP Helper
// reader supplies these records only during explicit limited-mode sessions. Addresses
// must be unicast entries.
type adapterIPv4 struct {
	index            uint32
	luid             uint64
	kind, operStatus uint32
	addresses        []netip.Addr
	unusable         []netip.Addr
}
type interfaceBinding struct {
	index   uint32
	luid    uint64
	address netip.Addr
}
type interfaceSnapshotFunc func() ([]adapterIPv4, error)

// A unique local-address match is observed correlation, not a documented direct
// HRASCONN identity conversion or exclusive ownership. Multiple matches fail
// even if only one of the matching adapters is currently up or is PPP.
func correlateInterface(address netip.Addr, rows []adapterIPv4) (interfaceBinding, error) {
	if !address.Is4() || !address.IsGlobalUnicast() || address.IsLoopback() || len(rows) > 4096 {
		return interfaceBinding{}, ErrVerification
	}
	seen := make(map[uint32]bool)
	seenLUID := make(map[uint64]bool)
	var result interfaceBinding
	matches := 0
	for _, row := range rows {
		if row.index == 0 || row.luid == 0 || seen[row.index] || seenLUID[row.luid] || len(row.addresses) > 64 {
			return interfaceBinding{}, ErrVerification
		}
		seen[row.index] = true
		seenLUID[row.luid] = true
		matched := false
		for _, ip := range row.addresses {
			if ip == address {
				matched = true
			}
		}
		if !matched {
			continue
		}
		for _, ip := range row.unusable {
			if ip == address {
				return interfaceBinding{}, ErrVerification
			}
		}
		matches++
		if row.kind != 23 || row.operStatus != 1 {
			return interfaceBinding{}, ErrVerification
		} // IF_TYPE_PPP, IfOperStatusUp
		result = interfaceBinding{row.index, row.luid, address}
	}
	if matches != 1 {
		return interfaceBinding{}, ErrVerification
	}
	return result, nil
}
