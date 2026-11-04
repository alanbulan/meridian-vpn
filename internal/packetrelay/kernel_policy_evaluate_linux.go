//go:build linux

package packetrelay

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"golang.org/x/sys/unix"
)

var ErrKernelPolicyDelta = errors.New("kernel policy delta is not the provisioned IPv4 policy")

// KernelIPv4Route is an exact allowed addition, not independent allowlists.
// Main-table unicast and local-table local/broadcast routes are supported. Gateway,
// multipath, encapsulation, metrics, marks and unknown added attributes fail.
// PreferredSource specifies exact attribute presence; when present its value
// must be the provisioned tunnel address. Kernel routes require it. Static NM
// routes can explicitly provision absence, matching four-element NM route tuples.
type KernelIPv4Route struct {
	Destination           netip.Prefix
	Table                 uint32
	Type, Scope, Protocol uint8
	Priority              uint32
	PreferredSource       bool
}

// KernelIPv4DeltaPolicy is trusted provisioning for a fresh TUN generation.
// Address has its host bits; each route destination must be canonical. Endpoints
// are the outer transport addresses that must never be captured by these routes.
// This does not establish that the baseline is safe or that the interface index
// belongs to the retained TUN. Independent authority must establish both.
type KernelIPv4DeltaPolicy struct {
	InterfaceIndex uint32
	InterfaceName  string
	Address        netip.Prefix
	Endpoints      []netip.Addr
	Routes         []KernelIPv4Route
}

// EvaluateKernelIPv4Delta accepts only byte-identical baseline records plus one
// expected IPv4 address and exactly the explicitly provisioned route tuples.
// It allows no removed/changed records, added rules or IPv6 changes. Unknown
// baseline attributes are preserved, NOT approved. Dynamic baseline lifetime
// changes fail conservatively; this is not a general-purpose policy engine.
//
// Inputs remain sequential, caller-constructible observations. Success is not
// readiness, ownership or cleanup proof, and says nothing about DNS, firewall,
// dispatcher hooks, link changes, completeness or safety of the baseline.
func EvaluateKernelIPv4Delta(before, after KernelPolicyObservation, policy KernelIPv4DeltaPolicy) error {
	if before.Namespace.Inode == 0 || before.Namespace != after.Namespace || !validKernelDeltaPolicy(policy) {
		return ErrKernelPolicyDelta
	}
	type key struct {
		kind uint16
		data string
	}
	baseline := make(map[key]bool)
	for _, snapshot := range []KernelPolicyObservation{before, after} {
		if len(snapshot.Records) > 4096 {
			return ErrKernelPolicyDelta
		}
		total := 0
		for _, record := range snapshot.Records {
			total += len(record.Data)
			if total > 1<<20 || !validPolicyRecord(record) {
				return ErrKernelPolicyDelta
			}
		}
	}
	for _, record := range before.Records {
		// The fresh tunnel may not already have an address or direct route
		// in the baseline. This is not an exhaustive indirect-reference check.
		if record.Type == unix.RTM_NEWADDR && binary.NativeEndian.Uint32(record.Data[4:]) == policy.InterfaceIndex {
			return ErrKernelPolicyDelta
		}
		if record.Type == unix.RTM_NEWROUTE {
			attrs, _ := kernelAttributes(record.Data[12:], 0)
			if output, ok := attrs[unix.RTA_OIF]; ok && (output.flags != 0 || len(output.value) != 4 || binary.NativeEndian.Uint32(output.value) == policy.InterfaceIndex) {
				return ErrKernelPolicyDelta
			}
		}
		k := key{record.Type, string(record.Data)}
		if baseline[k] {
			return ErrKernelPolicyDelta
		}
		baseline[k] = true
	}
	seen := make(map[key]bool)
	routes := make(map[KernelIPv4Route]bool)
	for _, route := range policy.Routes {
		routes[route] = false
	}
	address := false
	for _, record := range after.Records {
		k := key{record.Type, string(record.Data)}
		if seen[k] {
			return ErrKernelPolicyDelta
		}
		seen[k] = true
		if baseline[k] {
			delete(baseline, k)
			continue
		}
		switch record.Type {
		case unix.RTM_NEWADDR:
			if address || !kernelDeltaAddress(record.Data, policy) {
				return ErrKernelPolicyDelta
			}
			address = true
		case unix.RTM_NEWROUTE:
			route, ok := kernelDeltaRoute(record.Data, policy)
			if !ok {
				return ErrKernelPolicyDelta
			}
			used, expected := routes[route]
			if !expected || used {
				return ErrKernelPolicyDelta
			}
			routes[route] = true
		default:
			return ErrKernelPolicyDelta
		}
	}
	if len(baseline) != 0 || !address {
		return ErrKernelPolicyDelta
	}
	for _, used := range routes {
		if !used {
			return ErrKernelPolicyDelta
		}
	}
	return nil
}

func validKernelDeltaPolicy(p KernelIPv4DeltaPolicy) bool {
	if p.InterfaceIndex == 0 || p.InterfaceIndex > 1<<31-1 || !tunResourceName.MatchString(p.InterfaceName) || !p.Address.IsValid() || !p.Address.Addr().Is4() || !p.Address.Addr().IsGlobalUnicast() || p.Address.Bits() < 1 || len(p.Endpoints) == 0 || len(p.Endpoints) > 128 || len(p.Routes) == 0 || len(p.Routes) > 128 {
		return false
	}
	endpoints := map[netip.Addr]bool{}
	for _, endpoint := range p.Endpoints {
		if !endpoint.Is4() || !endpoint.IsGlobalUnicast() || p.Address.Contains(endpoint) || endpoints[endpoint] {
			return false
		}
		endpoints[endpoint] = true
	}
	seen := map[KernelIPv4Route]bool{}
	for _, route := range p.Routes {
		if !route.Destination.IsValid() || !route.Destination.Addr().Is4() || route.Destination != route.Destination.Masked() || route.Destination.Bits() < 1 || seen[route] || (route.Protocol == unix.RTPROT_KERNEL && !route.PreferredSource) || (route.Protocol != unix.RTPROT_KERNEL && route.Protocol != unix.RTPROT_STATIC) {
			return false
		}
		if route.Type == unix.RTN_LOCAL {
			if route.Table != unix.RT_TABLE_LOCAL || route.Scope != unix.RT_SCOPE_HOST || route.Destination != netip.PrefixFrom(p.Address.Addr(), 32) || route.Protocol != unix.RTPROT_KERNEL {
				return false
			}
		} else if route.Type == unix.RTN_BROADCAST {
			if route.Table != unix.RT_TABLE_LOCAL || route.Scope != unix.RT_SCOPE_LINK || route.Protocol != unix.RTPROT_KERNEL || route.Priority != 0 || p.Address.Bits() >= 31 || route.Destination.Bits() != 32 {
				return false
			}
			base := p.Address.Masked().Addr().As4()
			upper := base
			binary.BigEndian.PutUint32(upper[:], binary.BigEndian.Uint32(base[:])|(^uint32(0)>>uint(p.Address.Bits())))
			if route.Destination.Addr() != netip.AddrFrom4(base) && route.Destination.Addr() != netip.AddrFrom4(upper) {
				return false
			}
		} else if route.Type != unix.RTN_UNICAST || route.Table != unix.RT_TABLE_MAIN || route.Scope != unix.RT_SCOPE_LINK {
			return false
		}
		for _, endpoint := range p.Endpoints {
			if route.Destination.Contains(endpoint) {
				return false
			}
		}
		seen[route] = true
	}
	return true
}

func validPolicyRecord(r KernelPolicyRecord) bool {
	size := 12
	if r.Type == unix.RTM_NEWADDR {
		size = 8
	} else if r.Type != unix.RTM_NEWROUTE && r.Type != unix.RTM_NEWRULE {
		return false
	}
	if len(r.Data) < size || (r.Data[0] != unix.AF_INET && r.Data[0] != unix.AF_INET6) {
		return false
	}
	_, err := kernelAttributes(r.Data[size:], 0)
	return err == nil
}

func kernelDeltaAddress(data []byte, p KernelIPv4DeltaPolicy) bool {
	if len(data) < 8 || data[0] != unix.AF_INET || int(data[1]) != p.Address.Bits() || data[2] != unix.IFA_F_PERMANENT || data[3] != unix.RT_SCOPE_UNIVERSE || binary.NativeEndian.Uint32(data[4:]) != p.InterfaceIndex {
		return false
	}
	attrs, err := kernelAttributes(data[8:], 0)
	if err != nil {
		return false
	}
	local, address := false, false
	for kind, attr := range attrs {
		if attr.flags != 0 {
			return false
		}
		switch kind {
		case unix.IFA_LOCAL, unix.IFA_ADDRESS:
			if len(attr.value) != 4 || netip.AddrFrom4([4]byte(attr.value)) != p.Address.Addr() {
				return false
			}
			if kind == unix.IFA_LOCAL {
				local = true
			} else {
				address = true
			}
		case unix.IFA_LABEL:
			if string(attr.value) != p.InterfaceName+"\x00" {
				return false
			}
		case unix.IFA_FLAGS:
			if len(attr.value) != 4 || binary.NativeEndian.Uint32(attr.value) != unix.IFA_F_PERMANENT {
				return false
			}
		case unix.IFA_CACHEINFO:
			if len(attr.value) != 16 || binary.NativeEndian.Uint32(attr.value) != ^uint32(0) || binary.NativeEndian.Uint32(attr.value[4:]) != ^uint32(0) {
				return false
			}
		default:
			return false
		}
	}
	return local && address
}

func kernelDeltaRoute(data []byte, p KernelIPv4DeltaPolicy) (KernelIPv4Route, bool) {
	var out KernelIPv4Route
	if len(data) < 12 || data[0] != unix.AF_INET || data[1] < 1 || data[1] > 32 || data[2] != 0 || data[3] != 0 || binary.NativeEndian.Uint32(data[8:]) != 0 {
		return out, false
	}
	out.Table, out.Protocol, out.Scope, out.Type = uint32(data[4]), data[5], data[6], data[7]
	attrs, err := kernelAttributes(data[12:], 0)
	if err != nil {
		return out, false
	}
	destination, output := false, false
	for kind, attr := range attrs {
		if attr.flags != 0 {
			return out, false
		}
		switch kind {
		case unix.RTA_DST:
			if len(attr.value) != 4 {
				return out, false
			}
			out.Destination = netip.PrefixFrom(netip.AddrFrom4([4]byte(attr.value)), int(data[1]))
			destination = true
		case unix.RTA_OIF:
			if len(attr.value) != 4 || binary.NativeEndian.Uint32(attr.value) != p.InterfaceIndex {
				return out, false
			}
			output = true
		case unix.RTA_PREFSRC:
			if len(attr.value) != 4 || netip.AddrFrom4([4]byte(attr.value)) != p.Address.Addr() {
				return out, false
			}
			out.PreferredSource = true
		case unix.RTA_TABLE:
			if len(attr.value) != 4 {
				return out, false
			}
			table := binary.NativeEndian.Uint32(attr.value)
			if out.Table != 0 && out.Table != table {
				return out, false
			}
			out.Table = table
		case unix.RTA_PRIORITY:
			if len(attr.value) != 4 {
				return out, false
			}
			out.Priority = binary.NativeEndian.Uint32(attr.value)
		default:
			return out, false
		}
	}
	return out, destination && output
}
