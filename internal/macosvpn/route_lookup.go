package macosvpn

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrRouteLookup = errors.New("指定目的地址的内核路由验证不可用或不匹配")

const maxRouteLookupBytes = 16 << 10

// DestinationRouteObservation is an unscoped RTM_GET best-match result for one
// numeric destination. It is not an actual packet trace, NECP/per-app policy,
// source-bound flow lookup, resolver proof, or proof for all addresses in a CIDR.
type DestinationRouteObservation struct {
	Destination    netip.Addr
	MatchedPrefix  netip.Prefix
	Gateway        netip.Addr
	InterfaceName  string
	InterfaceIndex int
	Flags          uint32
	MTU            uint32
}

type DestinationRouteVerification struct {
	Generation             GenerationEvidence
	Routes                 []DestinationRouteObservation
	AllDestinationsMatch   bool
	CompletePolicyVerified bool // Always false: finite unscoped queries are not all traffic.
}

func validRouteDestination(ip netip.Addr) bool {
	return ip.IsValid() && ip.Zone() == "" && !ip.Is4In6() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast()
}

// LookupDestinationRoute asks the kernel to select the unscoped best match.
// The caller cannot supply route flags, commands, interface hints, or hostnames.
func LookupDestinationRoute(ctx context.Context, destination netip.Addr) (DestinationRouteObservation, error) {
	if ctx == nil || ctx.Err() != nil || !validRouteDestination(destination) {
		return DestinationRouteObservation{}, ErrRouteLookup
	}
	return lookupDestinationRouteNative(ctx, destination)
}

// VerifyDestinationRoutes binds explicit IPv4/IPv6 kernel lookup results to an
// already-observed PPP generation. It does not refresh or certify the generation:
// its owner must check that retained native connection before and after this call.
// No -ifscope hint is used: forcing the expected interface could conceal bypass.
func VerifyDestinationRoutes(ctx context.Context, generation GenerationEvidence, destinations []netip.Addr) (DestinationRouteVerification, error) {
	return verifyDestinationRoutes(ctx, generation, destinations, LookupDestinationRoute)
}
func verifyDestinationRoutes(ctx context.Context, generation GenerationEvidence, destinations []netip.Addr, lookup func(context.Context, netip.Addr) (DestinationRouteObservation, error)) (DestinationRouteVerification, error) {
	var zero DestinationRouteVerification
	if ctx == nil || ctx.Err() != nil || lookup == nil || len(destinations) == 0 || len(destinations) > 16 || !validServiceID(generation.Interface.ServiceID) || !validExistingGeneration(generation, generation.Interface.ServiceID) {
		return zero, ErrRouteLookup
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := DestinationRouteVerification{Generation: cloneGeneration(generation)}
	seen := map[netip.Addr]bool{}
	// Validate the whole batch before any native call.
	for _, ip := range destinations {
		if !validRouteDestination(ip) || seen[ip] {
			return zero, ErrRouteLookup
		}
		seen[ip] = true
	}
	for _, ip := range destinations {
		if ctx.Err() != nil {
			return zero, ErrRouteLookup
		}
		observation, err := lookup(ctx, ip)
		if err != nil || ctx.Err() != nil || observation.Destination != ip || !observation.MatchedPrefix.IsValid() || !observation.MatchedPrefix.Contains(ip) || observation.InterfaceName != generation.Interface.InterfaceName || observation.InterfaceIndex != generation.Interface.InterfaceIndex || observation.Flags&1 == 0 || observation.Flags&(8|0x1000|0x2000000|0x200000|0x400000|0x800000) != 0 {
			return zero, ErrRouteLookup
		}
		out.Routes = append(out.Routes, observation)
	}
	out.AllDestinationsMatch = true
	return out, nil
}

var routeInterfaceName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,14}$`)
var routeFlagNames = map[string]uint32{
	"UP": 1, "GATEWAY": 2, "HOST": 4, "REJECT": 8, "DYNAMIC": 16, "MODIFIED": 32, "DONE": 64, "DELCLONE": 128,
	"CLONING": 256, "XRESOLVE": 512, "LLINFO": 1024, "STATIC": 2048, "BLACKHOLE": 4096, "b016": 8192, "PROTO2": 16384, "PROTO1": 32768,
	"PRCLONING": 65536, "WASCLONED": 131072, "PROTO3": 262144, "b024": 524288, "PINNED": 1048576, "LOCAL": 2097152, "BROADCAST": 4194304, "MULTICAST": 8388608,
	"IFSCOPE": 16777216, "CONDEMNED": 33554432, "IFREF": 67108864, "PROXY": 134217728, "ROUTER": 268435456, "GLOBAL": 1073741824,
}

func routeArgs(destination netip.Addr) ([]string, error) {
	if !validRouteDestination(destination) {
		return nil, ErrRouteLookup
	}
	family := "-inet6"
	if destination.Is4() {
		family = "-inet"
	}
	return []string{"-n", "get", family, destination.String()}, nil
}
func parseRouteLookup(data []byte, requested netip.Addr) (DestinationRouteObservation, error) {
	var zero DestinationRouteObservation
	if !validRouteDestination(requested) || len(data) == 0 || len(data) > maxRouteLookupBytes {
		return zero, ErrRouteLookup
	}
	for _, b := range data {
		if (b < 32 && b != '\n' && b != '\t' && b != '\r') || b > 126 {
			return zero, ErrRouteLookup
		}
	}
	fields := map[string]string{}
	metrics := false
	complete := false
	var mtu uint32
	for _, raw := range strings.Split(string(data), "\n") {
		if len(raw) > 1024 {
			return zero, ErrRouteLookup
		}
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if complete {
			return zero, ErrRouteLookup
		}
		if metrics {
			values := strings.Fields(line)
			if len(values) != 8 {
				return zero, ErrRouteLookup
			}
			for i, value := range values {
				value = strings.TrimSuffix(value, "L")
				if i == 7 {
					if _, e := strconv.ParseInt(value, 10, 32); e != nil {
						return zero, ErrRouteLookup
					}
				} else {
					n, e := strconv.ParseUint(value, 10, 32)
					if e != nil {
						return zero, ErrRouteLookup
					}
					if i == 6 {
						mtu = uint32(n)
					}
				}
			}
			complete = true
			continue
		}
		if strings.Join(strings.Fields(line), " ") == "recvpipe sendpipe ssthresh rtt,msec rttvar hopcount mtu expire" {
			metrics = true
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || value == "" || fields[key] != "" {
			return zero, ErrRouteLookup
		}
		switch key {
		case "route to", "destination", "mask", "gateway", "interface", "flags":
		default:
			return zero, ErrRouteLookup
		}
		fields[key] = value
	}
	if !complete || !routeInterfaceName.MatchString(fields["interface"]) {
		return zero, ErrRouteLookup
	}
	actual, e := netip.ParseAddr(fields["route to"])
	if e != nil || actual != requested {
		return zero, ErrRouteLookup
	}
	destinationText := fields["destination"]
	if destinationText == "default" {
		destinationText = "::"
		if requested.Is4() {
			destinationText = "0.0.0.0"
		}
	}
	destination, e := netip.ParseAddr(destinationText)
	if e != nil || destination.Zone() != "" || destination.Is4In6() || destination.BitLen() != requested.BitLen() {
		return zero, ErrRouteLookup
	}
	flagsText := fields["flags"]
	if len(flagsText) < 3 || flagsText[0] != '<' || flagsText[len(flagsText)-1] != '>' {
		return zero, ErrRouteLookup
	}
	var flags uint32
	for _, label := range strings.Split(flagsText[1:len(flagsText)-1], ",") {
		flag, ok := routeFlagNames[label]
		if !ok || flags&flag != 0 {
			return zero, ErrRouteLookup
		}
		flags |= flag
	}
	bits := destination.BitLen()
	if maskText, ok := fields["mask"]; ok {
		mask, e := netip.ParseAddr(maskText)
		if e != nil || mask.Zone() != "" || mask.BitLen() != bits {
			return zero, ErrRouteLookup
		}
		ones, size := net.IPMask(mask.AsSlice()).Size()
		if size != bits || flags&4 != 0 && ones != bits {
			return zero, ErrRouteLookup
		}
		bits = ones
	} else if flags&4 == 0 {
		return zero, ErrRouteLookup
	}
	prefix := netip.PrefixFrom(destination, bits)
	if prefix.Masked() != prefix || !prefix.Contains(requested) {
		return zero, ErrRouteLookup
	}
	var gateway netip.Addr
	if gatewayText, ok := fields["gateway"]; ok {
		gateway, e = netip.ParseAddr(gatewayText)
		if e != nil || gateway.Is4In6() || gateway.BitLen() != requested.BitLen() || gateway.IsUnspecified() || gateway.IsMulticast() || flags&2 == 0 {
			return zero, ErrRouteLookup
		}
		if zone := gateway.Zone(); zone != "" && zone != fields["interface"] {
			return zero, ErrRouteLookup
		}
	} else if flags&2 != 0 {
		return zero, ErrRouteLookup
	}
	return DestinationRouteObservation{Destination: requested, MatchedPrefix: prefix, Gateway: gateway, InterfaceName: fields["interface"], Flags: flags, MTU: mtu}, nil
}

type boundedRouteOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (b *boundedRouteOutput) Write(p []byte) (int, error) {
	if len(p) > maxRouteLookupBytes-b.buffer.Len() {
		b.overflow = true
		return 0, ErrRouteLookup
	}
	return b.buffer.Write(p)
}

type routeStderr struct{ written bool }

func (s *routeStderr) Write(p []byte) (int, error) {
	if len(p) > 0 {
		s.written = true
	}
	return len(p), nil
}
