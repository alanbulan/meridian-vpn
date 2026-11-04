package macosvpn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// Limits apply before allocation/parsing, not after an unbounded FetchRIB.
const MaxKernelRouteBytes = 2 << 20
const MaxKernelRouteRecords = 8192

var ErrRouteReadback = errors.New("bounded macOS kernel route readback unavailable or unsupported")

// KernelRouteRecord is one observed Darwin RIB entry, not an effective route
// lookup. Flags are the raw Darwin RTF_* bits, including reject/blackhole/down
// and cloning flags. No record is silently filtered based on those flags.
// ScopeInterfaceIndex comes from RTF_IFSCOPE + rtm_index; IPv6 address zones
// are separate. Gateway is invalid for a link-layer gateway. Link names
// and MAC addresses are deliberately not exposed.
type KernelRouteRecord struct {
	Prefix                netip.Prefix
	Gateway               netip.Addr
	GatewayIsLink         bool
	GatewayInterfaceIndex int
	GatewayZoneIndex      uint32
	InterfaceIndex        int
	Flags                 uint32
	ScopeInterfaceIndex   int
	DestinationZoneIndex  uint32
}

// KernelRouteReadback does not assert complete traffic policy, effective
// selection, connection ownership, DNS/IPv6 safety, or a kill switch. A successful
// bounded dump may already be stale when returned. Empty records are not proof
// of safety. No network activity, routing-socket writes, or mutations occur.
type KernelRouteReadback struct {
	Records []KernelRouteRecord
	Bytes   int
}

// ReadKernelRoutes observes the local kernel RIB independently of a VPN service.
// At most two synchronous sysctl calls are made. Context cancellation is checked
// between calls but cannot interrupt a native call. No goroutine is detached.
func ReadKernelRoutes(ctx context.Context) (KernelRouteReadback, error) {
	if ctx == nil {
		return KernelRouteReadback{}, ErrRouteReadback
	}
	if err := ctx.Err(); err != nil {
		return KernelRouteReadback{}, err
	}
	return readKernelRoutesNative(ctx)
}

// This deliberately restricted injected boundary exposes only an old-data
// buffer. The Darwin implementation fixes the MIB and cannot accept newp/newlen.
type routeReadOnlySysctl func(old []byte, length *uintptr) error

func boundedRouteRIB(ctx context.Context, read routeReadOnlySysctl) (data []byte, err error) {
	defer func() {
		if recover() != nil {
			data, err = nil, routeReadbackError("rib-01")
		}
	}()
	if ctx == nil || read == nil {
		return nil, routeReadbackError("rib-02")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	var size uintptr
	if read(nil, &size) != nil {
		return nil, routeReadbackError("rib-03")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if size > MaxKernelRouteBytes {
		return nil, routeReadbackError("rib-04")
	}
	if size == 0 {
		return []byte{}, nil
	}
	data = make([]byte, int(size))
	// A changing table may yield ENOMEM or a partial result. Discard it; never
	// retry with a kernel-selected allocation or treat partial output as success.
	if read(data, &size) != nil || size > uintptr(len(data)) {
		return nil, routeReadbackError("rib-05")
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return data[:int(size)], nil
}

// Darwin's supported 64-bit layouts use a 92-byte rt_msghdr and 4-byte sockaddr
// alignment. Validate every message and address before x/net/route can allocate
// records or skip an unknown/truncated message. No wire struct is unsafe-cast.
func validateDarwinRouteFrames(data []byte) (int, error) {
	if len(data) > MaxKernelRouteBytes {
		return 0, routeReadbackError("rib-06")
	}
	count := 0
	for len(data) != 0 {
		if len(data) < 92 || count == MaxKernelRouteRecords {
			return 0, routeReadbackError("rib-07")
		}
		n := int(binary.LittleEndian.Uint16(data[:2]))
		if n < 92 || n > len(data) || data[2] != 5 || data[3] != 4 {
			return 0, routeReadbackError("rib-08")
		}
		frame := data[:n]
		// Darwin errno is offset 24; offset 28 is the route-use counter.
		if binary.LittleEndian.Uint32(frame[24:28]) != 0 {
			return 0, routeReadbackError("rib-09")
		}
		attrs := binary.LittleEndian.Uint32(frame[12:16])
		if attrs&^uint32(0xff) != 0 || attrs&3 != 3 {
			return 0, routeReadbackError("rib-10")
		}
		body, family := frame[92:], byte(0)
		for i := 0; i < 8; i++ {
			if attrs&(1<<i) == 0 {
				continue
			}
			if len(body) < 4 {
				return 0, routeReadbackError("rib-11")
			}
			l, af := int(body[0]), body[1]
			space := (l + 3) &^ 3
			if l == 0 {
				space = 4
			}
			if space > len(body) || l == 1 {
				return 0, routeReadbackError("rib-12")
			}
			switch i {
			case 0: // RTAX_DST
				if !validRouteInetSockaddr(af, l) {
					return 0, routeReadbackError("rib-13")
				}
				family = af
			case 1: // RTAX_GATEWAY: IP or AF_LINK, never an inferred default address.
				if af == 18 {
					if l < 8 || 8+int(body[5])+int(body[6])+int(body[7]) > l {
						return 0, routeReadbackError("rib-14")
					}
				} else if af != family || !validRouteInetSockaddr(af, l) {
					return 0, routeReadbackError("rib-15")
				}
			case 2, 3: // NETMASK/GENMASK can be short AF_UNSPEC sockaddrs.
				max := 16
				if family == 30 {
					max = 28
				}
				if l > max || (l != 0 && af != 0 && af != family) {
					return 0, routeReadbackError("rib-16")
				}
			default:
				if l < 2 {
					return 0, routeReadbackError("rib-17")
				}
			}
			body = body[space:]
		}
		if len(body) != 0 { // No silent trailers, including truncated extra messages.
			return 0, routeReadbackError("rib-18")
		}
		count++
		data = data[n:]
	}
	return count, nil
}

func validRouteInetSockaddr(af byte, size int) bool {
	return af == 2 && size == 16 || af == 30 && size == 28
}

type kernelRouteInput struct {
	destination, mask, gateway   netip.Addr
	destinationZone, gatewayZone uint32
	linkGateway                  bool
	linkIndex, index             int
	flags                        uint32
}

func normalizeKernelRoute(in kernelRouteInput) (KernelRouteRecord, error) {
	fail := KernelRouteRecord{}
	if !in.destination.IsValid() || in.destination.Is4In6() || in.destination.Zone() != "" || in.index <= 0 || in.index > 65535 {
		return fail, routeReadbackError("rib-19")
	}
	bits := in.destination.BitLen()
	if in.mask.IsValid() {
		if in.mask.BitLen() != bits || in.mask.Zone() != "" {
			return fail, routeReadbackError("rib-20")
		}
		var size int
		bits, size = net.IPMask(in.mask.AsSlice()).Size()
		if size != in.destination.BitLen() {
			return fail, routeReadbackError("rib-21")
		}
		if in.flags&4 != 0 && bits != size { // RTF_HOST must be a host prefix.
			return fail, routeReadbackError("rib-22")
		}
	} else if in.flags&4 == 0 {
		return fail, routeReadbackError("rib-23") // Missing netmask is not a default route.
	}
	prefix := netip.PrefixFrom(in.destination, bits)
	if prefix.Masked().Addr() != in.destination {
		return fail, routeReadbackError("rib-24")
	}
	if in.linkGateway {
		if in.gateway.IsValid() || in.gatewayZone != 0 || in.linkIndex < 0 || in.linkIndex > 65535 {
			return fail, routeReadbackError("rib-25")
		}
	} else if !in.gateway.IsValid() || in.gateway.BitLen() != in.destination.BitLen() || in.gateway.Is4In6() || in.gateway.Zone() != "" || in.linkIndex != 0 {
		return fail, routeReadbackError("rib-26")
	}
	if in.destination.Is4() && (in.destinationZone != 0 || in.gatewayZone != 0) {
		return fail, routeReadbackError("rib-27")
	}
	out := KernelRouteRecord{Prefix: prefix, Gateway: in.gateway, GatewayIsLink: in.linkGateway,
		GatewayInterfaceIndex: in.linkIndex, GatewayZoneIndex: in.gatewayZone,
		InterfaceIndex: in.index, Flags: in.flags, DestinationZoneIndex: in.destinationZone}
	if in.flags&0x1000000 != 0 { // Darwin RTF_IFSCOPE, not Linux scope semantics.
		out.ScopeInterfaceIndex = in.index
	}
	return out, nil
}

func routeReadbackError(code string) error {
	return fmt.Errorf("只读路由阶段 %s: %w", code, ErrRouteReadback)
}
