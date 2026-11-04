//go:build darwin

package macosvpn

import (
	"context"
	"net/netip"
	"runtime"
	"sync"
	"syscall"

	"github.com/ebitengine/purego"
	"golang.org/x/net/route"
)

// Official ABI: sysctl(int *, unsigned int, void *, size_t *, void *, size_t).
// https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/sysctl.3.html
// Kernel MIB/format: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/rtsock.c
// Only CTL_NET/AF_ROUTE/AF_UNSPEC/NET_RT_DUMP is bound here. No sysctlnametomib,
// writable routing socket, route utility, or caller-supplied MIB is used.
var routeSysctlOnce sync.Once
var routeSysctl func(*int32, uint32, *byte, *uintptr, uintptr, uintptr) int32
var routeSysctlErr error

func loadRouteSysctl() error {
	routeSysctlOnce.Do(func() {
		defer func() {
			if recover() != nil {
				routeSysctl, routeSysctlErr = nil, ErrRouteReadback
			}
		}()
		h, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			routeSysctlErr = ErrRouteReadback
			return
		}
		// Retain the library for the lifetime of the registered function.
		purego.RegisterLibFunc(&routeSysctl, h, "sysctl")
	})
	return routeSysctlErr
}

func readKernelRoutesNative(ctx context.Context) (out KernelRouteReadback, err error) {
	defer func() {
		if recover() != nil {
			out, err = KernelRouteReadback{}, ErrRouteReadback
		}
	}()
	if loadRouteSysctl() != nil || routeSysctl == nil {
		return out, ErrRouteReadback
	}
	data, err := boundedRouteRIB(ctx, func(old []byte, length *uintptr) error {
		mib := [6]int32{syscall.CTL_NET, syscall.AF_ROUTE, 0, syscall.AF_UNSPEC, syscall.NET_RT_DUMP, 0}
		var oldp *byte
		if len(old) != 0 {
			oldp = &old[0]
		}
		result := routeSysctl(&mib[0], uint32(len(mib)), oldp, length, 0, 0)
		runtime.KeepAlive(mib)
		runtime.KeepAlive(old)
		if result != 0 {
			return ErrRouteReadback // Discard partial output; errno never needed for retries.
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	records, err := decodeDarwinRouteRIB(data)
	if err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	return KernelRouteReadback{Records: records, Bytes: len(data)}, nil
}

func decodeDarwinRouteRIB(data []byte) (records []KernelRouteRecord, err error) {
	defer func() {
		if recover() != nil {
			records, err = nil, ErrRouteReadback
		}
	}()
	count, err := validateDarwinRouteFrames(data)
	if err != nil {
		return nil, err
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, data)
	if err != nil || len(messages) != count {
		return nil, ErrRouteReadback
	}
	records = make([]KernelRouteRecord, 0, count)
	for _, message := range messages {
		m, ok := message.(*route.RouteMessage)
		// v0.59.0's route_classic.go populates Err from offset 28 (Darwin
		// rtm_use). The strict preflight checks the actual rtm_errno at 24.
		if !ok || m.Version != syscall.RTM_VERSION || m.Type != syscall.RTM_GET || len(m.Addrs) < syscall.RTAX_MAX {
			return nil, ErrRouteReadback
		}
		in := kernelRouteInput{index: m.Index, flags: uint32(m.Flags)}
		in.destination, in.destinationZone, ok = kernelRouteIP(m.Addrs[syscall.RTAX_DST])
		if !ok {
			return nil, ErrRouteReadback
		}
		if mask := m.Addrs[syscall.RTAX_NETMASK]; mask != nil {
			var zone uint32
			in.mask, zone, ok = kernelRouteIP(mask)
			if !ok || zone != 0 {
				return nil, ErrRouteReadback
			}
		}
		if gateway, ok := m.Addrs[syscall.RTAX_GATEWAY].(*route.LinkAddr); ok {
			in.linkGateway, in.linkIndex = true, gateway.Index
		} else {
			in.gateway, in.gatewayZone, ok = kernelRouteIP(m.Addrs[syscall.RTAX_GATEWAY])
			if !ok {
				return nil, ErrRouteReadback
			}
		}
		r, err := normalizeKernelRoute(in)
		if err != nil {
			return nil, err // Never return a misleading subset of the table.
		}
		records = append(records, r)
	}
	return records, nil
}

func kernelRouteIP(a route.Addr) (netip.Addr, uint32, bool) {
	switch a := a.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(a.IP), 0, true
	case *route.Inet6Addr:
		if a.ZoneID < 0 || uint64(a.ZoneID) > uint64(^uint32(0)) {
			return netip.Addr{}, 0, false
		}
		return netip.AddrFrom16(a.IP), uint32(a.ZoneID), true
	default:
		return netip.Addr{}, 0, false
	}
}
