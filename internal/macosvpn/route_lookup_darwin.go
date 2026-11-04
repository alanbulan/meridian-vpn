//go:build darwin

package macosvpn

import (
	"context"
	"net"
	"net/netip"
	"os/exec"
	"time"
)

// Apple's route(8) -n get sends RTM_GET only. XNU rtsock.c uses rt_lookup
// and reports metrics; it does not add/delete routes or transmit IP packets.
// -n suppresses symbolic name resolution. No hostnames or user options accepted.
// Sources: apple-oss-distributions/network_cmds route.tproj/{route.c,route.8}
// and apple-oss-distributions/xnu bsd/net/rtsock.c, RTM_GET handling.
func lookupDestinationRouteNative(ctx context.Context, destination netip.Addr) (DestinationRouteObservation, error) {
	var zero DestinationRouteObservation
	args, err := routeArgs(destination)
	if err != nil {
		return zero, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/sbin/route", args...)
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.WaitDelay = time.Second
	var stdout boundedRouteOutput
	var stderr routeStderr
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// route can exit zero after an error; reject any stderr and require complete
	// strict output bound to the requested destination, not just the exit status.
	if cmd.Run() != nil || ctx.Err() != nil || stdout.overflow || stderr.written {
		return zero, ErrRouteLookup
	}
	out, err := parseRouteLookup(stdout.buffer.Bytes(), destination)
	if err != nil {
		return zero, err
	}
	iface, err := net.InterfaceByName(out.InterfaceName)
	if err != nil || ctx.Err() != nil || iface.Index <= 0 || iface.Name != out.InterfaceName {
		return zero, ErrRouteLookup
	}
	out.InterfaceIndex = iface.Index
	return out, nil
}
