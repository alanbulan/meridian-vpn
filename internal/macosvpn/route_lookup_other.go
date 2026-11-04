//go:build !darwin

package macosvpn

import (
	"context"
	"net/netip"
)

func lookupDestinationRouteNative(context.Context, netip.Addr) (DestinationRouteObservation, error) {
	return DestinationRouteObservation{}, ErrRouteLookup
}
