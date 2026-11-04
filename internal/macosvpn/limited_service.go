package macosvpn

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"slices"

	"mygo-vpn/internal/core"
)

// NewLimitedExistingCoreAdapter is a distinct, explicitly consented mode. It
// does not enable the all-policy ExistingCoreAdapter constructor. Readiness is
// scoped to this service, interface and finite destinations; it is not a global
// DNS/IPv6 leak-prevention or exclusive-service guarantee.
func NewLimitedExistingCoreAdapter(selection *ExistingServiceSelection, consent ExistingServiceConsent, targets []netip.Addr) *ExistingCoreAdapter {
	verification := &limitedServiceVerification{enabled: runtime.GOOS == "darwin", targets: slices.Clone(targets), lookup: LookupDestinationRoute, inspect: InspectExistingService, interfaces: net.Interfaces, routes: ReadKernelRoutes}
	return newLimitedExistingCoreAdapter(selection, consent, verification)
}
func newLimitedExistingCoreAdapter(selection *ExistingServiceSelection, consent ExistingServiceConsent, v *limitedServiceVerification) *ExistingCoreAdapter {
	var control existingControl
	if selection != nil && selection.state != nil {
		control = selection.state.owner
	}
	a := newExistingCoreAdapter(control, selection, consent, ExistingNetworkPolicy{}, nil)
	a.limited = v
	if v != nil {
		v.selected = selection.Configuration()
		v.targets = slices.Clone(v.targets)
		strings := make([]string, len(v.targets))
		for i, ip := range v.targets {
			strings[i] = ip.String()
		}
		a.profile.SystemService = &core.SystemServiceOptions{ServiceID: v.selected.ServiceID, Targets: strings}
	}
	return a
}

// LimitedProfile returns a detached profile bound to this single selection.
// No consent, passwords or system credentials are placed in the profile.
func (a *ExistingCoreAdapter) LimitedProfile() (core.Profile, error) {
	if a == nil || a.limited == nil || !a.available() {
		return core.Profile{}, ErrExistingVerification
	}
	p := a.profile
	o := *p.SystemService
	o.Targets = slices.Clone(o.Targets)
	p.SystemService = &o
	return p, nil
}

type limitedServiceVerification struct {
	enabled    bool
	selected   ServiceConfiguration
	targets    []netip.Addr
	lookup     func(context.Context, netip.Addr) (DestinationRouteObservation, error)
	inspect    func(context.Context, string) (ServiceInspection, error)
	interfaces func() ([]net.Interface, error)
	routes     func(context.Context) (KernelRouteReadback, error)
}

func (v *limitedServiceVerification) available() bool {
	if v == nil || !v.enabled || v.lookup == nil || v.inspect == nil || v.interfaces == nil || v.routes == nil || len(v.targets) == 0 || len(v.targets) > 16 || validateDiagnosticConfig(v.selected, v.selected.ServiceID) != nil {
		return false
	}
	seen := map[netip.Addr]bool{}
	for _, ip := range v.targets {
		if !validRouteDestination(ip) || ip.IsLoopback() || seen[ip] {
			return false
		}
		seen[ip] = true
	}
	return true
}
func (v *limitedServiceVerification) active(ctx context.Context, g GenerationEvidence) error {
	if !v.available() || g.Interface.ServiceID != v.selected.ServiceID {
		return ErrExistingVerification
	}
	proof, err := verifyDestinationRoutes(ctx, g, v.targets, v.lookup)
	if err != nil || !proof.AllDestinationsMatch || proof.CompletePolicyVerified {
		return ErrExistingVerification
	}
	return nil
}
func (v *limitedServiceVerification) restored(ctx context.Context, g *GenerationEvidence) error {
	if ctx == nil || ctx.Err() != nil || !v.available() {
		return ErrCleanup
	}

	serviceGone := func() bool {
		selected, err := v.inspect(ctx, v.selected.ServiceID)
		return err == nil && ctx.Err() == nil && selected.Status == Disconnected && selected.Generation == nil && sameDiagnosticConfig(v.selected, selected.Configuration)
	}
	if !serviceGone() {
		return ErrCleanup
	}
	// No observed generation means no interface was adopted. Still take a second
	// independent service/config sample; controller cleanup already released interest.
	if g == nil {
		if !serviceGone() {
			return ErrCleanup
		}
		return nil
	}
	if !validExistingGeneration(*g, v.selected.ServiceID) {
		return ErrCleanup
	}
	// Two bounded absence passes, each bracketed by fresh disconnected/config
	// observations. These samples do not claim an atomic snapshot or exclude ABA.
	for pass := 0; pass < 2; pass++ {
		interfaces, err := v.interfaces()
		if err != nil || ctx.Err() != nil || len(interfaces) > 4096 {
			return ErrCleanup
		}
		for _, iface := range interfaces {
			if iface.Index == g.Interface.InterfaceIndex || iface.Name == g.Interface.InterfaceName {
				return ErrCleanup
			}
		}
		routes, err := v.routes(ctx)
		if err != nil || ctx.Err() != nil || len(routes.Records) > MaxKernelRouteRecords || routes.Bytes > MaxKernelRouteBytes || routes.Bytes < 0 {
			return ErrCleanup
		}
		for _, r := range routes.Records {
			if r.InterfaceIndex == g.Interface.InterfaceIndex || r.ScopeInterfaceIndex == g.Interface.InterfaceIndex || r.GatewayInterfaceIndex == g.Interface.InterfaceIndex || r.GatewayZoneIndex == uint32(g.Interface.InterfaceIndex) || r.DestinationZoneIndex == uint32(g.Interface.InterfaceIndex) {
				return ErrCleanup
			}
		}
		if !serviceGone() {
			return ErrCleanup
		}
	}

	return nil
}

func (a *ExistingCoreAdapter) SupportsProtocol(protocol string) bool {
	return a != nil && a.limited != nil && protocol == core.ProtocolMacOSSystemL2TP
}
