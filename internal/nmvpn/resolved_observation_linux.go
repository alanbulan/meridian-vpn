//go:build linux

package nmvpn

import (
	"context"
	"errors"
	"reflect"
	"strings"

	"mygo-vpn/internal/packetrelay"

	"github.com/godbus/dbus/v5"
)

// ResolvedObservationSnapshot combines a sampled kernel namespace's complete
// link inventory with resolved's Manager and each matching Link projection.
// It is historical diagnostic data, NOT an atomic snapshot, live policy lease,
// ownership/namespace proof, ServicePolicy, HostBinding or readiness evidence.
// Kernel index/name equality cannot exclude link deletion/recreation (ABA).
type ResolvedObservationSnapshot struct {
	BusID, Owner string
	Namespace    packetrelay.KernelNamespaceIdentity
	Manager      ResolvedManagerSnapshot
	Links        []ResolvedLinkSnapshot
}

type ResolvedObservation struct{ snapshot *ResolvedObservationSnapshot }

// Snapshot returns an independent copy; it does not revalidate old evidence.
func (o *ResolvedObservation) Snapshot() (ResolvedObservationSnapshot, error) {
	if o == nil || o.snapshot == nil {
		return ResolvedObservationSnapshot{}, errResolvedObservation
	}
	out := *o.snapshot
	out.Manager.DNS = append([]ResolvedDNSServer{}, out.Manager.DNS...)
	out.Manager.FallbackDNS = append([]ResolvedDNSServer{}, out.Manager.FallbackDNS...)
	out.Manager.Domains = append([]ResolvedDomain{}, out.Manager.Domains...)
	out.Manager.Modes.NegativeTrustAnchors = append([]string{}, out.Manager.Modes.NegativeTrustAnchors...)
	out.Links = append([]ResolvedLinkSnapshot{}, out.Links...)
	for i := range out.Links {
		out.Links[i].DNS = append([]ResolvedDNSServer{}, out.Links[i].DNS...)
		out.Links[i].Domains = append([]ResolvedDomain{}, out.Links[i].Domains...)
		out.Links[i].Modes.NegativeTrustAnchors = append([]string{}, out.Links[i].Modes.NegativeTrustAnchors...)
	}
	return out, nil
}

// ObserveAllLinks brackets two resolved readbacks with concrete, bounded kernel
// RTM_GETLINK dumps. No caller-supplied ifindex list is accepted as completeness
// evidence. Each kernel link, including loopback/down/unmanaged links, must have
// a successful GetLink, strict property inventory and supported individual Get
// results; errors are never dropped.
// Manager DNS/domains and each Link must agree. Empty ListDelegates is required;
// systemd 258+ supplies this capability. An older daemon without the method or a
// nonempty delegate set fails closed.
//
// expected must have independent namespace provenance. The broker must ALSO
// establish that the pinned resolved owner belongs to that namespace; bus owner
// UID and kernel IDs alone cannot establish it. No normal application entry point
// invokes this observer. No host files, positive trust anchors, NSS, firewall,
// dispatcher policy or other resolvers are inspected.
//
// Equal sequential readings do not exclude silent intervening or future changes:
// many policy properties have EmitsChangedSignal=false. A successful observation
// is never permission to publish. Failure closes only this dedicated connection.
func (b *PinnedResolvedObserver) ObserveAllLinks(ctx context.Context, expected packetrelay.KernelNamespaceIdentity) (*ResolvedObservation, error) {
	if b == nil || b.self != b || b.conn == nil {
		return nil, errResolvedObservation
	}
	var out ResolvedObservationSnapshot
	err := b.run(ctx, func(ctx context.Context) error {
		var err error
		out, err = b.observeAllWith(ctx, expected, resolvedObservationOps{
			kernel: func(ctx context.Context, ns packetrelay.KernelNamespaceIdentity) (packetrelay.KernelLinkSetSnapshot, error) {
				links, err := packetrelay.ObserveKernelLinkSet(ctx, ns)
				if err != nil {
					return packetrelay.KernelLinkSetSnapshot{}, err
				}
				return links.Snapshot()
			},
			check: b.check, read: b.readResolved,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return &ResolvedObservation{snapshot: &out}, nil
}

// Private fixtures cannot inject a source into the public production path.
type resolvedObservationOps struct {
	kernel func(context.Context, packetrelay.KernelNamespaceIdentity) (packetrelay.KernelLinkSetSnapshot, error)
	check  func(context.Context) error
	read   func(context.Context, []packetrelay.KernelLinkIdentity) (ResolvedObservationSnapshot, error)
}

func (b *PinnedResolvedObserver) observeAllWith(ctx context.Context, expected packetrelay.KernelNamespaceIdentity, ops resolvedObservationOps) (ResolvedObservationSnapshot, error) {
	var empty ResolvedObservationSnapshot
	if ctx == nil || ctx.Err() != nil || expected.Inode == 0 || ops.kernel == nil || ops.check == nil || ops.read == nil {
		return empty, errResolvedObservation
	}
	if err := ops.check(ctx); err != nil {
		return empty, errors.Join(errResolvedObservation, err)
	}
	before, err := ops.kernel(ctx, expected)
	if err != nil {
		return empty, errors.Join(errResolvedObservation, err)
	}
	if !resolvedKernelSetValid(before, expected) {
		return empty, errResolvedObservation
	}
	first, err := ops.read(ctx, before.Links)
	if err != nil || ctx.Err() != nil {
		return empty, errors.Join(errResolvedObservation, err, ctx.Err())
	}
	if !resolvedProjectionConsistent(first, before.Links) {
		return empty, errResolvedObservation
	}
	second, err := ops.read(ctx, before.Links)
	if err != nil || ctx.Err() != nil {
		return empty, errors.Join(errResolvedObservation, err, ctx.Err())
	}
	if !reflect.DeepEqual(first, second) || !resolvedProjectionConsistent(second, before.Links) {
		return empty, errResolvedObservation
	}
	after, err := ops.kernel(ctx, expected)
	if err != nil || ctx.Err() != nil {
		return empty, errors.Join(errResolvedObservation, err, ctx.Err())
	}
	if !resolvedKernelSetValid(after, expected) || !reflect.DeepEqual(before, after) || b.invalid.Load() {
		return empty, errResolvedObservation
	}
	if err := ops.check(ctx); err != nil {
		return empty, errors.Join(errResolvedObservation, err)
	}
	if ctx.Err() != nil || b.invalid.Load() {
		return empty, errors.Join(errResolvedObservation, ctx.Err())
	}
	second.Namespace, second.BusID, second.Owner = expected, b.pin.BusID, b.pin.Owner
	return second, nil
}

func resolvedKernelSetValid(s packetrelay.KernelLinkSetSnapshot, expected packetrelay.KernelNamespaceIdentity) bool {
	if s.Namespace != expected || expected.Inode == 0 || len(s.Links) == 0 || len(s.Links) > resolvedMaxLinks {
		return false
	}
	names := make(map[string]bool, len(s.Links))
	last := int32(0)
	for _, link := range s.Links {
		if link.Index <= last || len(link.Name) == 0 || len(link.Name) > 15 || link.Name == "." || link.Name == ".." || strings.ContainsAny(link.Name, "/:\x00 \t\r\n") || names[link.Name] {
			return false
		}
		for _, c := range []byte(link.Name) {
			if c < 33 || c > 126 {
				return false
			}
		}
		last, names[link.Name] = link.Index, true
	}
	return true
}

func (b *PinnedResolvedObserver) readResolved(ctx context.Context, links []packetrelay.KernelLinkIdentity) (ResolvedObservationSnapshot, error) {
	var out ResolvedObservationSnapshot
	var delegates [][]any
	if b.call(ctx, b.pin.Owner, resolvedPath, resolvedManagerInterface+".ListDelegates", nil, "a(so)", &delegates) != nil || len(delegates) != 0 {
		return out, errResolvedObservation
	}
	properties, err := b.readResolvedProperties(ctx, resolvedPath, resolvedManagerInterface)
	if err != nil {
		return out, err
	}
	if out.Manager, err = parseResolvedManager(properties); err != nil {
		return ResolvedObservationSnapshot{}, err
	}
	out.Links = make([]ResolvedLinkSnapshot, 0, len(links))
	for _, link := range links {
		var path dbus.ObjectPath
		if b.call(ctx, b.pin.Owner, resolvedPath, resolvedManagerInterface+".GetLink", []any{link.Index}, "o", &path) != nil || path != resolvedLinkPath(link.Index) {
			return ResolvedObservationSnapshot{}, errResolvedObservation
		}
		properties, err := b.readResolvedProperties(ctx, path, resolvedLinkInterface)
		if err != nil {
			return ResolvedObservationSnapshot{}, err
		}
		snapshot, err := parseResolvedLink(properties, link.Index, path)
		if err != nil {
			return ResolvedObservationSnapshot{}, err
		}
		snapshot.Name = link.Name
		out.Links = append(out.Links, snapshot)
	}
	return out, nil
}

func (b *PinnedResolvedObserver) readResolvedProperties(ctx context.Context, path dbus.ObjectPath, iface string) (map[string]dbus.Variant, error) {
	return readResolvedPropertiesWith(ctx, path, iface, func(method string, args []any, signature string, out ...any) error {
		return b.call(ctx, b.pin.Owner, path, method, args, signature, out...)
	})
}

// Read individual variants, never a{sv}: godbus's dictionary decoder collapses
// duplicate keys before callers can reject conflicting values. Introspection
// brackets the fixed property reads and validates inventory without dictionaries.
// This closes the wire-schema ambiguity, not the silent-change/atomicity gap.
func readResolvedPropertiesWith(ctx context.Context, path dbus.ObjectPath, iface string, call func(string, []any, string, ...any) error) (map[string]dbus.Variant, error) {
	if ctx == nil || call == nil || (iface != resolvedManagerInterface && iface != resolvedLinkInterface) {
		return nil, errResolvedObservation
	}
	manager := iface == resolvedManagerInterface
	validate := func() error {
		var document string
		if ctx.Err() != nil {
			return errResolvedObservation
		}
		if err := call(resolvedIntrospectInterface+".Introspect", nil, "s", &document); err != nil {
			return err
		}
		return validateResolvedIntrospection(document, path, iface)
	}
	if err := validate(); err != nil {
		return nil, err
	}
	properties := make(map[string]dbus.Variant)
	for _, name := range resolvedPropertyNames(manager) {
		var value dbus.Variant
		if ctx.Err() != nil {
			return nil, errResolvedObservation
		}
		if err := call(propertiesInterface+".Get", []any{iface, name}, "v", &value); err != nil {
			return nil, err
		}
		if value.Signature().String() != resolvedPropertySchema(manager)[name] {
			return nil, errResolvedObservation
		}
		properties[name] = value
	}
	if err := validate(); err != nil {
		return nil, err
	}
	return resolvedPolicyProperties(properties, manager)
}

func resolvedProjectionConsistent(s ResolvedObservationSnapshot, links []packetrelay.KernelLinkIdentity) bool {
	if len(s.Links) != len(links) {
		return false
	}
	byIndex := make(map[int32]ResolvedLinkSnapshot, len(links))
	for i, link := range links {
		observed := s.Links[i]
		if observed.Index != link.Index || observed.Name != link.Name || observed.Path != resolvedLinkPath(link.Index) {
			return false
		}
		byIndex[link.Index] = observed
	}
	// Preserve each link's DNS and search-domain order while allowing the
	// manager's cross-link iteration order to differ from numeric ifindex order.
	servers := make(map[int32][]ResolvedDNSServer)
	domains := make(map[int32][]ResolvedDomain)
	for _, server := range s.Manager.DNS {
		if server.LinkIndex == 0 {
			continue
		}
		if _, ok := byIndex[server.LinkIndex]; !ok {
			return false
		}
		servers[server.LinkIndex] = append(servers[server.LinkIndex], server)
	}
	for _, domain := range s.Manager.Domains {
		if domain.LinkIndex == 0 {
			continue
		}
		if _, ok := byIndex[domain.LinkIndex]; !ok {
			return false
		}
		domains[domain.LinkIndex] = append(domains[domain.LinkIndex], domain)
	}
	for _, server := range s.Manager.FallbackDNS {
		if server.LinkIndex != 0 {
			if _, ok := byIndex[server.LinkIndex]; !ok {
				return false
			}
		}
	}
	for index, link := range byIndex {
		if len(servers[index]) != len(link.DNS) || len(domains[index]) != len(link.Domains) {
			return false
		}
		for i := range link.DNS {
			if link.DNS[i] != servers[index][i] {
				return false
			}
		}
		for i := range link.Domains {
			if link.Domains[i] != domains[index][i] {
				return false
			}
		}
	}
	return true
}
