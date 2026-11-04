//go:build linux

package nmvpn

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"mygo-vpn/internal/packetrelay"
)

func resolvedSnapshotFixture(t *testing.T) ResolvedObservationSnapshot {
	t.Helper()
	manager, err := parseResolvedManager(resolvedManagerFixture())
	if err != nil {
		t.Fatal(err)
	}
	link, err := parseResolvedLink(resolvedLinkFixture(), 2, resolvedLinkPath(2))
	if err != nil {
		t.Fatal(err)
	}
	link.Name = "eth0"
	loopback := ResolvedLinkSnapshot{Index: 1, Name: "lo", Path: resolvedLinkPath(1)}
	return ResolvedObservationSnapshot{Manager: manager, Links: []ResolvedLinkSnapshot{loopback, link}}
}

type resolvedObservationFixture struct {
	b                          *PinnedResolvedObserver
	ns                         packetrelay.KernelNamespaceIdentity
	ops                        resolvedObservationOps
	kernelReads, reads, checks int
}

func resolvedObserverFixture(t *testing.T) *resolvedObservationFixture {
	t.Helper()
	f := &resolvedObservationFixture{b: &PinnedResolvedObserver{pin: BusPin{BusID: "0123456789abcdef0123456789abcdef", Owner: ":1.42"}}, ns: packetrelay.KernelNamespaceIdentity{Device: 1, Inode: 2}}
	f.ops = resolvedObservationOps{
		kernel: func(ctx context.Context, ns packetrelay.KernelNamespaceIdentity) (packetrelay.KernelLinkSetSnapshot, error) {
			f.kernelReads++
			return packetrelay.KernelLinkSetSnapshot{Namespace: ns, Links: []packetrelay.KernelLinkIdentity{{Index: 1, Name: "lo"}, {Index: 2, Name: "eth0"}}}, nil
		},
		check: func(context.Context) error { f.checks++; return nil },
		read: func(ctx context.Context, links []packetrelay.KernelLinkIdentity) (ResolvedObservationSnapshot, error) {
			f.reads++
			if len(links) != 2 || links[0].Name != "lo" || links[1].Index != 2 {
				t.Fatal("incomplete kernel membership passed to reader")
			}
			return resolvedSnapshotFixture(t), nil
		},
	}
	return f
}

func TestResolvedObservationReadsCompleteKernelSet(t *testing.T) {
	f := resolvedObserverFixture(t)
	out, err := f.b.observeAllWith(context.Background(), f.ns, f.ops)
	if err != nil || f.kernelReads != 2 || f.reads != 2 || f.checks != 2 {
		t.Fatalf("did not bracket readbacks and identity checks: %v %+v", err, f)
	}
	if out.Namespace != f.ns || out.BusID != f.b.pin.BusID || out.Owner != f.b.pin.Owner || len(out.Links) != 2 || out.Links[0].Name != "lo" {
		t.Fatal("incomplete observation")
	}
	if _, ok := any(&ResolvedObservation{snapshot: &out}).(ServicePolicy); ok {
		t.Fatal("diagnostic observation became policy authority")
	}
}

func TestResolvedObservationRejectsIncompleteKernelSet(t *testing.T) {
	for _, change := range []struct {
		name   string
		mutate func(*packetrelay.KernelLinkSetSnapshot)
	}{
		{"empty", func(s *packetrelay.KernelLinkSetSnapshot) { s.Links = nil }},
		{"wrong-namespace", func(s *packetrelay.KernelLinkSetSnapshot) { s.Namespace.Inode++ }},
		{"negative-index", func(s *packetrelay.KernelLinkSetSnapshot) { s.Links[0].Index = -1 }},
		{"duplicate-index", func(s *packetrelay.KernelLinkSetSnapshot) { s.Links[1].Index = 1 }},
		{"duplicate-name", func(s *packetrelay.KernelLinkSetSnapshot) { s.Links[1].Name = "lo" }},
		{"unsorted", func(s *packetrelay.KernelLinkSetSnapshot) { s.Links[0], s.Links[1] = s.Links[1], s.Links[0] }},
		{"bad-name", func(s *packetrelay.KernelLinkSetSnapshot) { s.Links[1].Name = "eth 0" }},
		{"unsupported-name", func(s *packetrelay.KernelLinkSetSnapshot) { s.Links[1].Name = "eth\x7f0" }},
		{"too-many", func(s *packetrelay.KernelLinkSetSnapshot) {
			s.Links = make([]packetrelay.KernelLinkIdentity, resolvedMaxLinks+1)
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			f := resolvedObserverFixture(t)
			original := f.ops.kernel
			f.ops.kernel = func(ctx context.Context, ns packetrelay.KernelNamespaceIdentity) (packetrelay.KernelLinkSetSnapshot, error) {
				s, e := original(ctx, ns)
				change.mutate(&s)
				return s, e
			}
			out, err := f.b.observeAllWith(context.Background(), f.ns, f.ops)
			if err == nil || !reflect.DeepEqual(out, ResolvedObservationSnapshot{}) || f.reads != 0 {
				t.Fatal("bad complete-set evidence accepted")
			}
		})
	}
}

func TestResolvedObservationRejectsDriftAndErrors(t *testing.T) {
	for _, name := range []string{"kernel-before-error", "kernel-after-error", "renamed", "added", "removed", "manager-change", "link-change", "getlink-error", "owner-before-error", "owner-after-error", "owner-signal", "cancel"} {
		t.Run(name, func(t *testing.T) {
			f := resolvedObserverFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			kernel, read, check := f.ops.kernel, f.ops.read, f.ops.check
			f.ops.kernel = func(ctx context.Context, ns packetrelay.KernelNamespaceIdentity) (packetrelay.KernelLinkSetSnapshot, error) {
				s, e := kernel(ctx, ns)
				if name == "kernel-before-error" || name == "kernel-after-error" && f.kernelReads == 2 {
					return s, errors.New("kernel unavailable")
				}
				if f.kernelReads == 2 {
					switch name {
					case "renamed":
						s.Links[1].Name = "renamed"
					case "added":
						s.Links = append(s.Links, packetrelay.KernelLinkIdentity{Index: 3, Name: "wlan0"})
					case "removed":
						s.Links = s.Links[:1]
					}
				}
				return s, e
			}
			f.ops.read = func(ctx context.Context, links []packetrelay.KernelLinkIdentity) (ResolvedObservationSnapshot, error) {
				s, e := read(ctx, links)
				if name == "getlink-error" {
					return s, errors.New("NoSuchLink")
				}
				if f.reads == 2 {
					switch name {
					case "manager-change":
						s.Manager.Modes.LLMNR = "yes"
					case "link-change":
						s.Links[1].DefaultRoute = false
					case "owner-signal":
						f.b.markInvalid()
					case "cancel":
						cancel()
					}
				}
				return s, e
			}
			f.ops.check = func(ctx context.Context) error {
				e := check(ctx)
				if name == "owner-before-error" || name == "owner-after-error" && f.checks == 2 {
					return errors.New("owner changed")
				}
				return e
			}
			out, err := f.b.observeAllWith(ctx, f.ns, f.ops)
			if err == nil || !reflect.DeepEqual(out, ResolvedObservationSnapshot{}) {
				t.Fatal("drift/failure returned historical success")
			}
		})
	}
}

func TestResolvedObservationProjectionCrossChecks(t *testing.T) {
	for _, name := range []string{"missing-link", "wrong-link", "wrong-path", "unlisted-dns", "unlisted-domain", "missing-dns", "missing-domain", "port-mismatch", "domain-order", "fallback-index"} {
		t.Run(name, func(t *testing.T) {
			s := resolvedSnapshotFixture(t)
			switch name {
			case "missing-link":
				s.Links = s.Links[1:]
			case "wrong-link":
				s.Links[1].Index = 3
			case "wrong-path":
				s.Links[1].Path = resolvedLinkPath(3)
			case "unlisted-dns":
				s.Manager.DNS[1].LinkIndex = 3
			case "unlisted-domain":
				s.Manager.Domains[1].LinkIndex = 3
			case "missing-dns":
				s.Manager.DNS = s.Manager.DNS[:1]
			case "missing-domain":
				s.Manager.Domains = s.Manager.Domains[:1]
			case "port-mismatch":
				s.Links[1].DNS[0].Port = 853
			case "domain-order":
				s.Links[1].Domains[0], s.Links[1].Domains[1] = s.Links[1].Domains[1], s.Links[1].Domains[0]
			case "fallback-index":
				s.Manager.FallbackDNS[0].LinkIndex = 99
			}
			if resolvedProjectionConsistent(s, []packetrelay.KernelLinkIdentity{{Index: 1, Name: "lo"}, {Index: 2, Name: "eth0"}}) {
				t.Fatal("incomplete or contradictory projection accepted")
			}
		})
	}
}

func TestResolvedObservationRejectsZeroAuthority(t *testing.T) {
	for _, b := range []*PinnedResolvedObserver{nil, {}} {
		if _, err := b.ObserveAllLinks(context.Background(), packetrelay.KernelNamespaceIdentity{Inode: 1}); err == nil {
			t.Fatal("uninitialized observer accepted")
		}
	}
	f := resolvedObserverFixture(t)
	if _, err := f.b.observeAllWith(context.Background(), packetrelay.KernelNamespaceIdentity{}, f.ops); err == nil {
		t.Fatal("zero namespace accepted")
	}
	if _, err := f.b.observeAllWith(nil, f.ns, f.ops); err == nil {
		t.Fatal("nil context accepted")
	}
}

func TestResolvedObservationPreservesKernelCleanupUncertainty(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		f := resolvedObserverFixture(t)
		kernel := f.ops.kernel
		f.ops.kernel = func(ctx context.Context, ns packetrelay.KernelNamespaceIdentity) (packetrelay.KernelLinkSetSnapshot, error) {
			snapshot, err := kernel(ctx, ns)
			if f.kernelReads == failAt {
				return snapshot, errors.Join(err, packetrelay.ErrCleanup)
			}
			return snapshot, err
		}
		if _, err := f.b.observeAllWith(context.Background(), f.ns, f.ops); !errors.Is(err, packetrelay.ErrCleanup) {
			t.Fatal("kernel cleanup uncertainty was discarded", err)
		}
	}
}
