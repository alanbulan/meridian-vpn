//go:build linux

package core

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"testing"

	"mygo-vpn/internal/nmvpn"
	"mygo-vpn/internal/packetrelay"
)

// Kernel observations are injected at the private cross-package seam. The
// shared local fixture uses unnamed socketpairs and temporary process files;
// these tests never open a TUN, issue netlink requests, or start a process.
func uniVPNKernelFixture(t *testing.T) (*uniVPNLocalFixture, *UniVPNNMLocalBinding, packetrelay.TUNKernelObservation) {
	t.Helper()
	f := newUniVPNLocalFixture(t)
	l, err := f.retain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s, err := l.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	kernel := packetrelay.TUNKernelObservation{
		TUN:       s.TUN,
		Namespace: packetrelay.KernelNamespaceIdentity{Device: 4, Inode: 19},
		Link:      packetrelay.KernelLinkObservation{Name: s.Binding.Identity.Interface, Index: 7, MTU: 1400},
	}
	return f, l, kernel
}

func assertUniVPNKernelRejected(t *testing.T, got UniVPNNMKernelObservation, err error) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(got, UniVPNNMKernelObservation{}) {
		t.Fatalf("invalid observation returned partial evidence: %#v, %v", got, err)
	}
}

func TestUniVPNNMKernelObservationCopiesWithoutAuthority(t *testing.T) {
	f, l, kernel := uniVPNKernelFixture(t)
	want, err := l.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	calls := 0
	observe := func(gotContext context.Context) (packetrelay.TUNKernelObservation, error) {
		calls++
		if gotContext != ctx {
			t.Fatal("observer did not receive caller context")
		}
		return kernel, nil
	}
	before := [2]int32{f.correlations.Load(), f.observations.Load()}
	got, err := l.observeKernelLink(ctx, observe)
	if err != nil || calls != 1 || !reflect.DeepEqual(got.Local, want) || got.Kernel != kernel {
		t.Fatal("kernel observation lost original local evidence", got, err)
	}
	for _, value := range []any{got, &got, got.Local, &got.Local, got.Kernel, &got.Kernel} {
		if _, ok := value.(UniVPNNMHostAuthority); ok {
			t.Fatalf("%T gained host authority", value)
		}
		if _, ok := value.(UniVPNNMHostBinding); ok {
			t.Fatalf("%T replaced the independent host binding", value)
		}
		if _, ok := value.(UniVPNHostLease); ok {
			t.Fatalf("%T gained cleanup authority", value)
		}
		if _, ok := value.(nmvpn.Broker); ok {
			t.Fatalf("%T gained broker authority", value)
		}
		if _, ok := value.(nmvpn.PublicationVerifier); ok {
			t.Fatalf("%T gained publication authority", value)
		}
	}
	got.Local.Offer.Routes[0] = netip.MustParsePrefix("198.51.100.0/24")
	got.Local.Offer.DNS[0] = netip.MustParseAddr("198.51.100.53")
	got.Local.Offer.Domains[0] = "changed.invalid"
	got.Local.Binding.Identity.Interface = "wrong0"
	got.Local.Native.PID++
	got.Local.TUN.Name = "wrong1"
	got.Kernel.Namespace.Inode++
	got.Kernel.Link.Index++
	again, err := l.observeKernelLink(ctx, observe)
	if err != nil || calls != 2 || !reflect.DeepEqual(again.Local, want) || again.Kernel != kernel || !reflect.DeepEqual(f.b.offer, want.Offer) {
		t.Fatal("returned evidence aliases retained metadata", err)
	}
	if after := [2]int32{f.correlations.Load(), f.observations.Load()}; after != before {
		t.Fatal("kernel read refreshed historical receipt or local relay evidence")
	}
	assertUniVPNLocalPairOpen(t, f)
}

func TestUniVPNNMKernelObservationRejectsInvalidInputBeforeCallback(t *testing.T) {
	for _, name := range []string{"nil token", "zero token", "copied token", "nil broker", "nil callback", "nil context", "canceled context"} {
		t.Run(name, func(t *testing.T) {
			f, l, kernel := uniVPNKernelFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			observe := func(context.Context) (packetrelay.TUNKernelObservation, error) {
				calls++
				return kernel, nil
			}
			switch name {
			case "nil token":
				l = nil
			case "zero token":
				l = &UniVPNNMLocalBinding{}
			case "copied token":
				copyL := *l
				l = &copyL
			case "nil broker":
				l.broker = nil
			case "nil callback":
				observe = nil
			case "nil context":
				ctx = nil
			case "canceled context":
				cancel()
			}
			got, err := l.observeKernelLink(ctx, observe)
			assertUniVPNKernelRejected(t, got, err)
			if calls != 0 {
				t.Fatal("invalid input reached kernel observer")
			}
			assertUniVPNLocalPairOpen(t, f)
		})
	}
}

func TestUniVPNNMKernelObservationRejectsKernelMismatch(t *testing.T) {
	for _, name := range []string{"kernel error", "cleanup error", "TUN name", "TUN flags", "link name", "zero index", "negative index", "missing namespace"} {
		t.Run(name, func(t *testing.T) {
			f, l, kernel := uniVPNKernelFixture(t)
			var observationErr error
			switch name {
			case "kernel error":
				observationErr = io.ErrUnexpectedEOF
			case "cleanup error":
				observationErr = errors.Join(packetrelay.ErrCleanup, io.ErrUnexpectedEOF)
			case "TUN name":
				kernel.TUN.Name = "foreign0"
			case "TUN flags":
				kernel.TUN.Flags++
			case "link name":
				kernel.Link.Name = "foreign1"
			case "zero index":
				kernel.Link.Index = 0
			case "negative index":
				kernel.Link.Index = -1
			case "missing namespace":
				kernel.Namespace.Inode = 0
			}
			calls := 0
			got, err := l.observeKernelLink(context.Background(), func(context.Context) (packetrelay.TUNKernelObservation, error) {
				calls++
				return kernel, observationErr
			})
			assertUniVPNKernelRejected(t, got, err)
			if observationErr != nil && !errors.Is(err, observationErr) {
				t.Fatal("lost underlying observation failure", err)
			}
			if name == "cleanup error" && !errors.Is(err, packetrelay.ErrCleanup) {
				t.Fatal("lost cleanup uncertainty", err)
			}
			if calls != 1 || f.b.CheckLocalBinding(context.Background(), l) != nil {
				t.Fatal("failed kernel read discarded the historical local association")
			}
			assertUniVPNLocalPairOpen(t, f)
		})
	}
}

func TestUniVPNNMKernelObservationRechecksIdentityAndContext(t *testing.T) {
	for _, name := range []string{"caller cancel", "local token", "process", "activation", "pair", "binding", "offer", "relay check"} {
		t.Run(name, func(t *testing.T) {
			f, l, kernel := uniVPNKernelFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			got, err := l.observeKernelLink(ctx, func(context.Context) (packetrelay.TUNKernelObservation, error) {
				calls++
				switch name {
				case "caller cancel":
					cancel()
				case "local token":
					f.b.local = &UniVPNNMLocalBinding{}
				case "process":
					f.b.process = &uniVPNExecProcess{}
				case "activation":
					copyA := *f.a
					f.b.activation = &copyA
				case "pair":
					copyPair := *f.p.packetPair
					f.p.packetPair = &copyPair
				case "binding":
					f.b.binding.Identity.ActivePath += "0"
				case "offer":
					f.b.offer.Domains[0] = "changed.invalid"
				case "relay check":
					l.checkRelay = func(packetrelay.TUNRelayBinding, *packetrelay.DatagramPackets) error { return io.ErrUnexpectedEOF }
				}
				return kernel, nil
			})
			assertUniVPNKernelRejected(t, got, err)
			if name == "caller cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("lost cancellation", err)
			}
			if calls != 1 {
				t.Fatal("callback did not execute exactly once")
			}
			assertUniVPNLocalPairOpen(t, f)
		})
	}
}

func TestUniVPNNMKernelObservationPublicBoundaryRejectsFakeRelay(t *testing.T) {
	f, l, _ := uniVPNKernelFixture(t)
	copyL := *l
	for _, token := range []*UniVPNNMLocalBinding{nil, {}, &copyL, l} {
		got, err := token.ObserveKernelLink(context.Background())
		assertUniVPNKernelRejected(t, got, err)
	}
	if err := f.b.CheckLocalBinding(context.Background(), l); err != nil {
		t.Fatal("public rejection discarded historical evidence", err)
	}
	assertUniVPNLocalPairOpen(t, f)
}

func TestUniVPNNMKernelObservationDoesNotRefreshLifecycle(t *testing.T) {
	f, l, kernel := uniVPNKernelFixture(t)
	f.a.cancel()
	f.b.cancel()
	before := [2]int32{f.correlations.Load(), f.observations.Load()}
	got, err := l.observeKernelLink(context.Background(), func(context.Context) (packetrelay.TUNKernelObservation, error) {
		return kernel, nil
	})
	if err != nil || got.Kernel != kernel {
		t.Fatal("historical association was incorrectly treated as a live binding", err)
	}
	if err := f.b.VerifyPublish(context.Background(), f.b.binding, f.b.offer); err == nil {
		t.Fatal("kernel evidence revived publication after cancellation")
	}
	if after := [2]int32{f.correlations.Load(), f.observations.Load()}; after != before {
		t.Fatal("kernel observation refreshed local or native/NM liveness")
	}
	assertUniVPNLocalPairOpen(t, f)
}
