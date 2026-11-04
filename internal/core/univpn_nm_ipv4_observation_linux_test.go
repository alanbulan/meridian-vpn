//go:build linux

package core

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"testing"

	"github.com/godbus/dbus/v5"

	"mygo-vpn/internal/nmvpn"
)

// Reuses synthetic retained handles only. No host bus, NM, TUN or gateway.
func uniVPNIPv4Fixture(t *testing.T) (*uniVPNLocalFixture, *UniVPNNMLocalBinding, nmvpn.IPv4ObservationSnapshot) {
	t.Helper()
	f := newUniVPNLocalFixture(t)
	l, err := f.retain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return f, l, nmvpn.IPv4ObservationSnapshot{
		Binding:       f.b.binding,
		Address:       f.b.offer.Address,
		IP4Config:     "/org/freedesktop/NetworkManager/IP4Config/7",
		ParentDevices: []dbus.ObjectPath{"/org/freedesktop/NetworkManager/Devices/1"},
		Routes:        []nmvpn.IPv4ObservedRoute{{Destination: f.b.offer.Routes[0], Metric: 50}},
	}
}

func TestUniVPNNMIPv4ObservationCopiesAndPreservesOwners(t *testing.T) {
	f, l, projection := uniVPNIPv4Fixture(t)
	ctx := context.Background()
	calls := 0
	got, err := l.observeIPv4(ctx, func(received context.Context) (nmvpn.IPv4ObservationSnapshot, error) {
		calls++
		if received != ctx {
			t.Fatal("lost caller context")
		}
		return projection, nil
	})
	if err != nil || calls != 1 || !reflect.DeepEqual(got.IPv4, projection) || got.Local.Binding != f.b.binding {
		t.Fatal("lost original evidence", got, err)
	}
	for _, value := range []any{got, &got, got.IPv4, &got.IPv4} {
		if _, ok := value.(UniVPNNMHostAuthority); ok {
			t.Fatal("gained host authority")
		}
		if _, ok := value.(UniVPNNMHostBinding); ok {
			t.Fatal("replaced independent host binding")
		}
		if _, ok := value.(UniVPNHostLease); ok {
			t.Fatal("gained cleanup authority")
		}
		if _, ok := value.(nmvpn.PublicationVerifier); ok {
			t.Fatal("gained publication authority")
		}
	}
	got.IPv4.Routes[0].Metric++
	got.IPv4.ParentDevices[0] = "/changed"
	got.Local.Offer.Routes[0] = netip.MustParsePrefix("198.51.100.0/24")
	if projection.Routes[0].Metric != 50 || projection.ParentDevices[0] == "/changed" || l.snapshot.Offer.Routes[0] != netip.MustParsePrefix("10.50.0.0/16") {
		t.Fatal("returned collections alias retained evidence")
	}
	assertUniVPNLocalPairOpen(t, f)
}

func TestUniVPNNMIPv4ObservationRejectsBeforeRead(t *testing.T) {
	for _, name := range []string{"nil", "zero", "copy", "broker", "receipt", "callback", "context", "canceled"} {
		t.Run(name, func(t *testing.T) {
			f, l, projection := uniVPNIPv4Fixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			observe := func(context.Context) (nmvpn.IPv4ObservationSnapshot, error) {
				calls++
				return projection, nil
			}
			switch name {
			case "nil":
				l = nil
			case "zero":
				l = &UniVPNNMLocalBinding{}
			case "copy":
				copyL := *l
				l = &copyL
			case "broker":
				l.broker = nil
			case "receipt":
				l.receipt = nil
			case "callback":
				observe = nil
			case "context":
				ctx = nil
			case "canceled":
				cancel()
			}
			got, err := l.observeIPv4(ctx, observe)
			if err == nil || !reflect.DeepEqual(got, UniVPNNMIPv4Observation{}) || calls != 0 {
				t.Fatal("invalid input reached observer", got, err)
			}
			assertUniVPNLocalPairOpen(t, f)
		})
	}
}

func TestUniVPNNMIPv4ObservationRejectsMismatchAndDrift(t *testing.T) {
	for _, name := range []string{"error", "session", "owner", "bus", "active", "profile", "interface", "address", "cancel", "local", "worker", "offer"} {
		t.Run(name, func(t *testing.T) {
			f, l, projection := uniVPNIPv4Fixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var failure error
			got, err := l.observeIPv4(ctx, func(context.Context) (nmvpn.IPv4ObservationSnapshot, error) {
				switch name {
				case "error":
					failure = io.ErrUnexpectedEOF
				case "session":
					projection.Binding.Identity.Session += "different"
				case "owner":
					projection.Binding.Identity.Owner = ":1.999"
				case "bus":
					projection.Binding.Identity.BusID = "different"
				case "active":
					projection.Binding.Identity.ActivePath += "0"
				case "profile":
					projection.Binding.ConnectionPath += "0"
				case "interface":
					projection.Binding.Identity.Interface = "foreign0"
				case "address":
					projection.Address = netip.MustParsePrefix("10.0.0.1/24")
				case "cancel":
					cancel()
					failure = context.Canceled
				case "local":
					f.b.local = &UniVPNNMLocalBinding{}
				case "worker":
					f.b.process = &uniVPNExecProcess{}
				case "offer":
					f.b.offer.Domains[0] = "changed.invalid"
				}
				return projection, failure
			})
			if err == nil || !reflect.DeepEqual(got, UniVPNNMIPv4Observation{}) {
				t.Fatal("returned partial or mismatched evidence", got, err)
			}
			if failure != nil && !errors.Is(err, failure) {
				t.Fatal("lost underlying error", err)
			}
			assertUniVPNLocalPairOpen(t, f)
		})
	}
}

func TestUniVPNNMIPv4ObservationPublicBoundaryRejectsSyntheticActivation(t *testing.T) {
	f, l, _ := uniVPNIPv4Fixture(t)
	copyL := *l
	for _, token := range []*UniVPNNMLocalBinding{nil, {}, &copyL, l} {
		got, err := token.ObserveIPv4(context.Background())
		if err == nil || !reflect.DeepEqual(got, UniVPNNMIPv4Observation{}) {
			t.Fatal("synthetic activation accepted", err)
		}
	}
	assertUniVPNLocalPairOpen(t, f)
}
