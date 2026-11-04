//go:build linux

package core

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"testing"

	"github.com/godbus/dbus/v5"

	"mygo-vpn/internal/fdtransport"
	"mygo-vpn/internal/nmvpn"
	"mygo-vpn/internal/packetrelay"
)

// No native process, system bus, transport, TUN or network operation is used.
type nmServiceHosts struct {
	preflightCalls, authorizeCalls int
	fail                           bool
}

func (h *nmServiceHosts) Preflight(context.Context) error {
	h.preflightCalls++
	if h.fail {
		return errors.New("private provider detail")
	}
	return nil
}
func (h *nmServiceHosts) Authorize(context.Context, *nmvpn.ActivationReceipt, *nmvpn.Activation) (UniVPNNMHostBinding, error) {
	h.authorizeCalls++
	return nil, errors.New("no fixture authority")
}

type nmServiceGlobalPolicy struct{ done chan struct{} }

func (p *nmServiceGlobalPolicy) Done() <-chan struct{}         { return p.done }
func (*nmServiceGlobalPolicy) Preflight(context.Context) error { return nil }
func (*nmServiceGlobalPolicy) CheckPublication(context.Context, nmvpn.Binding, nmvpn.Offer) error {
	return nil
}

func nmServiceNativeFixture(t *testing.T) UniVPNNMServiceNative {
	t.Helper()
	return UniVPNNMServiceNative{
		Launcher: &UniVPNExecLauncher{Executable: "/never-executed", NativeSessionChannel: true, Isolation: &transportIsolation{},
			Transport: transportProviderFunc(func(context.Context, string, fdtransport.Endpoint) (*os.File, *os.File, error) {
				t.Error("transport unexpectedly acquired")
				return nil, nil, errors.New("denied")
			}),
			PacketProvider: packetProviderFunc(func(context.Context, string) (*os.File, packetrelay.PacketIO, error) {
				t.Error("packet unexpectedly acquired")
				return nil, nil, errors.New("denied")
			}),
			TransportGateways: map[string]fdtransport.Endpoint{"https://gateway.invalid": {Address: netip.MustParseAddr("192.0.2.1"), Port: 443}},
			AllowedCAFiles:    map[string]bool{"/not-opened": true}},
		Executable: "/never-executed", Arguments: []string{"--protocol=univpn", "--non-inter", "--passwd-on-stdin", "--no-proxy", "--no-dtls", "--user=test", "--", "https://gateway.invalid"}, Hosts: &nmServiceHosts{},
	}
}

type nmServiceJournal struct{}

func (*nmServiceJournal) LoadActivation() (*nmvpn.ActivationRecord, error) { return nil, nil }
func (*nmServiceJournal) SaveActivation(nmvpn.ActivationRecord) error      { return nil }
func (*nmServiceJournal) Load() (*nmvpn.Record, error)                     { return nil, nil }
func (*nmServiceJournal) Save(nmvpn.Record) error                          { return nil }
func (*nmServiceJournal) Clear() error                                     { return nil }

type nmServiceNoRollback struct{ UniVPNProcessIsolation }

func nmServiceConfigFixture() nmvpn.ServiceConfig {
	const uuid = "12345678-1234-1234-1234-123456789abc"
	return nmvpn.ServiceConfig{
		Bus: &nmvpn.PinnedBus{}, Plan: nmvpn.PluginPlan{UUID: uuid, Interface: "meridian0", Username: "test", Nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Network: map[string]map[string]dbus.Variant{
			"connection": {"uuid": dbus.MakeVariant(uuid), "type": dbus.MakeVariant("vpn")},
			"vpn":        {"service-type": dbus.MakeVariant(nmvpn.PluginService)},
			"ipv4":       {"method": dbus.MakeVariant("auto"), "never-default": dbus.MakeVariant(true), "ignore-auto-dns": dbus.MakeVariant(true)},
			"ipv6":       {"method": dbus.MakeVariant("disabled")}},
		Allowlist:         nmvpn.Policy{Addresses: []netip.Prefix{netip.MustParsePrefix("10.20.30.7/24")}, Endpoints: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
		ActivationJournal: &nmServiceJournal{}, PublicationJournal: &nmServiceJournal{},
		Boot:         func(context.Context) (string, error) { return "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", nil },
		GlobalPolicy: &nmServiceGlobalPolicy{done: make(chan struct{})},
	}
}

func TestUniVPNNMServiceMandatoryDeploymentGates(t *testing.T) {
	// Prove the baseline really reaches the service constructor before testing
	// each independent omission; invalid unrelated config cannot false-green.
	if s, e := NewUniVPNNMService(nmServiceConfigFixture(), nmServiceNativeFixture(t)); e != nil || s == nil {
		t.Fatal("valid conditional composition rejected", e)
	}
	for _, mode := range []string{"empty", "missing-host", "typed-nil-host", "missing-policy", "typed-nil-policy", "missing-launcher", "injected-factory", "missing-rollback"} {
		t.Run(mode, func(t *testing.T) {
			n := nmServiceNativeFixture(t)
			c := nmServiceConfigFixture()
			switch mode {
			case "empty":
				n = UniVPNNMServiceNative{}
				c = nmvpn.ServiceConfig{}
			case "missing-host":
				n.Hosts = nil
			case "typed-nil-host":
				n.Hosts = (*nmServiceHosts)(nil)
			case "missing-policy":
				c.GlobalPolicy = nil
			case "typed-nil-policy":
				c.GlobalPolicy = (*nmServiceGlobalPolicy)(nil)
			case "missing-launcher":
				n.Launcher = nil
			case "injected-factory":
				c.Factory = &uniVPNNMServiceFactory{}
			case "missing-rollback":
				n.Launcher.Isolation = nmServiceNoRollback{n.Launcher.Isolation}
			}
			if s, e := NewUniVPNNMService(c, n); e != errUniVPNNM || s != nil {
				t.Fatal("native deployment gate did not reject before generic constructor", e)
			}
		})
	}
}

func TestUniVPNNMServiceLaunchSnapshotAndValidation(t *testing.T) {
	for _, mode := range []string{"success", "nil", "executable", "native-mode", "isolation", "transport", "packet", "args", "gateway", "username"} {
		t.Run(mode, func(t *testing.T) {
			n := nmServiceNativeFixture(t)
			switch mode {
			case "nil":
				n.Launcher = nil
			case "executable":
				n.Executable = "/replacement"
			case "native-mode":
				n.Launcher.NativeSessionChannel = false
			case "isolation":
				n.Launcher.Isolation = nil
			case "transport":
				n.Launcher.Transport = nil
			case "packet":
				n.Launcher.PacketProvider = nil
			case "args":
				n.Arguments[0] = "--unsafe"
			case "gateway":
				delete(n.Launcher.TransportGateways, "https://gateway.invalid")
			case "username":
				n.Arguments[5] = "--user=another"
			}
			l, a, e := snapshotUniVPNNMLaunch(n.Launcher, n.Executable, n.Arguments, "test")
			if mode != "success" {
				if e == nil || l != nil || a != nil {
					t.Fatal("invalid launch admitted")
				}
				return
			}
			if e != nil || l == nil || !reflect.DeepEqual(a, n.Arguments) {
				t.Fatal("safe fixture rejected", e)
			}
			n.Arguments[5] = "--user=changed"
			delete(n.Launcher.TransportGateways, "https://gateway.invalid")
			n.Launcher.AllowedCAFiles["/not-opened"] = false
			if a[5] != "--user=test" || len(l.TransportGateways) != 1 || !l.AllowedCAFiles["/not-opened"] {
				t.Fatal("launch policy shares caller maps or slices")
			}
		})
	}
}

func TestUniVPNNMServiceFactoryFailsBeforeCredentialOrLaunch(t *testing.T) {
	h := &nmServiceHosts{fail: true}
	f := &uniVPNNMServiceFactory{hosts: h, launcher: &UniVPNExecLauncher{}, executable: "/never-read"}
	if e := f.Preflight(context.Background()); e != errUniVPNNM || h.preflightCalls != 1 || h.authorizeCalls != 0 {
		t.Fatal("host preflight did not fail closed")
	}
	h.fail = false
	if e := f.Preflight(context.Background()); e != errUniVPNNM {
		t.Fatal("missing executable pin accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := f.Preflight(ctx); e != errUniVPNNM {
		t.Fatal("canceled preflight accepted")
	}
	for _, pair := range []struct {
		r *nmvpn.ActivationReceipt
		a *nmvpn.Activation
	}{{nil, nil}, {&nmvpn.ActivationReceipt{}, nil}, {&nmvpn.ActivationReceipt{}, &nmvpn.Activation{}}} {
		if b, e := f.Start(context.Background(), pair.r, pair.a); e == nil || b != nil {
			t.Fatal("foreign receipt admitted")
		}
	}
	if h.authorizeCalls != 0 {
		t.Fatal("unbound receipt reached host authority")
	}
}

func TestUniVPNNMServiceNativeDoneRetainsSoleWait(t *testing.T) {
	f := newNMBridgeFixture(t)
	b := f.start(t)
	if b.Done() == nil {
		t.Fatal("missing generation lifetime")
	}
	select {
	case <-b.Done():
		t.Fatal("fresh lifetime closed")
	default:
	}
	copyOwner := &UniVPNNMBroker{self: b, run: b.run}
	if copyOwner.Done() != nil || ((*UniVPNNMBroker)(nil)).Done() != nil {
		t.Fatal("foreign lifetime escaped")
	}
	if b.Close(context.Background()) != nil {
		t.Fatal("fixture teardown failed")
	}
	select {
	case <-b.Done():
	default:
		t.Fatal("shutdown did not close lifetime")
	}
	if f.p.waits.Load() != 1 {
		t.Fatal("Done added another process waiter")
	}
}
