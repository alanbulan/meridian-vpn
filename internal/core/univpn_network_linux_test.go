//go:build linux

package core

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type networkTestProcess struct{ id int }

func (*networkTestProcess) Wait() error { return nil }
func (*networkTestProcess) Stop() error { return nil }

type networkTestSource struct {
	c             UniVPNNetworkConfig
	err, proofErr error
	proofs        int
}

func (s *networkTestSource) WaitNetworkConfig(context.Context, UniVPNNativeProcess) (UniVPNNetworkConfig, error) {
	return s.c, s.err
}
func (s *networkTestSource) ProveNetworkGone(context.Context, UniVPNNativeProcess) error {
	s.proofs++
	return s.proofErr
}

type networkTestOps struct {
	state     UniVPNLinkState
	escape    bool
	calls     []string
	fail      string
	failAfter bool
	proofErr  error
	domains   []string
}

func (o *networkTestOps) step(name string, fn func()) error {
	o.calls = append(o.calls, name)
	if o.fail == name && !o.failAfter {
		return errors.New("injected failure")
	}
	if fn != nil {
		fn()
	}
	if o.fail == name {
		return errors.New("injected uncertain outcome")
	}
	return nil
}
func (o *networkTestOps) Snapshot(context.Context, string) (UniVPNLinkState, error) {
	return o.state, o.step("snapshot", nil)
}
func (o *networkTestOps) Escape(_ context.Context, a netip.Addr) (UniVPNEscapeRoute, error) {
	return UniVPNEscapeRoute{Endpoint: a, Gateway: netip.MustParseAddr("192.0.2.1"), Device: "eth0"}, o.step("escape_lookup", nil)
}
func (o *networkTestOps) EscapeExists(context.Context, UniVPNEscapeRoute) (bool, error) {
	return o.escape, o.step("escape_exists", nil)
}
func (o *networkTestOps) AddEscape(context.Context, UniVPNEscapeRoute) error {
	return o.step("escape_add", func() { o.escape = true })
}
func (o *networkTestOps) DeleteEscape(context.Context, UniVPNEscapeRoute) error {
	return o.step("escape_delete", func() { o.escape = false })
}
func (o *networkTestOps) AddAddress(_ context.Context, _ UniVPNNetworkConfig, a netip.Prefix) error {
	return o.step("address", func() { o.state.Addresses = append(o.state.Addresses, a) })
}
func (o *networkTestOps) AddRoute(_ context.Context, _ UniVPNNetworkConfig, p netip.Prefix) error {
	return o.step("route", func() { o.state.Routes = append(o.state.Routes, p) })
}
func (o *networkTestOps) SetDNS(_ context.Context, _ UniVPNNetworkConfig, a []netip.Addr) error {
	return o.step("dns", func() {
		o.state.DNS = append([]netip.Addr(nil), a...)
		o.state.DNSDomains = append([]string(nil), o.domains...)
		o.state.DNSDefaultRouteKnown = true
	})
}
func (o *networkTestOps) SetUp(context.Context, UniVPNNetworkConfig) error {
	return o.step("up", func() { o.state.Up = true })
}
func (o *networkTestOps) RevertDNS(context.Context, UniVPNNetworkConfig) error {
	return o.step("dns_revert", func() { o.state.DNS = nil; o.state.DNSDomains = nil })
}
func (o *networkTestOps) DeleteLink(context.Context, UniVPNNetworkConfig) error {
	return o.step("link_delete", func() { o.state = UniVPNLinkState{} })
}
func (o *networkTestOps) ProveAbsent(context.Context, UniVPNNetworkConfig) error {
	if o.proofErr != nil {
		return o.proofErr
	}
	if o.state.Exists || len(o.state.Routes) > 0 || len(o.state.DNS) > 0 || len(o.state.DNSDomains) > 0 {
		return errors.New("resources remain")
	}
	return o.step("prove_absent", nil)
}
func networkFixture(t *testing.T) (*UniVPNLinuxNetworkController, *networkTestSource, *networkTestOps, *networkTestProcess) {
	t.Helper()
	c := UniVPNNetworkConfig{Interface: "uvtun0", Index: 77, Alias: "univpn-session-abcdef0123456789", Addresses: []netip.Prefix{netip.MustParsePrefix("10.70.0.2/24")}, Routes: []netip.Prefix{netip.MustParsePrefix("10.80.0.0/16")}, DNS: []netip.Addr{netip.MustParseAddr("10.80.0.53")}, Endpoint: netip.MustParseAddr("198.51.100.5")}
	s := &networkTestSource{c: c}
	o := &networkTestOps{state: UniVPNLinkState{Exists: true, Index: c.Index, Alias: c.Alias, Kind: "tun"}, domains: []string{"~corp.example"}}
	n, e := NewUniVPNLinuxNetworkController(s, o, UniVPNNetworkPolicy{Routes: c.Routes, Addresses: c.Addresses, DNS: c.DNS, Endpoints: []netip.Addr{c.Endpoint}, DNSDomains: o.domains})
	if e != nil {
		t.Fatal(e)
	}
	return n, s, o, &networkTestProcess{1}
}
func TestUniVPNNetworkReadinessAndCleanup(t *testing.T) {
	n, s, o, p := networkFixture(t)
	if e := n.WaitReady(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	if !o.escape || !o.state.Up {
		t.Fatal("not configured")
	}
	if e := n.Cleanup(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	if o.escape || o.state.Exists || s.proofs != 1 {
		t.Fatal("cleanup not proven")
	}
	before := len(o.calls)
	if e := n.Cleanup(context.Background(), p); e != nil || len(o.calls) != before {
		t.Fatal("cleanup not idempotent")
	}
}
func TestUniVPNNetworkRejectsPushedConfigurationBeforeMutation(t *testing.T) {
	for _, what := range []string{"route", "default", "dns", "address", "endpoint", "alias", "name"} {
		t.Run(what, func(t *testing.T) {
			n, s, o, p := networkFixture(t)
			switch what {
			case "route":
				s.c.Routes = []netip.Prefix{netip.MustParsePrefix("10.80.1.0/24")}
			case "default":
				s.c.Routes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
			case "dns":
				s.c.DNS = []netip.Addr{netip.MustParseAddr("8.8.8.8")}
			case "address":
				s.c.Addresses = []netip.Prefix{netip.MustParsePrefix("10.70.0.3/24")}
			case "endpoint":
				s.c.Endpoint = netip.MustParseAddr("198.51.100.6")
			case "alias":
				s.c.Alias = "bad"
			case "name":
				s.c.Interface = "tun0;id"
			}
			if e := n.WaitReady(context.Background(), p); e == nil {
				t.Fatal("accepted pushed config")
			}
			if len(o.calls) != 0 {
				t.Fatal(o.calls)
			}
			if e := n.Cleanup(context.Background(), p); e != nil {
				t.Fatal(e)
			}
			if s.proofs != 1 {
				t.Fatal("source absence not checked")
			}
		})
	}
}
func TestUniVPNNetworkPartialSetupRollback(t *testing.T) {
	for _, stage := range []string{"address", "route", "dns", "up"} {
		t.Run(stage, func(t *testing.T) {
			n, _, o, p := networkFixture(t)
			o.fail = stage
			o.failAfter = true
			if e := n.WaitReady(context.Background(), p); e == nil {
				t.Fatal("setup should fail")
			}
			o.fail = ""
			if e := n.Cleanup(context.Background(), p); e != nil {
				t.Fatal(e)
			}
			if o.escape || o.state.Exists {
				t.Fatal("partial setup leaked")
			}
		})
	}
}
func TestUniVPNNetworkUncertainEscapeNeverDeleted(t *testing.T) {
	n, _, o, p := networkFixture(t)
	o.fail = "escape_add"
	o.failAfter = true
	if e := n.WaitReady(context.Background(), p); e == nil {
		t.Fatal("expected failure")
	}
	o.fail = ""
	if e := n.Cleanup(context.Background(), p); e == nil {
		t.Fatal("uncertainty not quarantined")
	}
	if uniVPNContains(o.calls, "escape_delete") {
		t.Fatal("deleted uncertain route")
	}
	if e := n.WaitReady(context.Background(), p); e == nil {
		t.Fatal("dirty controller reused")
	}
}
func TestUniVPNNetworkForeignResourcesUntouched(t *testing.T) {
	for _, kind := range []string{"alias", "index", "address", "route", "dns"} {
		t.Run(kind, func(t *testing.T) {
			n, _, o, p := networkFixture(t)
			switch kind {
			case "alias":
				o.state.Alias = "foreign"
			case "index":
				o.state.Index++
			case "address":
				o.state.Addresses = []netip.Prefix{netip.MustParsePrefix("10.1.1.1/24")}
			case "route":
				o.state.Routes = []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}
			case "dns":
				o.state.DNS = []netip.Addr{netip.MustParseAddr("10.1.1.2")}
			}
			if e := n.WaitReady(context.Background(), p); e == nil {
				t.Fatal("foreign TUN accepted")
			}
			if e := n.Cleanup(context.Background(), p); e != nil {
				t.Fatal(e)
			}
			if uniVPNContains(o.calls, "link_delete") || uniVPNContains(o.calls, "escape_add") {
				t.Fatal("foreign state touched")
			}
		})
	}
}
func TestUniVPNNetworkReplacementCleanupRefused(t *testing.T) {
	n, _, o, p := networkFixture(t)
	if e := n.WaitReady(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	o.state.Index++
	if e := n.Cleanup(context.Background(), p); e == nil {
		t.Fatal("replacement deleted")
	}
	if uniVPNContains(o.calls, "link_delete") {
		t.Fatal("replacement mutation")
	}
}
func TestUniVPNNetworkMissingSourceProofQuarantines(t *testing.T) {
	n, s, _, p := networkFixture(t)
	s.err = errors.New("hook acquisition failed")
	s.proofErr = errors.New("partial hook state unknown")
	if n.WaitReady(context.Background(), p) == nil {
		t.Fatal("expected error")
	}
	if n.Cleanup(context.Background(), p) == nil {
		t.Fatal("missing hook proof accepted")
	}
}
func TestUniVPNNetworkAbsenceProofRequired(t *testing.T) {
	n, _, o, p := networkFixture(t)
	if e := n.WaitReady(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	o.proofErr = errors.New("resolver unavailable")
	if e := n.Cleanup(context.Background(), p); e == nil {
		t.Fatal("missing absence proof accepted")
	}
}
func TestUniVPNNetworkDuplicateSetMismatch(t *testing.T) {
	if sameUniVPNSet([]string{"a", "a"}, []string{"a", "b"}) || sameUniVPNSet([]string{"a", "b"}, []string{"a", "a"}) {
		t.Fatal("duplicate equality accepted")
	}
}

type networkCommandMock struct {
	calls    []string
	response func(string, []string) ([]byte, error)
}

func (m *networkCommandMock) Run(_ context.Context, p string, a ...string) ([]byte, error) {
	m.calls = append(m.calls, p+" "+strings.Join(a, " "))
	return m.response(p, a)
}
func commandOpsFixture(t *testing.T, r *networkCommandMock) *UniVPNCommandNetworkOps {
	t.Helper()
	o, e := NewUniVPNCommandNetworkOps(r, networkTestLease{}, "/trusted/ip", "/trusted/resolvectl", []string{"~corp.example"})
	if e != nil {
		t.Fatal(e)
	}
	if len(r.calls) > 0 {
		t.Fatal("constructor executed host command")
	}
	return o
}
func TestUniVPNNetworkCommandEscapeOwnership(t *testing.T) {
	for _, what := range []string{"own", "table", "protocol", "metric", "device"} {
		t.Run(what, func(t *testing.T) {
			table, protocol, metric, dev := "main", "186", uint32(1073741901), "eth0"
			switch what {
			case "table":
				table = "123"
			case "protocol":
				protocol = "boot"
			case "metric":
				metric++
			case "device":
				dev = "eth1"
			}
			r := &networkCommandMock{response: func(_ string, a []string) ([]byte, error) {
				if a[0] == "-6" {
					return []byte("[]"), nil
				}
				return []byte(`[{"dst":"198.51.100.5","gateway":"192.0.2.1","dev":"` + dev + `","table":"` + table + `","protocol":"` + protocol + `","metric":` + strconvUint(metric) + `}]`), nil
			}}
			o := commandOpsFixture(t, r)
			exists, e := o.EscapeExists(context.Background(), UniVPNEscapeRoute{Endpoint: netip.MustParseAddr("198.51.100.5"), Gateway: netip.MustParseAddr("192.0.2.1"), Device: "eth0", Metric: 1073741901})
			if what == "own" {
				if e != nil || !exists {
					t.Fatal(exists, e)
				}
			} else if e == nil {
				t.Fatal("foreign route accepted")
			}
		})
	}
}
func strconvUint(v uint32) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	s := ""
	for v > 0 {
		s = string(digits[v%10]) + s
		v /= 10
	}
	return s
}
func TestUniVPNNetworkCommandAbsenceRequiresResolver(t *testing.T) {
	for _, what := range []string{"clean", "dns", "domain", "default", "failure"} {
		t.Run(what, func(t *testing.T) {
			r := &networkCommandMock{response: func(p string, a []string) ([]byte, error) {
				if p == "/trusted/ip" {
					return []byte("[]"), nil
				}
				if what == "failure" {
					return nil, errors.New("resolver failed")
				}
				if what == "dns" && a[0] == "dns" {
					return []byte("Global:\nLink 77 (uvtun0): 10.80.0.53\n"), nil
				}
				if what == "domain" && a[0] == "domain" {
					return []byte("Global:\nLink 77 (uvtun0): ~corp.example\n"), nil
				}
				if what == "default" && a[0] == "default-route" {
					return []byte("Link 77 (uvtun0): yes\n"), nil
				}
				return []byte("Global:\n"), nil
			}}
			o := commandOpsFixture(t, r)
			e := o.ProveAbsent(context.Background(), UniVPNNetworkConfig{Interface: "uvtun0", Index: 77, Alias: "univpn-session-abcdef0123456789"})
			if (e == nil) != (what == "clean") {
				t.Fatal(e)
			}
		})
	}
}
func TestUniVPNNetworkCommandRefusesReplacedTUN(t *testing.T) {
	r := &networkCommandMock{response: func(string, []string) ([]byte, error) {
		return []byte(`[{"ifindex":78,"ifname":"uvtun0","ifalias":"foreign","linkinfo":{"info_kind":"tun"}}]`), nil
	}}
	o := commandOpsFixture(t, r)
	if e := o.DeleteLink(context.Background(), UniVPNNetworkConfig{Interface: "uvtun0", Index: 77, Alias: "univpn-session-abcdef0123456789"}); e == nil {
		t.Fatal("foreign link deleted")
	}
	if len(r.calls) != 1 || strings.Contains(r.calls[0], "delete") {
		t.Fatal(r.calls)
	}
}

type networkTestLease struct{}

func (networkTestLease) AssertHeld(context.Context, UniVPNNetworkConfig) error { return nil }

func TestUniVPNNetworkCancelledBeforeWrites(t *testing.T) {
	n, _, o, p := networkFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := n.WaitReady(ctx, p); e == nil {
		t.Fatal("cancelled setup succeeded")
	}
	if uniVPNContains(o.calls, "escape_add") {
		t.Fatal("cancelled setup mutated route")
	}
	if e := n.Cleanup(context.Background(), p); e != nil {
		t.Fatal(e)
	}
}
func TestUniVPNNetworkWrongProcessCleanupRefused(t *testing.T) {
	n, _, o, p := networkFixture(t)
	if e := n.WaitReady(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	before := len(o.calls)
	if n.Cleanup(context.Background(), &networkTestProcess{2}) == nil || len(o.calls) != before {
		t.Fatal("wrong process cleanup was not rejected")
	}
}

type networkDeniedLease struct{}

func (networkDeniedLease) AssertHeld(context.Context, UniVPNNetworkConfig) error {
	return errors.New("no exclusive namespace lease")
}
func TestUniVPNNetworkCommandMissingLeaseFailsClosed(t *testing.T) {
	r := &networkCommandMock{response: func(string, []string) ([]byte, error) { t.Fatal("command ran without lease"); return nil, nil }}
	if _, e := NewUniVPNCommandNetworkOps(r, nil, "/trusted/ip", "/trusted/resolvectl", nil); e == nil {
		t.Fatal("missing lease accepted")
	}
	o, e := NewUniVPNCommandNetworkOps(r, networkDeniedLease{}, "/trusted/ip", "/trusted/resolvectl", nil)
	if e != nil {
		t.Fatal(e)
	}
	if o.DeleteLink(context.Background(), UniVPNNetworkConfig{}) == nil {
		t.Fatal("lease denial ignored")
	}
	if o.DeleteEscape(context.Background(), UniVPNEscapeRoute{}) == nil {
		t.Fatal("escape cleanup ignored lease denial")
	}
}
func TestUniVPNNetworkDNSDefaultRouteEvidence(t *testing.T) {
	for _, what := range []string{"no", "missing", "duplicate", "yes"} {
		t.Run(what, func(t *testing.T) {
			n, _, o, p := networkFixture(t)
			if e := n.WaitReady(context.Background(), p); e != nil {
				t.Fatal(e)
			}
			r := &networkCommandMock{response: func(path string, a []string) ([]byte, error) {
				if path == "/trusted/ip" {
					if a[0] == "-json" {
						return []byte(`[{"ifindex":77,"ifname":"uvtun0","ifalias":"univpn-session-abcdef0123456789","flags":["UP"],"linkinfo":{"info_kind":"tun"}}]`), nil
					}
					return []byte("[]"), nil
				}
				switch a[0] {
				case "dns":
					return []byte("Global:\nLink 77 (uvtun0): 10.80.0.53\n"), nil
				case "domain":
					return []byte("Global:\nLink 77 (uvtun0): ~corp.example\n"), nil
				case "default-route":
					switch what {
					case "no":
						return []byte("Link 77 (uvtun0): no\n"), nil
					case "yes":
						return []byte("Link 77 (uvtun0): yes\n"), nil
					case "duplicate":
						return []byte("Link 77 (uvtun0): yes\nLink 77 (uvtun0): no\n"), nil
					default:
						return []byte(""), nil
					}
				}
				return nil, errors.New("unexpected command")
			}}
			ops := commandOpsFixture(t, r)
			state, e := ops.Snapshot(context.Background(), "uvtun0")
			if what == "duplicate" {
				if e == nil {
					t.Fatal("duplicate default-route accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			good := state.DNSDefaultRouteKnown && !state.DNSDefaultRoute
			if good != (what == "no") {
				t.Fatal(state)
			}
			_ = o
		})
	}
}

func TestUniVPNNetworkRejectsAmbiguousInterfaceNames(t *testing.T){for _,name:=range []string{"77","-a","--help","lo","tun0;id","tun0\n"}{if safeUniVPNLink(name){t.Fatalf("accepted ambiguous name %q",name)}};if !safeUniVPNLink("uvtun0"){t.Fatal("normal TUN rejected")}}
