//go:build linux

package nmvpn

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type serviceTestActivationJournal struct{ record *ActivationRecord }

func (j *serviceTestActivationJournal) LoadActivation() (*ActivationRecord, error) {
	return j.record, nil
}
func (j *serviceTestActivationJournal) SaveActivation(r ActivationRecord) error {
	j.record = &r
	return nil
}

type serviceTestFactory struct {
	preflight func(context.Context) error
	start     func(context.Context, *ActivationReceipt, *Activation) (ServiceBackend, error)
}

func (f *serviceTestFactory) Preflight(ctx context.Context) error {
	if f.preflight != nil {
		return f.preflight(ctx)
	}
	return nil
}
func (f *serviceTestFactory) Start(ctx context.Context, r *ActivationReceipt, a *Activation) (ServiceBackend, error) {
	return f.start(ctx, r, a)
}

type serviceTestPolicy struct {
	done      chan struct{}
	preflight func(context.Context) error
	check     func(context.Context, Binding, Offer) error
}

func (p *serviceTestPolicy) Done() <-chan struct{} { return p.done }
func (p *serviceTestPolicy) Preflight(ctx context.Context) error {
	if p.preflight != nil {
		return p.preflight(ctx)
	}
	return nil
}
func (p *serviceTestPolicy) CheckPublication(ctx context.Context, b Binding, o Offer) error {
	if p.check != nil {
		return p.check(ctx, b, o)
	}
	return nil
}

type serviceTestBackend struct {
	verify func(context.Context, Binding, Offer) error
}

func (b *serviceTestBackend) Verify(context.Context, Binding, Offer) error { return nil }
func (b *serviceTestBackend) Stop(context.Context, Binding) error          { return nil }
func (b *serviceTestBackend) ProveAbsent(context.Context, Binding) error   { return nil }
func (b *serviceTestBackend) VerifyPublish(c context.Context, v Binding, o Offer) error {
	return b.verify(c, v, o)
}
func (b *serviceTestBackend) Binding() Binding            { return Binding{} }
func (b *serviceTestBackend) Offer() Offer                { return Offer{} }
func (b *serviceTestBackend) Done() <-chan struct{}       { return nil }
func (b *serviceTestBackend) Close(context.Context) error { return nil }

func serviceConstructorConfig(t *testing.T) ServiceConfig {
	t.Helper()
	network, id := profileFixture()
	plan, err := NewPluginPlan(id.UUID, id.Interface, "alice")
	if err != nil {
		t.Fatal(err)
	}
	_, policy := configFixture()
	return ServiceConfig{Bus: &PinnedBus{}, Plan: plan, Network: network, Allowlist: policy,
		ActivationJournal: &serviceTestActivationJournal{}, PublicationJournal: &memoryJournal{trace: new([]string)},
		Boot:    func(context.Context) (string, error) { return "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", nil },
		Factory: &serviceTestFactory{}, GlobalPolicy: &serviceTestPolicy{done: make(chan struct{})}}
}

func TestServiceConstructorRequiresEveryDependency(t *testing.T) {
	cases := map[string]func(*ServiceConfig){
		"bus":                           func(c *ServiceConfig) { c.Bus = nil },
		"plan":                          func(c *ServiceConfig) { c.Plan = PluginPlan{} },
		"profile":                       func(c *ServiceConfig) { c.Network = nil },
		"activation journal":            func(c *ServiceConfig) { c.ActivationJournal = nil },
		"typed nil activation journal":  func(c *ServiceConfig) { c.ActivationJournal = (*serviceTestActivationJournal)(nil) },
		"publication journal":           func(c *ServiceConfig) { c.PublicationJournal = nil },
		"typed nil publication journal": func(c *ServiceConfig) { c.PublicationJournal = (*memoryJournal)(nil) },
		"boot":                          func(c *ServiceConfig) { c.Boot = nil },
		"factory":                       func(c *ServiceConfig) { c.Factory = nil },
		"typed nil factory":             func(c *ServiceConfig) { c.Factory = (*serviceTestFactory)(nil) },
		"global policy":                 func(c *ServiceConfig) { c.GlobalPolicy = nil },
		"typed nil global policy":       func(c *ServiceConfig) { c.GlobalPolicy = (*serviceTestPolicy)(nil) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := serviceConstructorConfig(t)
			mutate(&c)
			if s, err := NewService(c); err == nil || s != nil {
				t.Fatal("missing dependency admitted")
			}
		})
	}
	if s, err := NewService(ServiceConfig{}); err == nil || s != nil {
		t.Fatal("zero configuration admitted")
	}
}

func TestServiceConstructorSnapshotsProvisioningWithoutIO(t *testing.T) {
	c := serviceConstructorConfig(t)
	// These callbacks would panic if construction attempted operational admission.
	c.Factory = &serviceTestFactory{preflight: func(context.Context) error { panic("constructor performed preflight") }}
	c.GlobalPolicy = &serviceTestPolicy{done: make(chan struct{}), preflight: func(context.Context) error { panic("constructor performed policy IO") }}
	before := cloneSafeProfile(c.Network)
	policy := copyServicePolicy(c.Allowlist)
	s, err := NewService(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Network["connection"]["uuid"] = dbus.MakeVariant("changed")
	delete(c.Network, "ipv6")
	c.Allowlist.Addresses[0] = netip.MustParsePrefix("203.0.113.1/32")
	c.Allowlist.Endpoints[0] = netip.MustParseAddr("203.0.113.2")
	c.Allowlist.Routes[0] = netip.MustParsePrefix("203.0.113.0/24")
	if !reflect.DeepEqual(before, s.config.Network) || !reflect.DeepEqual(policy, s.config.Allowlist) {
		t.Fatal("caller mutated retained provisioning")
	}
	if _, ok := reflect.TypeOf(ServiceResult{}).FieldByName("Ready"); ok {
		t.Fatal("local publication must not expose readiness")
	}
	// Explicit field construction avoids copying atomic state (and go vet's copylocks).
	copied := &Service{self: s, config: s.config}
	if r, e := copied.Run(context.Background()); e == nil || r != (ServiceResult{}) {
		t.Fatal("copied service ran")
	}
	if _, e := s.Run(nil); e == nil {
		t.Fatal("nil context accepted")
	}
	var absent *Service
	if _, e := absent.Run(context.Background()); e == nil {
		t.Fatal("nil service accepted")
	}
	if _, e := (&Service{}).Run(context.Background()); e == nil {
		t.Fatal("zero service accepted")
	}
}

func TestServiceBrokerChecksBeforeAndAfterPolicyAndCopiesOffer(t *testing.T) {
	for _, mode := range []string{"success", "first native denial", "policy denial", "second native denial", "policy cancels", "policy ends generation", "second native ends generation", "second native cancels", "already ended generation", "policy revokes", "final native revokes policy", "already revoked policy"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			offer, _ := configFixture()
			want := copyOffer(offer)
			var order []string
			calls := 0
			done := make(chan struct{})
			policyDone := make(chan struct{})
			if mode == "already revoked policy" {
				close(policyDone)
			}
			if mode == "already ended generation" {
				close(done)
			}
			backend := &serviceTestBackend{verify: func(_ context.Context, _ Binding, o Offer) error {
				calls++
				order = append(order, "native")
				if calls == 2 && mode == "final native revokes policy" {
					close(policyDone)
				}
				if calls == 2 && mode == "second native ends generation" {
					close(done)
				}
				if calls == 2 && mode == "second native cancels" {
					cancel()
				}
				if !reflect.DeepEqual(o, want) {
					t.Error("callback mutation crossed verification boundary")
				}
				o.Routes[0] = netip.MustParsePrefix("203.0.113.0/24")
				if mode == "first native denial" && calls == 1 || mode == "second native denial" && calls == 2 {
					return injectedError
				}
				return nil
			}}
			policy := &serviceTestPolicy{done: policyDone, check: func(_ context.Context, _ Binding, o Offer) error {
				order = append(order, "policy")
				if !reflect.DeepEqual(o, want) {
					t.Error("policy received mutated offer")
				}
				o.Routes[0] = netip.MustParsePrefix("198.51.100.0/24")
				if mode == "policy revokes" {
					close(policyDone)
				}
				if mode == "policy denial" {
					return injectedError
				}
				if mode == "policy cancels" {
					cancel()
				}
				if mode == "policy ends generation" {
					close(done)
				}
				return nil
			}}
			err := (&serviceBroker{ServiceBackend: backend, policy: policy, done: done, policyDone: policy.done}).VerifyPublish(ctx, Binding{}, offer)
			if (err == nil) != (mode == "success") {
				t.Fatalf("unexpected gate result: %v", err)
			}
			if err != nil && !errors.Is(err, errService) {
				t.Fatal("callback error was not sanitized")
			}
			expected := []string{"native", "policy", "native"}
			if mode == "already ended generation" || mode == "already revoked policy" {
				expected = nil
			} else if mode == "first native denial" {
				expected = expected[:1]
			} else if mode == "policy denial" || mode == "policy cancels" || mode == "policy ends generation" || mode == "policy revokes" {
				expected = expected[:2]
			}
			if !reflect.DeepEqual(order, expected) || !reflect.DeepEqual(offer, want) {
				t.Fatal("gate order or immutable offer contract failed", order)
			}
		})
	}
}

func TestServiceCanceledRunIsConsumedWithoutAdmission(t *testing.T) {
	c := serviceConstructorConfig(t)
	calls := 0
	c.Factory = &serviceTestFactory{preflight: func(context.Context) error { calls++; return nil }}
	s, err := NewService(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r, e := s.Run(ctx); e == nil || r != (ServiceResult{}) {
		t.Fatal("canceled Run admitted")
	}
	if r, e := s.Run(context.Background()); e == nil || r != (ServiceResult{}) {
		t.Fatal("canceled Run was replayable")
	}
	if calls != 0 {
		t.Fatal("canceled Run called factory")
	}
}

func TestServiceStartupDeadlineStopsWithoutCanceling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finish := serviceStartupDeadline(200*time.Millisecond, cancel)
	finish()
	finish()
	select {
	case <-ctx.Done():
		t.Fatal("stopped timer canceled generation")
	case <-time.After(250 * time.Millisecond):
	}
	if ctx.Err() != nil {
		t.Fatal("stopping startup deadline canceled live generation")
	}
}
func TestServiceStartupDeadlineJoinsFiredCallback(t *testing.T) {
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	finish := serviceStartupDeadline(0, func() { close(entered); <-release })
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("startup deadline did not fire")
	}
	go func() { finish(); close(finished) }()
	select {
	case <-finished:
		close(release)
		t.Fatal("finish returned before callback joined")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("startup callback was not joined")
	}
	finish()
}

func TestServiceRejectsUnsafeAllowlist(t *testing.T) {
	cases := map[string]func(*Policy){
		"empty addresses":     func(p *Policy) { p.Addresses = nil },
		"empty endpoints":     func(p *Policy) { p.Endpoints = nil },
		"invalid address":     func(p *Policy) { p.Addresses[0] = netip.Prefix{} },
		"IPv6 address":        func(p *Policy) { p.Addresses[0] = netip.MustParsePrefix("2001:db8::1/64") },
		"default address":     func(p *Policy) { p.Addresses[0] = netip.MustParsePrefix("10.0.0.1/0") },
		"duplicate address":   func(p *Policy) { p.Addresses = append(p.Addresses, p.Addresses[0]) },
		"invalid endpoint":    func(p *Policy) { p.Endpoints[0] = netip.Addr{} },
		"loopback endpoint":   func(p *Policy) { p.Endpoints[0] = netip.MustParseAddr("127.0.0.1") },
		"duplicate endpoint":  func(p *Policy) { p.Endpoints = append(p.Endpoints, p.Endpoints[0]) },
		"endpoint in address": func(p *Policy) { p.Endpoints[0] = netip.MustParseAddr("10.20.30.8") },
		"invalid route":       func(p *Policy) { p.Routes[0] = netip.Prefix{} },
		"IPv6 route":          func(p *Policy) { p.Routes[0] = netip.MustParsePrefix("2001:db8::/64") },
		"default route":       func(p *Policy) { p.Routes[0] = netip.MustParsePrefix("0.0.0.0/0") },
		"unmasked route":      func(p *Policy) { p.Routes[0] = netip.MustParsePrefix("10.50.1.1/16") },
		"duplicate route":     func(p *Policy) { p.Routes = append(p.Routes, p.Routes[0]) },
		"endpoint in route":   func(p *Policy) { p.Routes[0] = netip.MustParsePrefix("192.0.2.0/24") },
		"oversized addresses": func(p *Policy) { p.Addresses = make([]netip.Prefix, 129) },
		"oversized endpoints": func(p *Policy) { p.Endpoints = make([]netip.Addr, 129) },
		"oversized routes":    func(p *Policy) { p.Routes = make([]netip.Prefix, 129) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := serviceConstructorConfig(t)
			mutate(&c.Allowlist)
			if s, e := NewService(c); e == nil || s != nil {
				t.Fatal("unsafe deployment allowlist admitted")
			}
		})
	}
	c := serviceConstructorConfig(t)
	c.Allowlist.Routes = nil
	if _, e := NewService(c); e != nil {
		t.Fatal("empty optional routes rejected", e)
	}
}
