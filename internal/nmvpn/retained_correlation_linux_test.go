//go:build linux

package nmvpn

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
)

// These callbacks deliberately panic even for reads. Retained correlation must
// use only local evidence, never refresh boot identity or persisted state.
type retainedCorrelationNoIOJournal struct{}

func (*retainedCorrelationNoIOJournal) LoadActivation() (*ActivationRecord, error) {
	panic("retained correlation read the journal")
}
func (*retainedCorrelationNoIOJournal) SaveActivation(ActivationRecord) error {
	panic("retained correlation wrote the journal")
}

type retainedCorrelationFixture struct {
	r *ActivationReceipt
	a *Activation
	m *ActivationManager
	p *Plugin
	b *PinnedBus
}

func newRetainedCorrelationFixture(t *testing.T) *retainedCorrelationFixture {
	t.Helper()
	record := activationRecordFixture()
	record.Phase = "correlated"
	record.ConnectionPath = "/org/freedesktop/NetworkManager/Settings/1"
	record.ActivePath = "/org/freedesktop/NetworkManager/ActiveConnection/1"
	profile, _ := profileFixture()
	pluginCtx, cancelPlugin := context.WithCancel(context.Background())
	activationCtx, cancelActivation := context.WithCancel(pluginCtx)
	t.Cleanup(cancelPlugin)
	t.Cleanup(cancelActivation)
	// No raw socket or D-Bus connection exists, so accidental bus I/O cannot
	// silently pass. The successful wire fixture separately proves provenance.
	b := &PinnedBus{pin: BusPin{BusID: record.BusID, Owner: record.Owner}, unique: record.PluginOwner, invalidated: make(chan struct{})}
	p := &Plugin{
		bus: b, ctx: pluginCtx, cancel: cancelPlugin, disconnectCh: make(chan struct{}),
		plan: PluginPlan{UUID: record.UUID, Interface: record.Interface, Nonce: record.Nonce, Username: "alice"},
	}
	a := &Activation{plugin: p, ctx: activationCtx, cancel: cancelActivation, profile: cloneSafeProfile(profile)}
	p.activation.Store(a)
	p.managerClaimed.Store(true)
	b.plugin.Store(p)
	m := &ActivationManager{
		bus: b, plugin: p, journal: &retainedCorrelationNoIOJournal{}, bootID: record.BootID,
		boot:    func(context.Context) (string, error) { panic("retained correlation refreshed boot identity") },
		started: true, record: record, profile: profile,
	}
	return &retainedCorrelationFixture{r: &ActivationReceipt{manager: m, activation: a}, a: a, m: m, p: p, b: b}
}

type retainedCorrelationLocalState struct {
	record                                            ActivationRecord
	started, observed, invalid, disconnected, claimed bool
	retained, current                                 *Activation
	published                                         uint32
	pluginErr, activationErr                          error
	profile, activationProfile                        map[string]map[string]dbus.Variant
}

func (f *retainedCorrelationFixture) localState() retainedCorrelationLocalState {
	var pluginErr, activationErr error
	if f.p.ctx != nil {
		pluginErr = f.p.ctx.Err()
	}
	if f.a.ctx != nil {
		activationErr = f.a.ctx.Err()
	}
	return retainedCorrelationLocalState{
		record: f.m.record, started: f.m.started, observed: f.m.hostObservationClaimed,
		invalid: f.b.invalid.Load(), disconnected: f.p.disconnected.Load(), claimed: f.p.managerClaimed.Load(),
		retained: f.r.activation, current: f.p.activation.Load(), published: f.p.published.Load(),
		pluginErr: pluginErr, activationErr: activationErr,
		profile: cloneSafeProfile(f.m.profile), activationProfile: cloneSafeProfile(f.a.profile),
	}
}

func TestRetainedCorrelationReturnsOnlyIndependentHistoricalIdentity(t *testing.T) {
	f := newRetainedCorrelationFixture(t)
	before := f.localState()
	want := Binding{
		Identity: Identity{
			BootID: f.m.record.BootID, BusID: f.m.record.BusID, Owner: f.m.record.Owner,
			UUID: f.m.record.UUID, ActivePath: f.m.record.ActivePath, Interface: f.m.record.Interface,
		},
		ConnectionPath: dbus.ObjectPath(f.m.record.ConnectionPath), PluginOwner: f.m.record.PluginOwner,
	}
	copyReceipt := *f.r
	for _, receipt := range []*ActivationReceipt{f.r, &copyReceipt, f.r} {
		binding, err := receipt.RetainedCorrelation(context.Background(), f.a)
		if err != nil || binding != want || binding.Identity.Session != "" {
			t.Fatal("retained transaction identity was not returned", err)
		}
		binding.Identity.Owner = ":9.9"
		binding.Identity.Session = "caller-supplied-session"
		binding.ConnectionPath = "/caller_mutation"
	}
	if !reflect.DeepEqual(before, f.localState()) {
		t.Fatal("readback changed local state or leaked a writable identity")
	}
	// Publication, native binding, or an observation attempt must not cause this
	// read-only identity getter to acquire or report those separate authorities.
	f.p.published.Store(2)
	f.m.hostObservationClaimed = true
	f.a.binding = &Binding{Identity: Identity{Session: "native-session"}}
	if got, err := f.r.RetainedCorrelation(context.Background(), f.a); err != nil || got != want {
		t.Fatal("historical identity was confused with publication/native authority", err)
	}
}

func TestRetainedCorrelationRejectsMalformedOrRevokedWithoutSideEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*retainedCorrelationFixture)
	}{
		{"manager", func(f *retainedCorrelationFixture) { f.r.manager = nil }},
		{"plugin", func(f *retainedCorrelationFixture) { f.m.plugin = nil }},
		{"bus", func(f *retainedCorrelationFixture) { f.m.bus = nil }},
		{"journal", func(f *retainedCorrelationFixture) { f.m.journal = nil }},
		{"typed-nil-journal", func(f *retainedCorrelationFixture) { f.m.journal = (*retainedCorrelationNoIOJournal)(nil) }},
		{"boot-function", func(f *retainedCorrelationFixture) { f.m.boot = nil }},
		{"not-started", func(f *retainedCorrelationFixture) { f.m.started = false }},
		{"uncorrelated", func(f *retainedCorrelationFixture) { f.m.record.Phase = "activated" }},
		{"quarantine", func(f *retainedCorrelationFixture) { f.m.record.Phase = "quarantine" }},
		{"record-version", func(f *retainedCorrelationFixture) { f.m.record.Version = 0 }},
		{"active-path", func(f *retainedCorrelationFixture) { f.m.record.ActivePath = "/" }},
		{"settings-path", func(f *retainedCorrelationFixture) { f.m.record.ConnectionPath = "/" }},
		{"missing-activation", func(f *retainedCorrelationFixture) { f.r.activation = nil }},
		{"different-activation", func(f *retainedCorrelationFixture) { f.r.activation = &Activation{} }},
		{"activation-plugin", func(f *retainedCorrelationFixture) { f.a.plugin = &Plugin{} }},
		{"activation-context", func(f *retainedCorrelationFixture) { f.a.ctx = nil }},
		{"activation-canceled", func(f *retainedCorrelationFixture) { f.a.cancel() }},
		{"plugin-context", func(f *retainedCorrelationFixture) { f.p.ctx = nil }},
		{"plugin-canceled", func(f *retainedCorrelationFixture) { f.p.cancel() }},
		{"plugin-canceled-activation-detached", func(f *retainedCorrelationFixture) {
			f.p.cancel()
			f.a.ctx = context.Background()
		}},
		{"plugin-bus", func(f *retainedCorrelationFixture) { f.p.bus = &PinnedBus{} }},
		{"bus-plugin", func(f *retainedCorrelationFixture) { f.b.plugin.Store(&Plugin{}) }},
		{"manager-unclaimed", func(f *retainedCorrelationFixture) { f.p.managerClaimed.Store(false) }},
		{"plugin-activation", func(f *retainedCorrelationFixture) { f.p.activation.Store(&Activation{}) }},
		{"disconnected", func(f *retainedCorrelationFixture) { f.p.disconnected.Store(true) }},
		{"invalid-bus", func(f *retainedCorrelationFixture) { f.b.invalid.Store(true) }},
		{"boot-pin", func(f *retainedCorrelationFixture) { f.m.bootID = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee" }},
		{"bus-pin", func(f *retainedCorrelationFixture) { f.b.pin.BusID = "fedcba9876543210fedcba9876543210" }},
		{"owner-pin", func(f *retainedCorrelationFixture) { f.b.pin.Owner = ":1.4" }},
		{"plugin-owner-pin", func(f *retainedCorrelationFixture) { f.b.unique = ":1.4" }},
		{"uuid-plan", func(f *retainedCorrelationFixture) { f.p.plan.UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" }},
		{"interface-plan", func(f *retainedCorrelationFixture) { f.p.plan.Interface = "meridian1" }},
		{"nonce-plan", func(f *retainedCorrelationFixture) { f.p.plan.Nonce = "0123456789abcdef0123456789abcdef" }},
		{"invalid-plan", func(f *retainedCorrelationFixture) { f.p.plan.Username = "alice\n" }},
		{"record-nonce", func(f *retainedCorrelationFixture) { f.m.record.Nonce = "" }},
		{"manager-profile", func(f *retainedCorrelationFixture) { f.m.profile = nil }},
		{"activation-profile", func(f *retainedCorrelationFixture) { f.a.profile = nil }},
		{"changed-profile", func(f *retainedCorrelationFixture) { f.a.profile["connection"]["id"] = dbus.MakeVariant("other") }},
		{"unsafe-profile", func(f *retainedCorrelationFixture) { f.a.profile["ipv4"]["never-default"] = dbus.MakeVariant(false) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRetainedCorrelationFixture(t)
			tc.mutate(f)
			before := f.localState()
			binding, err := f.r.RetainedCorrelation(context.Background(), f.a)
			if err == nil || binding != (Binding{}) {
				t.Fatal("malformed or revoked correlation accepted")
			}
			if !reflect.DeepEqual(before, f.localState()) {
				t.Fatal("rejected readback changed local state")
			}
		})
	}
}

func TestRetainedCorrelationRejectsForeignAndCanceledCallsWithoutRevokingOwner(t *testing.T) {
	f, foreign := newRetainedCorrelationFixture(t), newRetainedCorrelationFixture(t)
	before, foreignBefore := f.localState(), foreign.localState()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		receipt    *ActivationReceipt
		ctx        context.Context
		activation *Activation
	}{
		{nil, context.Background(), f.a},
		{&ActivationReceipt{}, context.Background(), f.a},
		{&ActivationReceipt{manager: &ActivationManager{}}, context.Background(), f.a},
		{&ActivationReceipt{manager: f.m}, context.Background(), f.a},
		{f.r, nil, f.a}, {f.r, canceled, f.a},
		{f.r, context.Background(), nil}, {f.r, context.Background(), &Activation{}},
		{f.r, context.Background(), foreign.a}, {foreign.r, context.Background(), f.a},
		{&ActivationReceipt{manager: foreign.m, activation: f.a}, context.Background(), f.a},
	} {
		binding, err := tc.receipt.RetainedCorrelation(tc.ctx, tc.activation)
		if err == nil || binding != (Binding{}) {
			t.Fatal("foreign, canceled, or uncorrelated call accepted")
		}
	}
	if !reflect.DeepEqual(before, f.localState()) || !reflect.DeepEqual(foreignBefore, foreign.localState()) {
		t.Fatal("foreign or canceled call revoked either transaction")
	}
	if _, err := f.r.RetainedCorrelation(context.Background(), f.a); err != nil {
		t.Fatal("rejected calls consumed the original correlation", err)
	}
}

func TestRetainedCorrelationSerializesWithManagerState(t *testing.T) {
	f := newRetainedCorrelationFixture(t)
	copyReceipt := *f.r
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(receipt *ActivationReceipt) {
			defer workers.Done()
			for n := 0; n < 100; n++ {
				binding, err := receipt.RetainedCorrelation(context.Background(), f.a)
				if (err != nil && binding != (Binding{})) || (err == nil && (binding.Identity.Session != "" || binding.Identity.UUID != f.p.plan.UUID)) {
					t.Error("concurrent read returned partial or native identity")
				}
			}
		}([]*ActivationReceipt{f.r, &copyReceipt}[i%2])
	}
	for n := 0; n < 100; n++ {
		f.m.mu.Lock()
		f.m.record.Phase = "quarantine"
		f.r.activation = nil
		f.m.mu.Unlock()
		f.m.mu.Lock()
		f.m.record.Phase = "correlated"
		f.r.activation = f.a
		f.m.mu.Unlock()
	}
	workers.Wait()
	if f.b.invalid.Load() || f.p.disconnected.Load() {
		t.Fatal("concurrent local rejection fenced the transaction")
	}
}
