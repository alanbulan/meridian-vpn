//go:build linux && nmvpnintegration

package nmvpn

// This fixture uses only a private D-Bus daemon and synthetic NM. Retaining its
// receipt proves local provenance, not real NM/network policy or native readiness.
import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type retainedCorrelationWireTrap struct{ calls atomic.Int32 }

func (s *retainedCorrelationWireTrap) Get(string, string) (dbus.Variant, *dbus.Error) {
	s.calls.Add(1)
	return dbus.MakeVariant(""), pluginError("org.freedesktop.DBus.Error.Failed")
}
func (s *retainedCorrelationWireTrap) GetAll(string) (map[string]dbus.Variant, *dbus.Error) {
	s.calls.Add(1)
	return nil, pluginError("org.freedesktop.DBus.Error.Failed")
}
func (s *retainedCorrelationWireTrap) GetSettings() (map[string]map[string]dbus.Variant, *dbus.Error) {
	s.calls.Add(1)
	return nil, pluginError("org.freedesktop.DBus.Error.Failed")
}

func TestNMVPNWireRetainedCorrelationUsesOnlyOriginalSuccessfulReceipt(t *testing.T) {
	f, journal, wire, manager := activationWireFixture(t)
	receipt, err := manager.Start(f.ctx, nmSafeSettings())
	if err != nil {
		t.Fatal(err)
	}
	activation, err := f.plugin.Receive(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	uncorrelatedCopy := *receipt
	if binding, err := receipt.RetainedCorrelation(f.ctx, activation); err == nil || binding != (Binding{}) {
		t.Fatal("Start alone minted retained correlation")
	}
	correlated, err := receipt.Correlate(f.ctx, activation)
	if err != nil {
		t.Fatal("uncorrelated read poisoned the transaction", err)
	}
	copyReceipt := *receipt
	journal.mu.Lock()
	beforeRecord := *journal.record
	beforePhases := append([]string{}, journal.phases...)
	journal.mu.Unlock()
	// No callback, journal method, or NM read may be used after correlation.
	manager.mu.Lock()
	manager.boot = func(context.Context) (string, error) { panic("retained correlation refreshed boot identity") }
	manager.journal = &retainedCorrelationNoIOJournal{}
	manager.mu.Unlock()
	trap := &retainedCorrelationWireTrap{}
	for _, path := range []dbus.ObjectPath{wireActive, NMPath} {
		if err := f.service.conn.ExportMethodTable(map[string]any{"Get": trap.Get, "GetAll": trap.GetAll}, path, propertiesInterface); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.service.conn.ExportMethodTable(map[string]any{"GetSettings": trap.GetSettings}, wireSettings, SettingsInterface); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		receipt    *ActivationReceipt
		ctx        context.Context
		activation *Activation
	}{
		{&uncorrelatedCopy, f.ctx, activation},
		{receipt, nil, activation}, {receipt, canceled, activation},
		{receipt, f.ctx, nil}, {receipt, f.ctx, &Activation{}},
	} {
		if got, err := tc.receipt.RetainedCorrelation(tc.ctx, tc.activation); err == nil || got != (Binding{}) {
			t.Fatal("invalid readback produced correlated identity")
		}
	}
	// A purely local read must not even need bus.run's serialization mutex.
	f.bus.mu.Lock()
	done := make(chan error, 1)
	go func() {
		for _, r := range []*ActivationReceipt{receipt, &copyReceipt} {
			binding, err := r.RetainedCorrelation(f.ctx, activation)
			if err != nil || binding != correlated || binding.Identity.Session != "" {
				done <- errPeer
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		f.bus.mu.Unlock()
		if err != nil {
			t.Fatal("retained correlation did not match successful receipt", err)
		}
	case <-time.After(2 * time.Second):
		f.bus.mu.Unlock()
		<-done
		t.Fatal("retained correlation depended on the bus serialization lock")
	}
	if trap.calls.Load() != 0 || f.bus.invalid.Load() || f.plugin.disconnected.Load() || activation.CheckLive(f.ctx) != nil {
		t.Fatal("retained correlation performed bus I/O or revoked its owner")
	}
	journal.mu.Lock()
	unchanged := *journal.record == beforeRecord && reflect.DeepEqual(journal.phases, beforePhases)
	journal.mu.Unlock()
	wire.mu.Lock()
	unchanged = unchanged && !wire.bad && wire.adds == 1 && wire.activates == 1
	wire.mu.Unlock()
	f.service.mu.Lock()
	unchanged = unchanged && f.service.deactivations == 0
	f.service.mu.Unlock()
	if !unchanged {
		t.Fatal("retained correlation mutated the journal or NM transaction")
	}
	// Local revocation rejects the same retained identity without running any
	// quarantine callback or attempting to alter its previously saved phase.
	activation.cancel()
	if got, err := receipt.RetainedCorrelation(context.Background(), activation); err == nil || got != (Binding{}) {
		t.Fatal("canceled original activation retained usable correlation")
	}
	if f.bus.invalid.Load() || f.plugin.disconnected.Load() || trap.calls.Load() != 0 {
		t.Fatal("canceled readback fenced or contacted the bus")
	}
}

func TestNMVPNWireRetainedCorrelationDoesNotPoisonForeignTransaction(t *testing.T) {
	f1, j1, _, m1 := activationWireFixture(t)
	f2, j2, _, m2 := activationWireFixture(t)
	start := func(f *nmPluginWireFixture, m *ActivationManager) (*ActivationReceipt, *Activation, Binding) {
		t.Helper()
		r, err := m.Start(f.ctx, nmSafeSettings())
		if err != nil {
			t.Fatal(err)
		}
		a, err := f.plugin.Receive(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := r.Correlate(f.ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		return r, a, binding
	}
	r1, a1, b1 := start(f1, m1)
	r2, a2, b2 := start(f2, m2)
	if got, err := r1.RetainedCorrelation(f1.ctx, a2); err == nil || got != (Binding{}) {
		t.Fatal("foreign activation accepted")
	}
	if got, err := r2.RetainedCorrelation(f2.ctx, a1); err == nil || got != (Binding{}) {
		t.Fatal("foreign receipt accepted")
	}
	for _, tc := range []struct {
		f       *nmPluginWireFixture
		journal *activationMemoryJournal
		r       *ActivationReceipt
		a       *Activation
		binding Binding
	}{{f1, j1, r1, a1, b1}, {f2, j2, r2, a2, b2}} {
		if got, err := tc.r.RetainedCorrelation(tc.f.ctx, tc.a); err != nil || got != tc.binding {
			t.Fatal("foreign lookup poisoned original receipt", err)
		}
		record, err := tc.journal.LoadActivation()
		if err != nil || record == nil || record.Phase != "correlated" || tc.f.bus.invalid.Load() || tc.f.plugin.disconnected.Load() {
			t.Fatal("foreign lookup quarantined or closed either original owner")
		}
	}
}
