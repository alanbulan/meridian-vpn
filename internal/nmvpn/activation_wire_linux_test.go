//go:build linux && nmvpnintegration

package nmvpn

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type activationMemoryJournal struct {
	mu        sync.Mutex
	record    *ActivationRecord
	phases    []string
	failPhase string
	corrupt   bool
}

func (j *activationMemoryJournal) LoadActivation() (*ActivationRecord, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.corrupt {
		return nil, errors.New("corrupt")
	}
	if j.record == nil {
		return nil, nil
	}
	r := *j.record
	return &r, nil
}
func (j *activationMemoryJournal) SaveActivation(r ActivationRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if r.Phase == j.failPhase {
		return errors.New("durability failure")
	}
	if err := validateActivationRecord(r); err != nil {
		return err
	}
	j.record = &r
	j.phases = append(j.phases, r.Phase)
	return nil
}

type activationWireManager struct {
	f                       *nmPluginWireFixture
	journal                 *activationMemoryJournal
	mu                      sync.Mutex
	adds, activates         int
	bad                     bool
	loseAdd, loseActivate   bool
	blockAdd, blockActivate chan struct{}
	entered                 chan struct{}
	handlerDone             chan struct{}
	malformed               string
	afterAdd                func()
}

func (s *activationWireManager) AddConnection2(sender dbus.Sender, profile map[string]map[string]dbus.Variant, flags uint32, args map[string]dbus.Variant) (dbus.ObjectPath, map[string]dbus.Variant, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adds++
	r, err := s.journal.LoadActivation()
	s.f.plugin.mu.Lock()
	plan := s.f.plugin.plan
	s.f.plugin.mu.Unlock()
	_, password, profileErr := incomingProfile(profile, plan)
	if err != nil || r == nil || r.Phase != "add-intent" || r.ConnectionPath != "" || string(sender) != s.f.bus.unique || flags != 0x22 || len(args) != 0 || profileErr != nil || password != "" || !profileEqual(profile["connection"]["autoconnect"], false) {
		s.bad = true
	}
	s.f.service.mu.Lock()
	s.f.service.profile = profile
	s.f.service.mu.Unlock()
	if s.afterAdd != nil {
		s.afterAdd()
	}
	if s.blockAdd != nil {
		defer close(s.handlerDone)
		close(s.entered)
		<-s.blockAdd
	}
	if s.malformed == "settings" {
		return "/", map[string]dbus.Variant{}, nil
	}
	if s.malformed == "result" {
		result := map[string]dbus.Variant{}
		for i := 0; i < 65; i++ {
			result[string(rune(33+i))] = dbus.MakeVariant(true)
		}
		return wireSettings, result, nil
	}
	if s.loseAdd {
		return "", nil, &dbus.Error{Name: "org.freedesktop.DBus.Error.Failed"}
	}
	return wireSettings, map[string]dbus.Variant{}, nil
}
func (s *activationWireManager) ActivateConnection(sender dbus.Sender, settings, device, specific dbus.ObjectPath) (dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activates++
	r, err := s.journal.LoadActivation()
	if err != nil || r == nil || r.Phase != "activate-intent" || r.ConnectionPath != string(wireSettings) || r.ActivePath != "" || settings != wireSettings || device != "/" || specific != "/" || string(sender) != s.f.bus.unique {
		s.bad = true
	}
	// Deliberately synchronous callback before the method reply: a manager holding
	// bus.run's mutex here deadlocks the plugin authentication/state transition.
	s.f.service.mu.Lock()
	profile := map[string]map[string]dbus.Variant{}
	for section, values := range s.f.service.profile {
		profile[section] = map[string]dbus.Variant{}
		for k, v := range values {
			profile[section][k] = v
		}
	}
	s.f.service.mu.Unlock()
	profile["vpn"]["secrets"] = dbus.MakeVariant(map[string]string{"password": nmPluginWirePassword})
	if call := s.f.call(s.f.service.conn, PluginInterface+".Connect", profile); call.Err != nil {
		s.bad = true
		return "", &dbus.Error{Name: "org.freedesktop.DBus.Error.Failed"}
	}
	if s.blockActivate != nil {
		defer close(s.handlerDone)
		close(s.entered)
		<-s.blockActivate
	}
	if s.malformed == "active" {
		return "/", nil
	}
	if s.loseActivate {
		return "", &dbus.Error{Name: "org.freedesktop.DBus.Error.Failed"}
	}
	return wireActive, nil
}
func activationWireFixture(t *testing.T) (*nmPluginWireFixture, *activationMemoryJournal, *activationWireManager, *ActivationManager) {
	t.Helper()
	f := nmPluginFixture(t)
	j := &activationMemoryJournal{}
	wire := &activationWireManager{f: f, journal: j}
	if err := f.service.conn.ExportMethodTable(map[string]any{"AddConnection2": wire.AddConnection2}, managerSettingsPath, managerSettingsInterface); err != nil {
		t.Fatal(err)
	}
	if err := f.service.conn.ExportMethodTable(map[string]any{"ActivateConnection": wire.ActivateConnection}, NMPath, NMName); err != nil {
		t.Fatal(err)
	}
	manager, err := NewActivationManager(f.ctx, f.bus, f.plugin, j, func(context.Context) (string, error) { return f.binding.Identity.BootID, nil })
	if err != nil {
		t.Fatal(err)
	}
	return f, j, wire, manager
}
func TestNMVPNWireManagerActivationWireReceipt(t *testing.T) {
	f, j, wire, m := activationWireFixture(t)
	if f.plan.Nonce == f.plugin.plan.Nonce {
		t.Fatal("manager did not issue fresh nonce")
	}
	profile := nmSafeSettings()
	receipt, err := m.Start(f.ctx, profile)
	if err != nil {
		t.Fatal(err)
	}
	profile["connection"]["uuid"] = dbus.MakeVariant("caller mutated snapshot")
	a, err := f.plugin.Receive(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := receipt.Correlate(f.ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Identity.Session != "" || binding.Identity.ActivePath != string(wireActive) || binding.ConnectionPath != wireSettings || binding.PluginOwner != f.bus.unique || a.Nonce() != m.record.Nonce {
		t.Fatal("receipt did not bind direct replies")
	}
	if a.CheckReceipt(f.ctx, binding) != nil {
		t.Fatal("receipt rejected by native boundary")
	}
	if _, err := m.Start(f.ctx, nmSafeSettings()); err == nil {
		t.Fatal("mutation replayed")
	}
	wire.mu.Lock()
	defer wire.mu.Unlock()
	if wire.bad || wire.adds != 1 || wire.activates != 1 {
		t.Fatal("wire or durable-intent contract failed")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if !reflect.DeepEqual(j.phases, []string{"add-intent", "added", "activate-intent", "activated", "correlated"}) {
		t.Fatal(j.phases)
	}
}
func TestNMVPNWireManagerActivationUncertainNeverReplays(t *testing.T) {
	for _, stage := range []string{"add", "activate", "add-intent", "added", "activate-intent", "activated"} {
		t.Run(stage, func(t *testing.T) {
			f, j, wire, m := activationWireFixture(t)
			wire.mu.Lock()
			wire.loseAdd = stage == "add"
			wire.loseActivate = stage == "activate"
			wire.mu.Unlock()
			j.mu.Lock()
			if stage != "add" && stage != "activate" {
				j.failPhase = stage
			}
			j.mu.Unlock()
			if _, err := m.Start(f.ctx, nmSafeSettings()); err == nil {
				t.Fatal("uncertain transaction accepted")
			}
			if _, err := m.Start(f.ctx, nmSafeSettings()); err == nil {
				t.Fatal("transaction replayed")
			}
			wire.mu.Lock()
			defer wire.mu.Unlock()
			if wire.adds > 1 || wire.activates > 1 || wire.bad {
				t.Fatal("mutation replay or missing durable intent")
			}
			r, err := j.LoadActivation()
			if err != nil || r == nil || r.Phase != "quarantine" {
				t.Fatal("uncertainty not quarantined")
			}
		})
	}
}
func TestNMVPNWireManagerReceiptRejectsBootAndNonceMismatch(t *testing.T) {
	for _, kind := range []string{"boot", "profile", "activation", "normalized", "journal"} {
		t.Run(kind, func(t *testing.T) {
			f, j, _, m := activationWireFixture(t)
			receipt, err := m.Start(f.ctx, nmSafeSettings())
			if err != nil {
				t.Fatal(err)
			}
			a, err := f.plugin.Receive(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "boot":
				m.boot = func(context.Context) (string, error) { return "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee", nil }
			case "profile":
				f.service.mu.Lock()
				f.service.profile["vpn"]["data"] = dbus.MakeVariant(map[string]string{"meridian-activation": "00000000000000000000000000000000", "password-flags": "2"})
				f.service.mu.Unlock()
			case "activation":
				a = &Activation{}
			case "normalized":
				f.service.mu.Lock()
				f.service.profile["connection"]["timestamp"] = dbus.MakeVariant(uint64(1))
				f.service.mu.Unlock()
			case "journal":
				j.mu.Lock()
				j.failPhase = "correlated"
				j.mu.Unlock()
			}
			if _, err := receipt.Correlate(f.ctx, a); err == nil {
				t.Fatal("uncorrelated receipt accepted")
			}
			r, _ := j.LoadActivation()
			if r.Phase != "quarantine" {
				t.Fatal("mismatch not quarantined")
			}
		})
	}
}
func TestNMVPNWireManagerRecoveryNeverMutates(t *testing.T) {
	for _, kind := range []string{"record", "corrupt"} {
		t.Run(kind, func(t *testing.T) {
			f := nmPluginFixture(t)
			j := &activationMemoryJournal{corrupt: kind == "corrupt"}
			if kind == "record" {
				r := activationRecordFixture()
				j.record = &r
			}
			if _, err := NewActivationManager(f.ctx, f.bus, f.plugin, j, func(context.Context) (string, error) { return f.binding.Identity.BootID, nil }); err == nil {
				t.Fatal("recovery minted manager")
			}
			if kind == "record" {
				r, _ := j.LoadActivation()
				if r.Phase != "quarantine" {
					t.Fatal("prior intent not quarantined")
				}
			}
		})
	}
}
func TestNMVPNWireManagerLostReplyCancellation(t *testing.T) {
	for _, stage := range []string{"add", "activate"} {
		t.Run(stage, func(t *testing.T) {
			f, j, wire, m := activationWireFixture(t)
			block := make(chan struct{})
			entered := make(chan struct{})
			handlerDone := make(chan struct{})
			wire.mu.Lock()
			wire.entered = entered
			wire.handlerDone = handlerDone
			if stage == "add" {
				wire.blockAdd = block
			} else {
				wire.blockActivate = block
			}
			wire.mu.Unlock()
			defer func() {
				close(block)
				select {
				case <-handlerDone:
				case <-time.After(3 * time.Second):
					t.Error("blocked handler did not finish")
					return
				}
				// The handler closes its completion channel before its deferred unlock.
				// Join that final release before the fixture tears down its connection.
				wire.mu.Lock()
				wire.mu.Unlock()
			}()
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := m.Start(ctx, nmSafeSettings()); done <- err }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("mutation not entered")
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("lost reply accepted")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("canceled mutation did not join")
			}
			if _, err := m.Start(f.ctx, nmSafeSettings()); err == nil {
				t.Fatal("lost reply replayed")
			}
			r, _ := j.LoadActivation()
			if r == nil || r.Phase != "quarantine" {
				t.Fatal("lost reply not quarantined")
			}
		})
	}
}
func TestNMVPNWireManagerMalformedRepliesAndPinLoss(t *testing.T) {
	for _, kind := range []string{"settings", "active", "result", "owner", "bus", "boot"} {
		t.Run(kind, func(t *testing.T) {
			f, j, wire, m := activationWireFixture(t)
			wire.mu.Lock()
			wire.malformed = kind
			switch kind {
			case "owner":
				wire.afterAdd = func() { _, _ = f.service.conn.ReleaseName(NMName) }
			case "bus":
				wire.afterAdd = func() { m.bus.markInvalid() }
			case "boot":
				var changed atomic.Bool
				m.boot = func(context.Context) (string, error) {
					if changed.Load() {
						return "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee", nil
					}
					return f.binding.Identity.BootID, nil
				}
				wire.afterAdd = func() { changed.Store(true) }
			}
			wire.mu.Unlock()
			if _, err := m.Start(f.ctx, nmSafeSettings()); err == nil {
				t.Fatal("invalid reply/pin accepted")
			}
			if _, err := m.Start(f.ctx, nmSafeSettings()); err == nil {
				t.Fatal("invalid transaction replayed")
			}
			r, _ := j.LoadActivation()
			if r == nil || r.Phase != "quarantine" {
				t.Fatal("invalid reply/pin not quarantined")
			}
		})
	}
}
func TestNMVPNWireManagerPreservesUnexpectedJournal(t *testing.T) {
	for _, kind := range []string{"corrupt", "existing", "canceled-corrupt"} {
		t.Run(kind, func(t *testing.T) {
			f, j, _, m := activationWireFixture(t)
			old := activationRecordFixture()
			j.mu.Lock()
			if kind == "corrupt" || kind == "canceled-corrupt" {
				j.corrupt = true
			} else {
				j.record = &old
			}
			j.mu.Unlock()
			ctx := f.ctx
			if kind == "canceled-corrupt" {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			if _, err := m.Start(ctx, nmSafeSettings()); err == nil {
				t.Fatal("unexpected journal accepted")
			}
			j.mu.Lock()
			defer j.mu.Unlock()
			if (kind == "corrupt" || kind == "canceled-corrupt") && j.record != nil {
				t.Fatal("corrupt evidence overwritten")
			}
			if kind == "existing" {
				old.Phase = "quarantine"
				if *j.record != old {
					t.Fatal("old evidence replaced")
				}
			}
		})
	}
}
