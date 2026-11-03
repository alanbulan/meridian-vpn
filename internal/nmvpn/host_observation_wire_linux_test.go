//go:build linux && nmvpnintegration

package nmvpn

// All observations here use the existing private bus and synthetic NM. These
// tests do not contact system buses or establish real host/network authority.
import (
	"context"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

type hostObservationWireProperties struct {
	mu              sync.Mutex
	f               *nmPluginWireFixture
	active          map[string]dbus.Variant
	members         dbus.Variant
	calls           map[string]int
	membershipReads int
	bad             bool
	afterMembership func(int)
	block           chan struct{}
	entered         chan struct{}
	handlerDone     chan struct{}
}

func (p *hostObservationWireProperties) Get(message dbus.Message, iface, name string) (dbus.Variant, *dbus.Error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[iface+"."+name]++
	if message.Headers[dbus.FieldSender].Value() != p.f.bus.unique || message.Headers[dbus.FieldDestination].Value() != p.f.pin.Owner || message.Flags&dbus.FlagNoAutoStart == 0 {
		p.bad = true
	}
	if iface == ActiveInterface && message.Headers[dbus.FieldPath].Value() == wireActive {
		if p.block != nil && name == "Uuid" {
			defer close(p.handlerDone)
			close(p.entered)
			<-p.block
		}
		value, ok := p.active[name]
		if ok {
			return value, nil
		}
	} else if iface == NMName && name == "ActiveConnections" && message.Headers[dbus.FieldPath].Value() == NMPath {
		p.membershipReads++
		value := p.members
		if p.afterMembership != nil {
			p.afterMembership(p.membershipReads)
		}
		return value, nil
	} else {
		p.bad = true
	}
	return dbus.MakeVariant(""), &dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownProperty"}
}

type hostObservationWireFixture struct {
	f          *nmPluginWireFixture
	journal    *activationMemoryJournal
	wire       *activationWireManager
	manager    *ActivationManager
	receipt    *ActivationReceipt
	activation *Activation
	properties *hostObservationWireProperties
}

func newHostObservationWireFixture(t *testing.T, correlate bool) *hostObservationWireFixture {
	t.Helper()
	f, journal, wire, manager := activationWireFixture(t)
	receipt, err := manager.Start(f.ctx, nmSafeSettings())
	if err != nil {
		t.Fatal(err)
	}
	activation, err := f.plugin.Receive(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if correlate {
		if _, err := receipt.Correlate(f.ctx, activation); err != nil {
			t.Fatal(err)
		}
	}
	_, active := hostObservationFixture()
	p := &hostObservationWireProperties{f: f, active: active, members: dbus.MakeVariant([]dbus.ObjectPath{wireActive}), calls: map[string]int{}}
	// Replace only this test's synthetic property exports. Unknown additive
	// metadata is deliberately never requested; no shared fixture is widened.
	for _, path := range []dbus.ObjectPath{wireActive, NMPath} {
		if err := f.service.conn.ExportMethodTable(map[string]any{"Get": p.Get}, path, propertiesInterface); err != nil {
			t.Fatal(err)
		}
	}
	// Keep DeactivateConnection observable even though the activation fixture
	// installs an ActivateConnection-only method table on the manager interface.
	if err := f.service.conn.ExportMethodTable(map[string]any{"ActivateConnection": wire.ActivateConnection, "DeactivateConnection": f.service.DeactivateConnection}, NMPath, NMName); err != nil {
		t.Fatal(err)
	}
	return &hostObservationWireFixture{f: f, journal: journal, wire: wire, manager: manager, receipt: receipt, activation: activation, properties: p}
}

func (h *hostObservationWireFixture) assertReadOnly(t *testing.T) {
	t.Helper()
	h.wire.mu.Lock()
	bad := h.wire.bad || h.wire.adds != 1 || h.wire.activates != 1
	h.wire.mu.Unlock()
	h.f.service.mu.Lock()
	bad = bad || h.f.service.deactivations != 0
	h.f.service.mu.Unlock()
	h.properties.mu.Lock()
	bad = bad || h.properties.bad
	h.properties.mu.Unlock()
	if bad {
		t.Fatal("observation changed NM or escaped its pinned read-only target")
	}
}

func (h *hostObservationWireFixture) assertQuarantined(t *testing.T) {
	t.Helper()
	record, err := h.journal.LoadActivation()
	if err != nil || record == nil || record.Phase != "quarantine" || !h.f.bus.invalid.Load() || !h.f.plugin.disconnected.Load() {
		t.Fatal("observation failure did not retain local quarantine and fence")
	}
	h.assertReadOnly(t)
}

func TestNMVPNWireHostObservationInitialReadOnlySnapshot(t *testing.T) {
	h := newHostObservationWireFixture(t, true)
	h.properties.mu.Lock()
	h.properties.active["FutureMetadata"] = dbus.MakeVariant(uint32(7))
	h.properties.mu.Unlock()
	copyReceipt := *h.receipt
	observation, err := h.receipt.ObserveHost(h.f.ctx, h.activation)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := observation.Snapshot()
	if err != nil || snapshot.State != 1 || snapshot.Default || snapshot.Default6 || snapshot.IP4Config != "/" || snapshot.IP6Config != "/" || snapshot.Binding.Identity.Session != "" || snapshot.Binding.Identity.Owner != h.f.pin.Owner || snapshot.Binding.PluginOwner != h.f.bus.unique {
		t.Fatal("initial observation did not preserve correlated diagnostic identity")
	}
	want := []dbus.ObjectPath{"/org/freedesktop/NetworkManager/Devices/1", "/org/freedesktop/NetworkManager/Devices/2"}
	if !reflect.DeepEqual(snapshot.ParentDevices, want) {
		t.Fatal("incorrect parent device diagnostics")
	}
	snapshot.ParentDevices[0] = "/caller_mutation"
	if again, err := observation.Snapshot(); err != nil || !reflect.DeepEqual(again.ParentDevices, want) {
		t.Fatal("caller modified observation")
	}
	h.properties.mu.Lock()
	readsOK := len(h.properties.calls) == 11 && h.properties.membershipReads == 2
	for _, count := range h.properties.calls {
		readsOK = readsOK && count == 2
	}
	h.properties.mu.Unlock()
	if !readsOK {
		t.Fatal("observation did not read exactly two copies of its named fields")
	}
	h.assertReadOnly(t)
	if record, err := h.journal.LoadActivation(); err != nil || record.Phase != "correlated" {
		t.Fatal("read-only observation changed the successful activation journal phase")
	}
	if _, err := copyReceipt.ObserveHost(h.f.ctx, h.activation); err == nil {
		t.Fatal("copied receipt replayed an observation")
	}
	h.assertQuarantined(t)
	// This remains historical data after local revocation, never a live permit.
	if _, err := observation.Snapshot(); err != nil {
		t.Fatal("historical diagnostic snapshot unexpectedly became a live check")
	}
}

func TestNMVPNWireHostObservationRejectsMissingAndUnsupportedFields(t *testing.T) {
	_, fields := hostObservationFixture()
	for field := range fields {
		t.Run("missing-"+field, func(t *testing.T) {
			h := newHostObservationWireFixture(t, true)
			h.properties.mu.Lock()
			delete(h.properties.active, field)
			h.properties.mu.Unlock()
			if _, err := h.receipt.ObserveHost(h.f.ctx, h.activation); err == nil {
				t.Fatal("missing NM field accepted")
			}
			h.assertQuarantined(t)
		})
	}
	for _, tc := range []struct {
		name, field string
		value       any
	}{
		{"uuid", "Uuid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		{"type", "Type", "ethernet"}, {"vpn", "Vpn", false},
		{"connection", "Connection", dbus.ObjectPath("/org/freedesktop/NetworkManager/Settings/2")},
		{"state-type", "State", int32(1)}, {"unknown-state", "State", uint32(0)},
		{"activated", "State", uint32(2)}, {"deactivated", "State", uint32(4)},
		{"default", "Default", true}, {"default6", "Default6", true},
		{"configured4", "Ip4Config", dbus.ObjectPath("/org/freedesktop/NetworkManager/IP4Config/1")},
		{"configured6", "Ip6Config", dbus.ObjectPath("/org/freedesktop/NetworkManager/IP6Config/1")},
		{"config-type", "Ip4Config", "/"},
		{"device-type", "Devices", []string{"/org/freedesktop/NetworkManager/Devices/1"}},
		{"device-root", "Devices", []dbus.ObjectPath{"/"}},
		{"device-path", "Devices", []dbus.ObjectPath{"/unexpected/1"}},
		{"duplicate-device", "Devices", []dbus.ObjectPath{"/org/freedesktop/NetworkManager/Devices/1", "/org/freedesktop/NetworkManager/Devices/1"}},
		{"long-device", "Devices", []dbus.ObjectPath{dbus.ObjectPath("/org/freedesktop/NetworkManager/Devices/" + strings.Repeat("1", 129))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostObservationWireFixture(t, true)
			h.properties.mu.Lock()
			h.properties.active[tc.field] = dbus.MakeVariant(tc.value)
			h.properties.mu.Unlock()
			if _, err := h.receipt.ObserveHost(h.f.ctx, h.activation); err == nil {
				t.Fatal("unsupported NM value accepted")
			}
			h.assertQuarantined(t)
		})
	}
}

func TestNMVPNWireHostObservationRejectsMembership(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"nonmember", []dbus.ObjectPath{"/org/freedesktop/NetworkManager/ActiveConnection/2"}},
		{"empty", []dbus.ObjectPath{}}, {"wrong-type", []string{string(wireActive)}},
		{"duplicate", []dbus.ObjectPath{wireActive, wireActive}},
		{"root", []dbus.ObjectPath{wireActive, "/"}},
		{"foreign", []dbus.ObjectPath{wireActive, "/org/freedesktop/NetworkManager/Devices/1"}},
		{"long", []dbus.ObjectPath{wireActive, dbus.ObjectPath("/org/freedesktop/NetworkManager/ActiveConnection/" + strings.Repeat("1", 129))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostObservationWireFixture(t, true)
			h.properties.mu.Lock()
			h.properties.members = dbus.MakeVariant(tc.value)
			h.properties.mu.Unlock()
			if _, err := h.receipt.ObserveHost(h.f.ctx, h.activation); err == nil {
				t.Fatal("invalid manager membership accepted")
			}
			h.assertQuarantined(t)
		})
	}
}

func TestNMVPNWireHostObservationRejectsChangedReadback(t *testing.T) {
	for _, kind := range []string{"parents", "membership", "profile", "nonce", "boot", "owner", "publication"} {
		t.Run(kind, func(t *testing.T) {
			h := newHostObservationWireFixture(t, true)
			var changedBoot atomic.Bool
			h.manager.boot = func(context.Context) (string, error) {
				if changedBoot.Load() {
					return "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee", nil
				}
				return h.f.binding.Identity.BootID, nil
			}
			h.properties.mu.Lock()
			h.properties.afterMembership = func(read int) {
				if read != 1 {
					return
				}
				switch kind {
				case "parents":
					h.properties.active["Devices"] = dbus.MakeVariant([]dbus.ObjectPath{"/org/freedesktop/NetworkManager/Devices/3"})
				case "membership":
					h.properties.members = dbus.MakeVariant([]dbus.ObjectPath{wireActive, "/org/freedesktop/NetworkManager/ActiveConnection/2"})
				case "profile", "nonce":
					h.f.service.mu.Lock()
					if kind == "profile" {
						h.f.service.profile["connection"]["autoconnect"] = dbus.MakeVariant(true)
					} else {
						h.f.service.profile["vpn"]["data"] = dbus.MakeVariant(map[string]string{"meridian-activation": strings.Repeat("0", 32), "password-flags": "2"})
					}
					h.f.service.mu.Unlock()
				case "boot":
					changedBoot.Store(true)
				case "owner":
					_, _ = h.f.service.conn.ReleaseName(NMName)
				case "publication":
					h.f.plugin.published.Store(1)
				}
			}
			h.properties.mu.Unlock()
			if _, err := h.receipt.ObserveHost(h.f.ctx, h.activation); err == nil {
				t.Fatal("changed readback or lifetime accepted")
			}
			h.assertQuarantined(t)
		})
	}
}

func TestNMVPNWireHostObservationRejectsUncorrelatedAndStaleInputs(t *testing.T) {
	for _, kind := range []string{"uncorrelated", "nil-activation", "wrong-activation", "nil-context", "canceled", "boot", "bus", "owner", "nonce", "profile", "publication", "stale"} {
		t.Run(kind, func(t *testing.T) {
			h := newHostObservationWireFixture(t, kind != "uncorrelated")
			ctx, activation := h.f.ctx, h.activation
			switch kind {
			case "nil-activation":
				activation = nil
			case "wrong-activation":
				activation = &Activation{plugin: h.f.plugin}
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "boot":
				h.manager.boot = func(context.Context) (string, error) { return "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee", nil }
			case "bus":
				h.manager.record.BusID = strings.Repeat("0", 32)
			case "owner":
				_, _ = h.f.service.conn.ReleaseName(NMName)
			case "nonce":
				h.manager.record.Nonce = strings.Repeat("0", 32)
			case "profile":
				h.f.service.mu.Lock()
				h.f.service.profile["connection"]["autoconnect"] = dbus.MakeVariant(true)
				h.f.service.mu.Unlock()
			case "publication":
				h.f.plugin.published.Store(1)
			case "stale":
				h.activation.cancel()
			}
			if _, err := h.receipt.ObserveHost(ctx, activation); err == nil {
				t.Fatal("uncorrelated or stale input accepted")
			}
			h.assertQuarantined(t)
		})
	}
}

func TestNMVPNWireHostObservationCancellationJoinsRead(t *testing.T) {
	h := newHostObservationWireFixture(t, true)
	block, entered, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h.properties.mu.Lock()
	h.properties.block, h.properties.entered, h.properties.handlerDone = block, entered, handlerDone
	h.properties.mu.Unlock()
	defer func() {
		close(block)
		select {
		case <-handlerDone:
		case <-time.After(3 * time.Second):
			t.Error("blocked read handler did not finish")
			return
		}
		h.properties.mu.Lock()
		h.properties.mu.Unlock()
		h.assertReadOnly(t)
	}()
	ctx, cancel := context.WithCancel(h.f.ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := h.receipt.ObserveHost(ctx, h.activation); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("observation read did not begin")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled observation accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled observation did not release manager and transport")
	}
	// Do not acquire the synthetic property's mutex until its handler is joined.
	record, err := h.journal.LoadActivation()
	if err != nil || record == nil || record.Phase != "quarantine" || !h.f.bus.invalid.Load() || !h.f.plugin.disconnected.Load() {
		t.Fatal("canceled read did not quarantine")
	}
	if _, err := h.receipt.ObserveHost(h.f.ctx, h.activation); err == nil {
		t.Fatal("canceled observation replayed")
	}
}
