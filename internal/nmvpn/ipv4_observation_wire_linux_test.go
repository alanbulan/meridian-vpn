//go:build linux && nmvpnintegration

package nmvpn

// Real private D-Bus transport, synthetic NM state only. These tests use no host
// bus, TUN, netlink socket, route mutation or production HostAuthority adapter.
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

const ipv4WirePath = dbus.ObjectPath("/org/freedesktop/NetworkManager/IP4Config/7")

type ipv4WireProperties struct {
	mu                          sync.Mutex
	f                           *nmPluginWireFixture
	values                      map[string]dbus.Variant
	calls                       map[string]int
	bad                         bool
	block, entered, handlerDone chan struct{}
}

func (p *ipv4WireProperties) Get(message dbus.Message, iface, name string) (dbus.Variant, *dbus.Error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls[name]++
	if message.Headers[dbus.FieldSender].Value() != p.f.bus.unique || message.Headers[dbus.FieldDestination].Value() != p.f.pin.Owner || message.Headers[dbus.FieldPath].Value() != ipv4WirePath || message.Flags&dbus.FlagNoAutoStart == 0 || iface != ipv4ConfigInterface {
		p.bad = true
	}
	if p.block != nil && name == "AddressData" {
		defer close(p.handlerDone)
		close(p.entered)
		<-p.block
	}
	if v, ok := p.values[name]; ok {
		return v, nil
	}
	return dbus.MakeVariant(""), &dbus.Error{Name: "org.freedesktop.DBus.Error.UnknownProperty"}
}

type ipv4WireFixture struct {
	*hostObservationWireFixture
	ipv4 *ipv4WireProperties
}

func newIPv4WireFixture(t *testing.T) *ipv4WireFixture {
	t.Helper()
	h := newHostObservationWireFixture(t, true)
	// Restore GetAll for the existing production publication checks. The new
	// observation itself only reads the explicitly enumerated Get properties.
	old := &nmWireProperties{s: h.f.service, active: true}
	if err := h.f.service.conn.ExportMethodTable(map[string]any{"Get": h.properties.Get, "GetAll": old.GetAll}, wireActive, propertiesInterface); err != nil {
		t.Fatal(err)
	}
	if h.activation.UsePassword(h.f.ctx, func([]byte) error { return nil }) != nil || h.activation.Bind(h.f.ctx, h.f.binding, h.f.offer) != nil {
		t.Fatal("synthetic native bind failed")
	}
	peer := h.f.peer(t)
	config, err := Encode(h.f.offer, h.f.policy)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Publish(h.f.ctx, h.f.binding.Identity, "Config", config.General) != nil || peer.Publish(h.f.ctx, h.f.binding.Identity, "Ip4Config", config.IPv4) != nil {
		t.Fatal("private publication failed")
	}
	if h.activation.MarkStarted(h.f.ctx) != nil {
		t.Fatal("synthetic started signal failed")
	}
	_, active := ipv4ActiveFixture()
	h.properties.mu.Lock()
	h.properties.active = active
	h.properties.calls = map[string]int{}
	h.properties.membershipReads = 0
	h.properties.mu.Unlock()
	_, values := ipv4ProjectionFixture()
	p := &ipv4WireProperties{f: h.f, values: values, calls: map[string]int{}}
	if err := h.f.service.conn.ExportMethodTable(map[string]any{"Get": p.Get}, ipv4WirePath, propertiesInterface); err != nil {
		t.Fatal(err)
	}
	return &ipv4WireFixture{hostObservationWireFixture: h, ipv4: p}
}

func (h *ipv4WireFixture) assertReadOnly(t *testing.T) {
	t.Helper()
	h.hostObservationWireFixture.assertReadOnly(t)
	h.ipv4.mu.Lock()
	bad := h.ipv4.bad
	h.ipv4.mu.Unlock()
	if bad {
		t.Fatal("IPv4 read escaped pinned no-auto-start target")
	}
}

func TestNMVPNWireIPv4ObservationBoundProjection(t *testing.T) {
	h := newIPv4WireFixture(t)
	copyReceipt := *h.receipt
	observation, err := h.receipt.ObserveIPv4(h.f.ctx, h.activation)
	if err != nil {
		t.Fatal(err)
	}
	s, err := observation.Snapshot()
	if err != nil || s.Binding != h.f.binding || s.IP4Config != ipv4WirePath || s.Address != h.f.offer.Address || len(s.Routes) != 2 || s.DNSPriority != 50 {
		t.Fatal("projection lost exact manager/native binding")
	}
	h.properties.mu.Lock()
	good := len(h.properties.calls) == 13 && h.properties.membershipReads == 2
	for _, count := range h.properties.calls {
		good = good && count == 2
	}
	h.properties.mu.Unlock()
	h.ipv4.mu.Lock()
	good = good && len(h.ipv4.calls) == 13
	for _, count := range h.ipv4.calls {
		good = good && count == 2
	}
	h.ipv4.mu.Unlock()
	if !good {
		t.Fatal("observer did not perform exactly two closed read projections")
	}
	h.assertReadOnly(t)
	if record, err := h.journal.LoadActivation(); err != nil || record.Phase != "correlated" {
		t.Fatal("observation changed successful journal")
	}
	s.Routes[0].Metric = 999
	s.ParentDevices[0] = "/replacement"
	if again, err := observation.Snapshot(); err != nil || again.Routes[0].Metric == 999 || reflect.DeepEqual(again.ParentDevices, s.ParentDevices) {
		t.Fatal("mutable observation escaped")
	}
	if _, err := copyReceipt.ObserveIPv4(h.f.ctx, h.activation); err == nil {
		t.Fatal("copied receipt replayed observation")
	}
	h.assertQuarantined(t)
	if _, err := observation.Snapshot(); err != nil {
		t.Fatal("historical evidence became a live permit")
	}
}

func TestNMVPNWireIPv4ObservationRejectsProjection(t *testing.T) {
	_, fields := ipv4ProjectionFixture()
	for name := range fields {
		t.Run("missing-"+name, func(t *testing.T) {
			h := newIPv4WireFixture(t)
			h.ipv4.mu.Lock()
			delete(h.ipv4.values, name)
			h.ipv4.mu.Unlock()
			if _, err := h.receipt.ObserveIPv4(h.f.ctx, h.activation); err == nil {
				t.Fatal("missing wire evidence accepted")
			}
			h.assertQuarantined(t)
			h.assertReadOnly(t)
		})
	}
	for _, kind := range []string{"dns", "route-table", "legacy-mismatch", "route-extra", "configured6", "inactive", "nonmember", "unknown-config"} {
		t.Run(kind, func(t *testing.T) {
			h := newIPv4WireFixture(t)
			h.ipv4.mu.Lock()
			switch kind {
			case "dns":
				h.ipv4.values["Nameservers"] = dbus.MakeVariant([]uint32{1})
			case "route-table":
				h.ipv4.values["RouteData"].Value().([]map[string]dbus.Variant)[0]["table"] = dbus.MakeVariant(uint32(100))
			case "legacy-mismatch":
				h.ipv4.values["Routes"].Value().([][]uint32)[0][3]++
			case "route-extra":
				h.ipv4.values["RouteData"].Value().([]map[string]dbus.Variant)[0]["dest"] = dbus.MakeVariant("10.99.0.0")
			}
			h.ipv4.mu.Unlock()
			h.properties.mu.Lock()
			switch kind {
			case "configured6":
				h.properties.active["Ip6Config"] = dbus.MakeVariant(dbus.ObjectPath("/org/freedesktop/NetworkManager/IP6Config/1"))
			case "inactive":
				h.properties.active["State"] = dbus.MakeVariant(uint32(1))
			case "nonmember":
				h.properties.members = dbus.MakeVariant([]dbus.ObjectPath{})
			case "unknown-config":
				h.properties.active["Ip4Config"] = dbus.MakeVariant(dbus.ObjectPath("/org/freedesktop/NetworkManager/IP4Config/99"))
			}
			h.properties.mu.Unlock()
			if _, err := h.receipt.ObserveIPv4(h.f.ctx, h.activation); err == nil {
				t.Fatal("invalid projection accepted")
			}
			h.assertQuarantined(t)
			h.assertReadOnly(t)
		})
	}
}

func TestNMVPNWireIPv4ObservationRejectsUnboundAndStaleInputs(t *testing.T) {
	for _, kind := range []string{"nil-activation", "foreign-activation", "uncorrelated", "unbound", "unpublished", "partial", "nonce", "binding", "nil-context", "canceled", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			h := newIPv4WireFixture(t)
			ctx, activation := h.f.ctx, h.activation
			switch kind {
			case "nil-activation":
				activation = nil
			case "foreign-activation":
				activation = &Activation{plugin: h.f.plugin}
			case "uncorrelated":
				h.receipt.activation = nil
			case "unbound":
				h.activation.mu.Lock()
				h.activation.binding = nil
				h.activation.mu.Unlock()
			case "unpublished":
				h.f.plugin.published.Store(0)
			case "partial":
				h.f.plugin.published.Store(1)
			case "nonce":
				h.manager.record.Nonce = strings.Repeat("0", 32)
			case "binding":
				h.activation.mu.Lock()
				h.activation.binding.Identity.ActivePath = "/org/freedesktop/NetworkManager/ActiveConnection/2"
				h.activation.mu.Unlock()
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "revoked":
				h.f.plugin.fence()
			}
			if _, err := h.receipt.ObserveIPv4(ctx, activation); err == nil {
				t.Fatal("unbound/stale input accepted")
			}
			h.assertQuarantined(t)
			h.assertReadOnly(t)
			h.ipv4.mu.Lock()
			count := len(h.ipv4.calls)
			h.ipv4.mu.Unlock()
			if count != 0 {
				t.Fatal("invalid local input reached config read")
			}
		})
	}
}

func TestNMVPNWireIPv4ObservationRejectsDrift(t *testing.T) {
	for _, kind := range []string{"metric", "priority", "path", "state", "parents", "membership", "profile", "boot", "owner", "disconnect"} {
		t.Run(kind, func(t *testing.T) {
			h := newIPv4WireFixture(t)
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
				case "metric":
					h.ipv4.mu.Lock()
					h.ipv4.values["RouteData"].Value().([]map[string]dbus.Variant)[0]["metric"] = dbus.MakeVariant(uint32(51))
					h.ipv4.values["Routes"].Value().([][]uint32)[0][3] = 51
					h.ipv4.mu.Unlock()
				case "priority":
					h.ipv4.mu.Lock()
					h.ipv4.values["DnsPriority"] = dbus.MakeVariant(int32(51))
					h.ipv4.mu.Unlock()
				case "path":
					h.properties.active["Ip4Config"] = dbus.MakeVariant(dbus.ObjectPath("/org/freedesktop/NetworkManager/IP4Config/8"))
				case "state":
					h.properties.active["State"] = dbus.MakeVariant(uint32(3))
				case "parents":
					h.properties.active["Devices"] = dbus.MakeVariant([]dbus.ObjectPath{"/org/freedesktop/NetworkManager/Devices/3"})
				case "membership":
					h.properties.members = dbus.MakeVariant([]dbus.ObjectPath{wireActive, "/org/freedesktop/NetworkManager/ActiveConnection/2"})
				case "profile":
					h.f.service.mu.Lock()
					h.f.service.profile["connection"]["autoconnect"] = dbus.MakeVariant(true)
					h.f.service.mu.Unlock()
				case "boot":
					changedBoot.Store(true)
				case "owner":
					_, _ = h.f.service.conn.ReleaseName(NMName)
				case "disconnect":
					h.f.plugin.fence()
				}
			}
			h.properties.mu.Unlock()
			if _, err := h.receipt.ObserveIPv4(h.f.ctx, h.activation); err == nil {
				t.Fatal("drifting evidence accepted")
			}
			h.assertQuarantined(t)
			h.assertReadOnly(t)
		})
	}
}

func TestNMVPNWireIPv4ObservationCancellationJoinsRead(t *testing.T) {
	h := newIPv4WireFixture(t)
	block, entered, handlerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h.ipv4.mu.Lock()
	h.ipv4.block, h.ipv4.entered, h.ipv4.handlerDone = block, entered, handlerDone
	h.ipv4.mu.Unlock()
	defer func() {
		close(block)
		select {
		case <-handlerDone:
		case <-time.After(3 * time.Second):
			t.Error("blocked private handler did not finish")
			return
		}
		h.assertReadOnly(t)
	}()
	ctx, cancel := context.WithCancel(h.f.ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := h.receipt.ObserveIPv4(ctx, h.activation); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("config read did not begin")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled read accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not release observer")
	}
	// Avoid the blocked fixture mutex until its own handler is released.
	if record, err := h.journal.LoadActivation(); err != nil || record.Phase != "quarantine" || !h.f.bus.invalid.Load() {
		t.Fatal("canceled observation did not quarantine")
	}
	if _, err := h.receipt.ObserveIPv4(h.f.ctx, h.activation); err == nil {
		t.Fatal("canceled observation replayed")
	}
}
