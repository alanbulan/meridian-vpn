//go:build linux

package nmvpn

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

func hostObservationFixture() (ActivationRecord, map[string]dbus.Variant) {
	r := activationRecordFixture()
	r.ConnectionPath = "/org/freedesktop/NetworkManager/Settings/1"
	r.ActivePath = "/org/freedesktop/NetworkManager/ActiveConnection/1"
	r.Phase = "correlated"
	return r, map[string]dbus.Variant{
		"Uuid": dbus.MakeVariant(r.UUID), "Type": dbus.MakeVariant("vpn"),
		"Vpn": dbus.MakeVariant(true), "Connection": dbus.MakeVariant(dbus.ObjectPath(r.ConnectionPath)),
		"State": dbus.MakeVariant(uint32(1)), "Default": dbus.MakeVariant(false),
		"Default6": dbus.MakeVariant(false), "Ip4Config": dbus.MakeVariant(dbus.ObjectPath("/")),
		"Ip6Config": dbus.MakeVariant(dbus.ObjectPath("/")),
		"Devices": dbus.MakeVariant([]dbus.ObjectPath{
			"/org/freedesktop/NetworkManager/Devices/2", "/org/freedesktop/NetworkManager/Devices/1",
		}),
	}
}

func TestHostObservationInitialSnapshotAndCopies(t *testing.T) {
	record, properties := hostObservationFixture()
	snapshot, err := parseHostObservation(properties, record)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != 1 || snapshot.Default || snapshot.Default6 || snapshot.IP4Config != "/" || snapshot.IP6Config != "/" || snapshot.Binding.Identity.Session != "" || snapshot.Binding.Identity.ActivePath != record.ActivePath || snapshot.Binding.ConnectionPath != dbus.ObjectPath(record.ConnectionPath) {
		t.Fatal("incorrect initial diagnostic snapshot")
	}
	want := []dbus.ObjectPath{"/org/freedesktop/NetworkManager/Devices/1", "/org/freedesktop/NetworkManager/Devices/2"}
	if !reflect.DeepEqual(snapshot.ParentDevices, want) {
		t.Fatal("parent paths were not sorted")
	}
	// The parser must not retain a caller-owned slice, and the public getter
	// must not expose the immutable stored copy.
	properties["Devices"].Value().([]dbus.ObjectPath)[0] = "/caller_mutation"
	observation := &HostObservation{snapshot: &snapshot}
	first, err := observation.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	first.ParentDevices[0] = "/getter_mutation"
	first.Binding.Identity.Owner = ":9.9"
	second, err := observation.Snapshot()
	if err != nil || !reflect.DeepEqual(second.ParentDevices, want) || second.Binding.Identity.Owner != record.Owner {
		t.Fatal("observation leaked a mutable snapshot")
	}
	for _, empty := range []*HostObservation{nil, {}} {
		if _, err := empty.Snapshot(); err == nil {
			t.Fatal("empty observation accepted")
		}
	}
	for _, receipt := range []*ActivationReceipt{nil, {}, {manager: &ActivationManager{}}} {
		if _, err := receipt.ObserveHost(context.Background(), nil); err == nil {
			t.Fatal("empty receipt accepted")
		}
	}
}

func TestHostObservationRejectsUnsupportedProperties(t *testing.T) {
	_, baseline := hostObservationFixture()
	for key := range baseline {
		t.Run("missing-"+key, func(t *testing.T) {
			r, props := hostObservationFixture()
			delete(props, key)
			if _, err := parseHostObservation(props, r); err == nil {
				t.Fatal("missing property accepted")
			}
		})
	}
	for _, tc := range []struct {
		name, property string
		value          any
	}{
		{"uuid", "Uuid", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
		{"type", "Type", "ethernet"}, {"not-vpn", "Vpn", false},
		{"connection", "Connection", dbus.ObjectPath("/org/freedesktop/NetworkManager/Settings/2")},
		{"connection-string", "Connection", "/org/freedesktop/NetworkManager/Settings/1"},
		{"unknown-state", "State", uint32(0)}, {"activated", "State", uint32(2)},
		{"deactivating", "State", uint32(3)}, {"deactivated", "State", uint32(4)},
		{"future-state", "State", uint32(5)}, {"state-wrong-type", "State", int32(1)},
		{"default-v4", "Default", true}, {"default-v6", "Default6", true},
		{"default-wrong-type", "Default", uint32(0)},
		{"configured-v4", "Ip4Config", dbus.ObjectPath("/org/freedesktop/NetworkManager/IP4Config/1")},
		{"configured-v6", "Ip6Config", dbus.ObjectPath("/org/freedesktop/NetworkManager/IP6Config/1")},
		{"config-wrong-type", "Ip4Config", "/"},
		{"devices-wrong-type", "Devices", []string{"/org/freedesktop/NetworkManager/Devices/1"}},
		{"device-root", "Devices", []dbus.ObjectPath{"/"}},
		{"device-foreign-path", "Devices", []dbus.ObjectPath{"/org/freedesktop/NetworkManager/ActiveConnection/1"}},
		{"device-malformed", "Devices", []dbus.ObjectPath{"/org/freedesktop/NetworkManager/Devices/not-a-path"}},
		{"duplicate-device", "Devices", []dbus.ObjectPath{"/org/freedesktop/NetworkManager/Devices/1", "/org/freedesktop/NetworkManager/Devices/1"}},
		{"long-device", "Devices", []dbus.ObjectPath{dbus.ObjectPath("/org/freedesktop/NetworkManager/Devices/" + strings.Repeat("1", 129))}},
		{"oversized-uuid", "Uuid", strings.Repeat("a", 257)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, props := hostObservationFixture()
			props[tc.property] = dbus.MakeVariant(tc.value)
			if _, err := parseHostObservation(props, r); err == nil {
				t.Fatal("unsupported property accepted")
			}
		})
	}
	for _, phase := range []string{"activated", "quarantine", ""} {
		r, props := hostObservationFixture()
		r.Phase = phase
		if _, err := parseHostObservation(props, r); err == nil {
			t.Fatal("uncorrelated record accepted")
		}
	}
}

func TestHostObservationPathBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values []dbus.ObjectPath
	}{
		{"duplicate", []dbus.ObjectPath{"/org/freedesktop/NetworkManager/ActiveConnection/1", "/org/freedesktop/NetworkManager/ActiveConnection/1"}},
		{"root", []dbus.ObjectPath{"/"}},
		{"foreign", []dbus.ObjectPath{"/org/freedesktop/NetworkManager/Devices/1"}},
		{"malformed", []dbus.ObjectPath{"/org/freedesktop/NetworkManager/ActiveConnection/not-numeric"}},
		{"long", []dbus.ObjectPath{dbus.ObjectPath("/org/freedesktop/NetworkManager/ActiveConnection/" + strings.Repeat("1", 129))}},
		{"too-many", make([]dbus.ObjectPath, hostMaxActiveConnections+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := hostObservationPaths(dbus.MakeVariant(tc.values), activePattern, hostMaxActiveConnections); err == nil {
				t.Fatal("unsupported active paths accepted")
			}
		})
	}
	r, props := hostObservationFixture()
	props["Devices"] = dbus.MakeVariant(make([]dbus.ObjectPath, hostMaxParentDevices+1))
	if _, err := parseHostObservation(props, r); err == nil {
		t.Fatal("too many parent devices accepted")
	}
	props["Devices"] = dbus.MakeVariant([]dbus.ObjectPath{})
	if _, err := parseHostObservation(props, r); err != nil {
		t.Fatal("empty diagnostic parent list rejected")
	}
}

func TestHostObservationHasNoAuthoritySurface(t *testing.T) {
	typeOf := reflect.TypeOf(&HostObservation{})
	if typeOf.NumMethod() != 1 || typeOf.Method(0).Name != "Snapshot" {
		t.Fatal("observation grew an authority or lifecycle API")
	}
	if _, ok := any(&HostObservation{}).(Broker); ok {
		t.Fatal("historical observation unexpectedly implements Broker")
	}
	if _, ok := any(&HostObservation{}).(PublicationVerifier); ok {
		t.Fatal("historical observation unexpectedly implements publication authority")
	}
}
