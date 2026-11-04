//go:build linux

package nmvpn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func resolvedTestObserver() *PinnedResolvedObserver {
	b := &PinnedResolvedObserver{pin: BusPin{Owner: ":1.42"}, gate: make(chan struct{}, 1), invalidated: make(chan struct{})}
	b.self = b
	return b
}

func resolvedTestMessage(kind dbus.Type, sender string, path dbus.ObjectPath, iface, member string, body ...any) *dbus.Message {
	return &dbus.Message{Type: kind, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldSender: dbus.MakeVariant(sender), dbus.FieldPath: dbus.MakeVariant(path), dbus.FieldInterface: dbus.MakeVariant(iface), dbus.FieldMember: dbus.MakeVariant(member),
	}, Body: body}
}

func TestResolvedTransportStickyOwnerInvalidation(t *testing.T) {
	b := resolvedTestObserver()
	done := b.Done()
	b.observe(resolvedTestMessage(dbus.TypeSignal, ":1.8", resolvedBusPath, resolvedBusName, "NameOwnerChanged", resolvedName, ":1.42", ":1.55"))
	if b.invalid.Load() {
		t.Fatal("forged daemon signal invalidated")
	}
	b.observe(resolvedTestMessage(dbus.TypeSignal, resolvedBusName, resolvedBusPath, resolvedBusName, "NameOwnerChanged", "unrelated.service", ":1.42", ":1.55"))
	if b.invalid.Load() {
		t.Fatal("unrelated name invalidated")
	}
	b.observe(resolvedTestMessage(dbus.TypeSignal, resolvedBusName, resolvedBusPath, resolvedBusName, "NameOwnerChanged", resolvedName, ":1.42", ""))
	if !b.invalid.Load() || b.Done() != done {
		t.Fatal("owner loss not sticky")
	}
	select {
	case <-done:
	default:
		t.Fatal("owner loss did not wake monitor")
	}
	b.observe(resolvedTestMessage(dbus.TypeSignal, resolvedBusName, resolvedBusPath, resolvedBusName, "NameOwnerChanged", resolvedName, "", ":1.42"))
	if !b.invalid.Load() {
		t.Fatal("owner rebound reauthorized transport")
	}
}

func TestResolvedTransportMalformedAndPolicySignals(t *testing.T) {
	for _, m := range []*dbus.Message{
		nil,
		resolvedTestMessage(dbus.TypeSignal, resolvedBusName, resolvedBusPath, resolvedBusName, "NameOwnerChanged", resolvedName),
		resolvedTestMessage(dbus.TypeSignal, resolvedBusName, resolvedBusPath, resolvedBusName, "NameOwnerChanged", uint32(0), "", ""),
		resolvedTestMessage(dbus.TypeSignal, ":1.42", resolvedPath, propertiesInterface, "PropertiesChanged"),
		resolvedTestMessage(dbus.TypeSignal, ":1.42", resolvedLinkPath(2), propertiesInterface, "PropertiesChanged"),
		resolvedTestMessage(dbus.TypeMethodCall, ":1.8", resolvedPath, "unknown.Interface", "Method"),
	} {
		b := resolvedTestObserver()
		b.observe(m)
		if !b.invalid.Load() {
			t.Fatal("relevant unsupported message did not invalidate")
		}
	}
	b := resolvedTestObserver()
	b.observe(resolvedTestMessage(dbus.TypeSignal, ":1.8", resolvedPath, propertiesInterface, "PropertiesChanged"))
	b.observe(resolvedTestMessage(dbus.TypeSignal, ":1.42", "/org/freedesktop/resolve10", propertiesInterface, "PropertiesChanged"))
	if b.invalid.Load() {
		t.Fatal("foreign signal accepted as policy evidence")
	}
}

func TestResolvedTransportPinsReplySenderSerialAndType(t *testing.T) {
	for _, name := range []string{"valid", "wrong-sender", "wrong-serial", "missing-serial", "wrong-signature", "error", "unsolicited"} {
		t.Run(name, func(t *testing.T) {
			b := resolvedTestObserver()
			expected := &resolvedExpectedReply{sender: b.pin.Owner, signature: "v"}
			expected.serial.Store(42)
			b.expected.Store(expected)
			m := resolvedTestMessage(dbus.TypeMethodReply, b.pin.Owner, "", "", "")
			m.Headers[dbus.FieldReplySerial] = dbus.MakeVariant(uint32(42))
			m.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.ParseSignatureMust("v"))
			switch name {
			case "wrong-sender":
				m.Headers[dbus.FieldSender] = dbus.MakeVariant(":1.99")
			case "wrong-serial":
				m.Headers[dbus.FieldReplySerial] = dbus.MakeVariant(uint32(43))
			case "missing-serial":
				delete(m.Headers, dbus.FieldReplySerial)
			case "wrong-signature":
				m.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.ParseSignatureMust("a{sv}"))
			case "error":
				m.Type = dbus.TypeError
			case "unsolicited":
				b.expected.Store(nil)
			}
			b.observe(m)
			if b.invalid.Load() != (name != "valid") {
				t.Fatal("reply authentication mismatch")
			}
		})
	}
}

func TestResolvedTransportOnlyPermitsFixedReads(t *testing.T) {
	b := resolvedTestObserver()
	makeCall := func(dest string, path dbus.ObjectPath, iface, member string, args ...any) *dbus.Message {
		m := resolvedTestMessage(dbus.TypeMethodCall, "", path, iface, member, args...)
		m.Headers[dbus.FieldDestination] = dbus.MakeVariant(dest)
		m.Flags = dbus.FlagNoAutoStart
		return m
	}
	for _, m := range []*dbus.Message{
		makeCall(b.pin.Owner, resolvedPath, resolvedManagerInterface, "GetLink", int32(2)),
		makeCall(b.pin.Owner, resolvedPath, resolvedManagerInterface, "ListDelegates"),
		makeCall(b.pin.Owner, resolvedPath, resolvedIntrospectInterface, "Introspect"),
		makeCall(b.pin.Owner, resolvedLinkPath(2), resolvedIntrospectInterface, "Introspect"),
		makeCall(b.pin.Owner, resolvedPath, propertiesInterface, "Get", resolvedManagerInterface, "LLMNR"),
		makeCall(b.pin.Owner, resolvedLinkPath(2), propertiesInterface, "Get", resolvedLinkInterface, "DNS"),
		makeCall(resolvedBusName, resolvedBusPath, resolvedBusName, "GetId"),
		makeCall(resolvedBusName, resolvedBusPath, resolvedBusName, "GetNameOwner", resolvedName),
		makeCall(resolvedBusName, resolvedBusPath, resolvedBusName, "GetConnectionUnixUser", b.pin.Owner),
		makeCall(resolvedBusName, resolvedBusPath, resolvedBusName, "AddMatch", b.signalRules()[0]),
	} {
		if !b.permittedCall(m) {
			t.Fatal("fixed read denied")
		}
	}
	for _, m := range []*dbus.Message{
		makeCall(b.pin.Owner, resolvedPath, propertiesInterface, "GetAll", resolvedManagerInterface),
		makeCall(b.pin.Owner, resolvedLinkPath(2), propertiesInterface, "GetAll", resolvedLinkInterface),
		makeCall(b.pin.Owner, resolvedPath, propertiesInterface, "Get", resolvedManagerInterface, "FuturePolicy"),
		makeCall(b.pin.Owner, "/untrusted", resolvedIntrospectInterface, "Introspect"),
		makeCall(b.pin.Owner, resolvedPath, resolvedIntrospectInterface, "Introspect", "unexpected"),
		makeCall(resolvedName, resolvedPath, propertiesInterface, "Get", resolvedManagerInterface, "LLMNR"),
		makeCall(":1.99", resolvedPath, propertiesInterface, "Get", resolvedManagerInterface, "LLMNR"),
		makeCall(b.pin.Owner, resolvedPath, resolvedManagerInterface, "ResolveHostname", int32(0), "example", int32(0), uint64(0)),
		makeCall(b.pin.Owner, resolvedPath, resolvedManagerInterface, "SetLinkDNS", int32(2)),
		makeCall(b.pin.Owner, resolvedPath, resolvedManagerInterface, "FlushCaches"),
		makeCall(b.pin.Owner, resolvedLinkPath(2), resolvedLinkInterface, "Revert"),
		makeCall(b.pin.Owner, resolvedPath, resolvedManagerInterface, "GetLink", uint32(2)),
		makeCall(b.pin.Owner, resolvedPath, resolvedManagerInterface, "GetLink", int32(0)),
		makeCall(b.pin.Owner, "/untrusted", propertiesInterface, "Get", resolvedLinkInterface, "DNS"),
		makeCall(b.pin.Owner, resolvedLinkPath(2), propertiesInterface, "Get", resolvedManagerInterface, "LLMNR"),
		makeCall(resolvedBusName, resolvedBusPath, resolvedBusName, "GetConnectionUnixUser", ":1.99"),
		makeCall(resolvedBusName, resolvedBusPath, resolvedBusName, "GetNameOwner", NMName),
		makeCall(resolvedBusName, resolvedBusPath, resolvedBusName, "StartServiceByName", resolvedName),
		makeCall(resolvedBusName, resolvedBusPath, resolvedBusName, "AddMatch", "type='signal'"),
	} {
		if b.permittedCall(m) {
			t.Fatal("unapproved operation admitted")
		}
	}
	m := makeCall(b.pin.Owner, resolvedPath, propertiesInterface, "Get", resolvedManagerInterface, "LLMNR")
	m.Flags = 0
	if b.permittedCall(m) {
		t.Fatal("auto-start capable read admitted")
	}
}

func TestResolvedTransportCancellationAndFailureAreJoined(t *testing.T) {
	for _, cancelOperation := range []bool{false, true} {
		b := resolvedTestObserver()
		ctx, cancel := context.WithCancel(context.Background())
		err := b.run(ctx, func(ctx context.Context) error {
			if cancelOperation {
				cancel()
				<-ctx.Done()
				return nil
			}
			return errors.New("read failed")
		})
		cancel()
		if err == nil || !b.invalid.Load() {
			t.Fatal("failed read left reusable transport")
		}
		select {
		case <-b.Done():
		default:
			t.Fatal("failed read did not close stable invalidation")
		}
		called := false
		if err := b.run(context.Background(), func(context.Context) error { called = true; return nil }); err == nil || called {
			t.Fatal("invalid transport was reused")
		}
	}
	b := resolvedTestObserver()
	b.gate <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	returned := make(chan error, 1)
	go func() {
		returned <- b.run(ctx, func(context.Context) error { t.Error("queued canceled operation ran"); return nil })
	}()
	select {
	case err := <-returned:
		if err == nil {
			t.Fatal("queued cancellation succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("queued cancellation blocked behind serialization")
	}
	<-b.gate
}

func TestResolvedTransportCloseIsConcurrentStickyAndZeroSafe(t *testing.T) {
	b := resolvedTestObserver()
	done := b.Done()
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if err := b.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if !b.invalid.Load() || done != b.Done() {
		t.Fatal("close not sticky")
	}
	select {
	case <-done:
	default:
		t.Fatal("close did not invalidate")
	}
	for _, b := range []*PinnedResolvedObserver{nil, {}} {
		select {
		case <-b.Done():
		default:
			t.Fatal("zero observer looks valid")
		}
		if err := b.Close(); (b == nil) != (err == nil) {
			t.Fatal("zero/copy close contract", err)
		}
	}
	copy := &PinnedResolvedObserver{self: b, gate: b.gate, invalidated: b.invalidated}
	if copy.Close() == nil {
		t.Fatal("copied observer accepted")
	}
	if err := copy.run(context.Background(), func(context.Context) error { t.Fatal("copied observer ran operation"); return nil }); err == nil {
		t.Fatal("copied operation accepted")
	}
	if _, err := OpenPinnedResolvedObserver(context.Background(), nil, BusPin{}); err == nil {
		t.Fatal("nil transport accepted")
	}
}
