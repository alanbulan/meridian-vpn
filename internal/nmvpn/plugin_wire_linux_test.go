//go:build linux && nmvpnintegration

package nmvpn

// These tests use only the opt-in private dbus-daemon and synthetic NM from
// wire_linux_test.go. A successful Connect, state transition or signal is NOT
// evidence of a real NM activation, applied networking, or native readiness.
import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

const nmPluginWirePassword = "fixture-only-password-never-log"

type nmPluginWireFixture struct {
	*nmWireFixture
	plugin *Plugin
	plan   PluginPlan
}

// This is only a synthetic live-admission gate. It does not establish actual
// native worker, link or host-policy authority, which requires a real broker.
type nmPluginWireBroker struct {
	*nmWireBroker
	activation    *Activation
	publishDenied bool
}

func (b *nmPluginWireBroker) VerifyPublish(ctx context.Context, binding Binding, offer Offer) error {
	if b.publishDenied || b.activation.CheckLive(ctx) != nil || b.activation.VerifyBinding(binding, offer) != nil {
		return errPeer
	}
	return b.Verify(ctx, binding, offer)
}

func (f *nmPluginWireFixture) peer(t *testing.T) *DBusPeer {
	t.Helper()
	broker := &nmPluginWireBroker{nmWireBroker: f.broker, activation: f.plugin.activation.Load()}
	peer, err := NewDBusPeer(f.ctx, f.bus, broker, f.binding, f.offer, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	return peer
}

func nmPluginFixture(t *testing.T) *nmPluginWireFixture {
	t.Helper()
	f := &nmWireFixture{socket: nmPrivateBus(t), ctx: nmContext(t)}
	f.service = nmInstallService(t, f.socket)
	if err := f.service.conn.BusObject().Call("org.freedesktop.DBus.GetId", 0).Store(&f.pin.BusID); err != nil {
		t.Fatal(err)
	}
	if err := f.service.conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, NMName).Store(&f.pin.Owner); err != nil {
		t.Fatal(err)
	}
	f.pin.BusUID, f.pin.OwnerUID = uint32(os.Geteuid()), uint32(os.Geteuid())
	var err error
	f.bus, err = OpenPinnedBus(f.ctx, nmRawConn(t, f.socket), f.pin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.bus.Close() })
	plan, err := NewPluginPlan(wireUUID, "meridian0", "alice")
	if err != nil {
		t.Fatal(err)
	}
	// Unlike nmFixture, do not claim the service name first: ServePlugin must
	// export the incoming ABI before claiming it on this exact connection.
	plugin, err := ServePlugin(f.ctx, f.bus, plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plugin.Close() })
	f.offer, f.policy = configFixture()
	f.binding = Binding{Identity: Identity{BootID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", BusID: f.pin.BusID, Owner: f.pin.Owner, UUID: wireUUID, ActivePath: string(wireActive), Session: f.offer.Session, Interface: f.offer.Interface}, ConnectionPath: wireSettings, PluginOwner: f.bus.UniqueName()}
	f.broker = &nmWireBroker{binding: f.binding, offer: f.offer}
	f.service.mu.Lock()
	f.service.profile = nmPluginProfile(plan, false)
	f.service.mu.Unlock()
	return &nmPluginWireFixture{nmWireFixture: f, plugin: plugin, plan: plan}
}

func nmPluginProfile(plan PluginPlan, password bool) map[string]map[string]dbus.Variant {
	s := nmSafeSettings()
	s["vpn"]["user-name"] = dbus.MakeVariant(plan.Username)
	s["vpn"]["data"] = dbus.MakeVariant(map[string]string{"meridian-activation": plan.Nonce, "password-flags": "2"})
	if password {
		s["vpn"]["secrets"] = dbus.MakeVariant(map[string]string{"password": nmPluginWirePassword})
	}
	return s
}

func (f *nmPluginWireFixture) call(c *dbus.Conn, method string, args ...any) *dbus.Call {
	return c.Object(PluginService, PluginPath).CallWithContext(f.ctx, method, dbus.FlagNoAutoStart, args...)
}

func nmPluginError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatal("request unexpectedly accepted")
	}
	if strings.Contains(err.Error(), nmPluginWirePassword) {
		t.Fatal("error exposed fixture credential")
	}
	if want == "" {
		return
	}
	var name string
	switch e := err.(type) {
	case dbus.Error:
		name = e.Name
	case *dbus.Error:
		name = e.Name
	}
	if name != want {
		t.Fatalf("D-Bus error name = %q, want %q", name, want)
	}
}

func (f *nmPluginWireFixture) connect(t *testing.T) *Activation {
	t.Helper()
	if err := f.call(f.service.conn, PluginInterface+".Connect", nmPluginProfile(f.plan, true)).Err; err != nil {
		t.Fatal("valid Connect rejected", err)
	}
	a, err := f.plugin.Receive(f.ctx)
	if err != nil || a == nil {
		t.Fatal("missing accepted activation", err)
	}
	return a
}

func (f *nmPluginWireFixture) state(t *testing.T) uint32 {
	t.Helper()
	var state dbus.Variant
	if err := f.call(f.service.conn, propertiesInterface+".Get", PluginInterface, "State").Store(&state); err != nil {
		t.Fatal(err)
	}
	value, ok := state.Value().(uint32)
	if !ok || state.Signature().String() != "u" {
		t.Fatal("State has the wrong wire type")
	}
	return value
}

func nmPluginStateSignal(t *testing.T, f *nmPluginWireFixture, ch <-chan *dbus.Signal, state uint32) {
	t.Helper()
	s := nmNextPluginSignal(t, f.ctx, ch)
	if s.Sender != f.bus.UniqueName() || s.Path != PluginPath || s.Name != PluginInterface+".StateChanged" || len(s.Body) != 1 || s.Body[0] != state {
		t.Fatal("incorrect directed StateChanged signal")
	}
}

func TestNMVPNWirePluginHandshakeAndOneShotSecrets(t *testing.T) {
	f := nmPluginFixture(t)
	other, err := NewPluginPlan(wireUUID, "meridian0", "alice")
	if err != nil || other.Nonce == f.plan.Nonce || !sessionPattern.MatchString(f.plan.Nonce) {
		t.Fatal("activation plan did not receive a fresh nonce")
	}
	if f.state(t) != 1 {
		t.Fatal("plugin did not start in INIT")
	}
	for i := 0; i < 3; i++ {
		for _, havePassword := range []bool{false, true} {
			var needed string
			if err := f.call(f.service.conn, PluginInterface+".NeedSecrets", nmPluginProfile(f.plan, havePassword)).Store(&needed); err != nil {
				t.Fatal("NeedSecrets consumed the activation", err)
			}
			want := "vpn"
			if havePassword {
				want = ""
			}
			if needed != want {
				t.Fatalf("NeedSecrets = %q, want %q", needed, want)
			}
		}
	}
	nmPluginError(t, f.call(f.service.conn, PluginInterface+".ConnectInteractive", nmPluginProfile(f.plan, true), map[string]dbus.Variant{}).Err, "org.freedesktop.NetworkManager.VPN.Error.InteractiveNotSupported")
	if f.state(t) != 1 {
		t.Fatal("NeedSecrets or unsupported interactive call changed state")
	}
	a := f.connect(t)
	if a.UUID() != f.plan.UUID || a.Interface() != f.plan.Interface || a.Username() != f.plan.Username || a.Nonce() != f.plan.Nonce || a.Context().Err() != nil {
		t.Fatal("Connect evidence lost its authenticated plan")
	}
	if f.state(t) != 3 {
		t.Fatal("Connect acceptance did not enter STARTING")
	}
	nmPluginError(t, f.call(f.service.conn, PluginInterface+".Connect", nmPluginProfile(f.plan, true)).Err, "org.freedesktop.NetworkManager.VPN.Error.WrongState")
	nmPluginError(t, f.call(f.service.conn, PluginInterface+".NeedSecrets", nmPluginProfile(f.plan, true)).Err, "org.freedesktop.NetworkManager.VPN.Error.WrongState")
	if err := a.MarkStarted(f.ctx); err == nil {
		t.Fatal("unbound activation entered STARTED")
	}
	if err := a.Bind(f.ctx, f.binding, f.offer); err == nil {
		t.Fatal("binding accepted before credential consumption")
	}
	var retained []byte // Test-only alias verifies zeroing after callback return.
	if err := a.UsePassword(f.ctx, func(password []byte) error {
		if string(password) != nmPluginWirePassword {
			t.Fatal("wrong credential handed to native consumer")
		}
		retained = password
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, b := range retained {
		if b != 0 {
			t.Fatal("credential callback buffer was not cleared")
		}
	}
	called := false
	if err := a.UsePassword(f.ctx, func([]byte) error { called = true; return nil }); err == nil || called {
		t.Fatal("credential could be consumed twice")
	}
	for _, mutate := range []func(*Binding){
		func(b *Binding) { b.Identity.Session = strings.Repeat("f", 32) },
		func(b *Binding) { b.Identity.UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" },
		func(b *Binding) { b.Identity.Owner = ":999.999" },
		func(b *Binding) { b.Identity.BusID = strings.Repeat("f", 32) },
		func(b *Binding) { b.Identity.Interface = "another0" },
		func(b *Binding) { b.PluginOwner = ":999.999" },
		func(b *Binding) { b.ConnectionPath = "/wrong" },
	} {
		wrong := f.binding
		mutate(&wrong)
		if a.Bind(f.ctx, wrong, f.offer) == nil {
			t.Fatal("mismatched native generation binding accepted")
		}
	}
	if err := a.Bind(f.ctx, f.binding, f.offer); err != nil {
		t.Fatal("valid activation binding rejected", err)
	}
	if a.MarkStarted(f.ctx) == nil {
		t.Fatal("bound activation entered STARTED before config publication")
	}
	if err := a.VerifyBinding(f.binding, f.offer); err != nil {
		t.Fatal(err)
	}
	if err := a.Bind(f.ctx, f.binding, f.offer); err == nil {
		t.Fatal("activation binding could be overwritten")
	}
	wrong := f.binding
	wrong.Identity.Session = strings.Repeat("f", 32)
	if a.VerifyBinding(wrong, f.offer) == nil {
		t.Fatal("another native session reused the activation")
	}
	ctx, cancel := context.WithTimeout(f.ctx, 30*time.Millisecond)
	defer cancel()
	if second, err := f.plugin.Receive(ctx); err == nil || second != nil {
		t.Fatal("one Connect produced more than one activation")
	}
}

func TestNMVPNWirePluginProfileEnvelopeRejections(t *testing.T) {
	f := nmPluginFixture(t)
	cases := []struct {
		name   string
		mutate func(map[string]map[string]dbus.Variant)
	}{
		{"UUID", func(s map[string]map[string]dbus.Variant) { s["connection"]["uuid"] = dbus.MakeVariant("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee") }},
		{"nonce", func(s map[string]map[string]dbus.Variant) { s["vpn"]["data"].Value().(map[string]string)["meridian-activation"] = strings.Repeat("f", 32) }},
		{"missing nonce", func(s map[string]map[string]dbus.Variant) { delete(s["vpn"]["data"].Value().(map[string]string), "meridian-activation") }},
		{"username", func(s map[string]map[string]dbus.Variant) { s["vpn"]["user-name"] = dbus.MakeVariant("mallory") }},
		{"missing username", func(s map[string]map[string]dbus.Variant) { delete(s["vpn"], "user-name") }},
		{"username signature", func(s map[string]map[string]dbus.Variant) { s["vpn"]["user-name"] = dbus.MakeVariant(uint32(1)) }},
		{"saved password", func(s map[string]map[string]dbus.Variant) { s["vpn"]["data"].Value().(map[string]string)["password-flags"] = "0" }},
		{"missing password flag", func(s map[string]map[string]dbus.Variant) { delete(s["vpn"]["data"].Value().(map[string]string), "password-flags") }},
		{"unrecognized data", func(s map[string]map[string]dbus.Variant) { s["vpn"]["data"].Value().(map[string]string)["gateway"] = "attacker.invalid" }},
		{"oversized password", func(s map[string]map[string]dbus.Variant) { s["vpn"]["secrets"] = dbus.MakeVariant(map[string]string{"password": strings.Repeat("x", 4096)}) }},
		{"unrecognized secret", func(s map[string]map[string]dbus.Variant) { s["vpn"]["secrets"] = dbus.MakeVariant(map[string]string{"password": nmPluginWirePassword, "token": "not-supported"}) }},
		{"only unrecognized secret", func(s map[string]map[string]dbus.Variant) { s["vpn"]["secrets"] = dbus.MakeVariant(map[string]string{"token": "not-supported"}) }},
		{"secret signature", func(s map[string]map[string]dbus.Variant) { s["vpn"]["secrets"] = dbus.MakeVariant(map[string]dbus.Variant{"password": dbus.MakeVariant(nmPluginWirePassword)}) }},
		{"newline password", func(s map[string]map[string]dbus.Variant) { s["vpn"]["secrets"] = dbus.MakeVariant(map[string]string{"password": "bad\npassword"}) }},
		{"network default", func(s map[string]map[string]dbus.Variant) { s["ipv4"]["never-default"] = dbus.MakeVariant(false) }},
		{"network DNS", func(s map[string]map[string]dbus.Variant) { s["ipv4"]["dns"] = dbus.MakeVariant([]uint32{1}) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := nmPluginProfile(f.plan, true)
			tc.mutate(s)
			for _, method := range []string{"NeedSecrets", "Connect"} {
				nmPluginError(t, f.call(f.service.conn, PluginInterface+"."+method, s).Err, "org.freedesktop.NetworkManager.VPN.Error.BadArguments")
			}
		})
	}
	nmPluginError(t, f.call(f.service.conn, PluginInterface+".Connect", nmPluginProfile(f.plan, false)).Err, "org.freedesktop.NetworkManager.VPN.Error.BadArguments")
	// Rejections must neither consume the activation nor poison the bus.
	_ = f.connect(t)
}

func TestNMVPNWirePluginRejectsUnauthenticatedAndMalformedCalls(t *testing.T) {
	f := nmPluginFixture(t)
	fake := nmWireConn(t, f.socket)
	profile := nmPluginProfile(f.plan, true)
	for _, c := range []struct {
		method string
		args   []any
	}{
		{PluginInterface + ".Connect", []any{profile}},
		{PluginInterface + ".NeedSecrets", []any{profile}},
		{PluginInterface + ".ConnectInteractive", []any{profile, map[string]dbus.Variant{}}},
		{PluginInterface + ".Disconnect", nil},
		{propertiesInterface + ".Get", []any{PluginInterface, "State"}},
		{propertiesInterface + ".GetAll", []any{PluginInterface}},
	} {
		nmPluginError(t, f.call(fake, c.method, c.args...).Err, "")
	}
	// A sender claimed inside the body cannot replace the daemon-supplied
	// sender header, including godbus's injected dbus.Message parameter.
	nmPluginError(t, f.call(fake, PluginInterface+".Connect", f.pin.Owner, profile).Err, "")
	spoof := nmPluginProfile(f.plan, true)
	spoof["vpn"]["sender"] = dbus.MakeVariant(f.pin.Owner)
	nmPluginError(t, f.call(fake, PluginInterface+".Connect", spoof).Err, "")
	for _, c := range []struct {
		path   dbus.ObjectPath
		method string
		args   []any
	}{
		{PluginPath, "Connect", []any{profile}},
		{PluginPath, "Disconnect", nil},
		{PluginPath, propertiesInterface + ".Disconnect", nil},
		{PluginPath, propertiesInterface + ".Connect", []any{profile}},
		{"/org/freedesktop/NetworkManager/VPN/Wrong", PluginInterface + ".Connect", []any{profile}},
		{PluginPath, PluginInterface + ".Connect", []any{"wrong-signature"}},
		{PluginPath, PluginInterface + ".Disconnect", []any{"unexpected-body"}},
		{PluginPath, PluginInterface + ".SetConfig", []any{map[string]dbus.Variant{}}},
		{PluginPath, PluginInterface + ".SetIp4Config", []any{map[string]dbus.Variant{}}},
		{PluginPath, PluginInterface + ".SetFailure", []any{"not-an-exported-helper"}},
		{PluginPath, PluginInterface + ".NewSecrets", []any{profile}},
	} {
		err := f.service.conn.Object(PluginService, c.path).CallWithContext(f.ctx, c.method, dbus.FlagNoAutoStart, c.args...).Err
		nmPluginError(t, err, "")
	}
	if f.plugin.disconnected.Load() || f.state(t) != 1 {
		t.Fatal("rejected traffic latched Disconnect or changed state")
	}
	_ = f.connect(t)
}

func TestNMVPNWirePluginImmutableSanitizedSnapshot(t *testing.T) {
	f := nmPluginFixture(t)
	input := nmPluginProfile(f.plan, true)
	input["connection"]["permissions"] = dbus.MakeVariant([]string{})
	input["ipv4"]["dns"] = dbus.MakeVariant([]uint32{})
	input["ipv4"]["route-data"] = dbus.MakeVariant([]map[string]dbus.Variant{})
	if err := f.call(f.service.conn, PluginInterface+".Connect", input).Err; err != nil {
		t.Fatal(err)
	}
	a, err := f.plugin.Receive(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := a.Profile()
	for _, key := range []string{"secrets", "data", "user-name"} {
		if _, ok := snapshot["vpn"][key]; ok {
			t.Fatal("credential envelope escaped into network snapshot")
		}
	}
	if ValidateProfile(snapshot, f.binding.Identity) != nil {
		t.Fatal("sanitized captured profile is not valid network evidence")
	}
	baseline := a.Profile()
	input["connection"]["uuid"] = dbus.MakeVariant("changed-after-call")
	input["vpn"]["secrets"].Value().(map[string]string)["password"] = "changed-after-call"
	snapshot["connection"]["uuid"] = dbus.MakeVariant("changed-snapshot")
	snapshot["ipv4"]["dns"] = dbus.MakeVariant(append(snapshot["ipv4"]["dns"].Value().([]uint32), 1))
	delete(snapshot, "ipv6")
	if !reflect.DeepEqual(a.Profile(), baseline) {
		t.Fatal("caller changed immutable Connect snapshot")
	}
	if err := a.UsePassword(f.ctx, func(p []byte) error {
		if string(p) != nmPluginWirePassword {
			t.Fatal("caller changed captured credential")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNMVPNWirePluginConcurrentSecretUseAndFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "callback failure"
		}
		t.Run(name, func(t *testing.T) {
			f := nmPluginFixture(t)
			a := f.connect(t)
			var calls atomic.Int32
			var successes atomic.Int32
			var retained []byte
			var wg sync.WaitGroup
			for i := 0; i < 12; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					err := a.UsePassword(f.ctx, func(p []byte) error {
						calls.Add(1)
						retained = p
						if fail {
							return errors.New(nmPluginWirePassword)
						}
						return nil
					})
					if err == nil {
						successes.Add(1)
					} else if strings.Contains(err.Error(), nmPluginWirePassword) {
						t.Error("native callback error exposed credential")
					}
				}()
			}
			wg.Wait()
			wantSuccesses := int32(1)
			if fail {
				wantSuccesses = 0
			}
			if calls.Load() != 1 || successes.Load() != wantSuccesses {
				t.Fatal("credential consumption was not exactly once")
			}
			if fail && a.Bind(f.ctx, f.binding, f.offer) == nil {
				t.Fatal("failed credential handoff authorized a native binding")
			}
			for _, b := range retained {
				if b != 0 {
					t.Fatal("credential was not cleared after callback")
				}
			}
		})
	}
}

func TestNMVPNWirePluginDirectedLifecycle(t *testing.T) {
	f := nmPluginFixture(t)
	received := nmSignals(t, f.service.conn)
	observed := nmSignals(t, nmWireConn(t, f.socket))
	// Positive control proves that both ordinary subscriptions can observe a
	// broadcast, so absent private signals are not a broken match-rule result.
	probe := nmWireConn(t, f.socket)
	if err := probe.Emit(PluginPath, PluginInterface+".FixtureProbe", "synthetic"); err != nil {
		t.Fatal(err)
	}
	for _, ch := range []chan *dbus.Signal{received, observed} {
		if nmNextPluginSignal(t, f.ctx, ch).Name != PluginInterface+".FixtureProbe" {
			t.Fatal("signal subscription positive control failed")
		}
	}
	a := f.connect(t)
	nmPluginStateSignal(t, f, received, 3)
	if a.UsePassword(f.ctx, func([]byte) error { return nil }) != nil || a.Bind(f.ctx, f.binding, f.offer) != nil {
		t.Fatal("could not bind synthetic activation")
	}
	peer := f.peer(t)
	config, err := Encode(f.offer, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []struct {
		member string
		values map[string]dbus.Variant
	}{{"Config", config.General}, {"Ip4Config", config.IPv4}} {
		if err := peer.Publish(f.ctx, f.binding.Identity, part.member, part.values); err != nil {
			t.Fatal(err)
		}
		s := nmNextPluginSignal(t, f.ctx, received)
		if s.Sender != f.bus.UniqueName() || s.Path != PluginPath || s.Name != PluginInterface+"."+part.member || len(s.Body) != 1 || !reflect.DeepEqual(s.Body[0], part.values) {
			t.Fatal("outbound configuration did not use incoming plugin connection")
		}
		if part.member == "Config" && a.MarkStarted(f.ctx) == nil {
			t.Fatal("partial publication entered STARTED")
		}
	}
	if err := a.MarkStarted(f.ctx); err != nil {
		t.Fatal(err)
	}
	nmPluginStateSignal(t, f, received, 4)
	if f.state(t) != 4 {
		t.Fatal("bound state transition did not reach STARTED")
	}
	if err := f.call(f.service.conn, PluginInterface+".Disconnect").Err; err != nil {
		t.Fatal(err)
	}
	nmPluginStateSignal(t, f, received, 5)
	select {
	case <-a.Context().Done():
	case <-f.ctx.Done():
		t.Fatal("Disconnect did not cancel native activation")
	}
	if f.state(t) != 5 {
		t.Fatal("Disconnect did not wait in STOPPING for native join")
	}
	if err := a.MarkStopped(f.ctx); err != nil {
		t.Fatal(err)
	}
	nmPluginStateSignal(t, f, received, 6)
	if f.state(t) != 6 || a.CheckLive(f.ctx) == nil {
		t.Fatal("stopped activation remained live")
	}
	nmPluginError(t, f.call(f.service.conn, PluginInterface+".Disconnect").Err, "org.freedesktop.NetworkManager.VPN.Error.AlreadyStopped")
	// An ordered broadcast fence from the same sender replaces a timing-only
	// absence assertion. Any leaked earlier state/config arrives before it.
	if err := f.bus.conn.Emit(PluginPath, PluginInterface+".FixtureFence", "complete"); err != nil {
		t.Fatal(err)
	}
	for _, ch := range []chan *dbus.Signal{observed, received} {
		s := nmNextPluginSignal(t, f.ctx, ch)
		if s.Sender != f.bus.UniqueName() || s.Name != PluginInterface+".FixtureFence" {
			t.Fatal("private state/config leaked or stopped state emitted twice")
		}
	}
}

func TestNMVPNWirePluginRequiresLivePublicationVerifier(t *testing.T) {
	f := nmPluginFixture(t)
	a := f.connect(t)
	if a.UsePassword(f.ctx, func([]byte) error { return nil }) != nil || a.Bind(f.ctx, f.binding, f.offer) != nil {
		t.Fatal("could not bind synthetic activation")
	}
	// The original fixture broker implements Broker only. Incoming plugins
	// must not silently treat retained provenance as live native admission.
	if peer, err := NewDBusPeer(f.ctx, f.bus, f.broker, f.binding, f.offer, f.policy); err == nil || peer != nil {
		t.Fatal("incoming plugin accepted a broker without live publication verification")
	}
	broker := &nmPluginWireBroker{nmWireBroker: f.broker, activation: a, publishDenied: true}
	peer, err := NewDBusPeer(f.ctx, f.bus, broker, f.binding, f.offer, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	config, err := Encode(f.offer, f.policy)
	if err != nil {
		t.Fatal(err)
	}
	for i, part := range []struct {
		member string
		values map[string]dbus.Variant
	}{{"Config", config.General}, {"Ip4Config", config.IPv4}} {
		broker.publishDenied = true
		if peer.Publish(f.ctx, f.binding.Identity, part.member, part.values) == nil {
			t.Fatal("live publication rejection was ignored")
		}
		if f.plugin.published.Load() != uint32(i) {
			t.Fatal("rejected live publication consumed its signal slot")
		}
		broker.publishDenied = false
		if err := peer.Publish(f.ctx, f.binding.Identity, part.member, part.values); err != nil {
			t.Fatal("allowed synthetic publication rejected", err)
		}
	}
}

func TestNMVPNWirePluginDisconnectDuringCredentialHandoff(t *testing.T) {
	f := nmPluginFixture(t)
	a := f.connect(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	result := make(chan error, 1)
	var retained []byte
	go func() {
		result <- a.UsePassword(f.ctx, func(password []byte) error {
			retained = password
			close(entered)
			select {
			case <-release:
			case <-f.ctx.Done():
			}
			return nil
		})
	}()
	select {
	case <-entered:
	case <-f.ctx.Done():
		t.Fatal("credential callback never started")
	}
	if err := f.call(f.service.conn, PluginInterface+".Disconnect").Err; err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.Context().Done():
	case <-f.ctx.Done():
		t.Fatal("Disconnect waited for native callback before cancellation")
	}
	close(release)
	select {
	case err := <-result:
		if err == nil || strings.Contains(err.Error(), nmPluginWirePassword) {
			t.Fatal("canceled native handoff succeeded or leaked credential")
		}
	case <-f.ctx.Done():
		t.Fatal("canceled credential handoff did not join")
	}
	for _, b := range retained {
		if b != 0 {
			t.Fatal("canceled handoff buffer was not cleared")
		}
	}
	if a.Bind(f.ctx, f.binding, f.offer) == nil {
		t.Fatal("disconnected native handoff created a binding")
	}
}

func nmPluginDisconnectMessage(f *nmPluginWireFixture) *dbus.Message {
	return &dbus.Message{Type: dbus.TypeMethodCall, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldSender:      dbus.MakeVariant(f.pin.Owner),
		dbus.FieldDestination: dbus.MakeVariant(PluginService),
		dbus.FieldPath:        dbus.MakeVariant(PluginPath),
		dbus.FieldInterface:   dbus.MakeVariant(PluginInterface),
		dbus.FieldMember:      dbus.MakeVariant("Disconnect"),
	}}
}

func TestNMVPNWirePluginDisconnectReceiveOrder(t *testing.T) {
	f := nmPluginFixture(t)
	// Exercise the reader seam directly to make handler scheduling irrelevant:
	// Disconnect was read, but its method handler has deliberately not run yet.
	f.plugin.observe(nmPluginDisconnectMessage(f))
	if !f.plugin.disconnected.Load() {
		t.Fatal("authenticated Disconnect was not latched by the reader")
	}
	nmPluginError(t, f.call(f.service.conn, PluginInterface+".Connect", nmPluginProfile(f.plan, true)).Err, "org.freedesktop.NetworkManager.VPN.Error.WrongState")
	if f.plugin.activation.Load() != nil {
		t.Fatal("later Connect overtook received Disconnect")
	}
}

func TestNMVPNWirePluginDisconnectObserverRejectsMalformed(t *testing.T) {
	f := nmPluginFixture(t)
	for _, tc := range []struct {
		name   string
		mutate func(*dbus.Message)
	}{
		{"fake sender", func(m *dbus.Message) { m.Headers[dbus.FieldSender] = dbus.MakeVariant(":999.999") }},
		{"missing interface", func(m *dbus.Message) { delete(m.Headers, dbus.FieldInterface) }},
		{"properties interface", func(m *dbus.Message) { m.Headers[dbus.FieldInterface] = dbus.MakeVariant(propertiesInterface) }},
		{"wrong path", func(m *dbus.Message) { m.Headers[dbus.FieldPath] = dbus.MakeVariant(dbus.ObjectPath("/wrong")) }},
		{"wrong destination", func(m *dbus.Message) { m.Headers[dbus.FieldDestination] = dbus.MakeVariant(":999.999") }},
		{"wrong member", func(m *dbus.Message) { m.Headers[dbus.FieldMember] = dbus.MakeVariant("Connect") }},
		{"signal", func(m *dbus.Message) { m.Type = dbus.TypeSignal }},
		{"no reply", func(m *dbus.Message) { m.Flags = dbus.FlagNoReplyExpected }},
		{"wrong signature", func(m *dbus.Message) { m.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf("unexpected")) }},
		{"body sender spoof", func(m *dbus.Message) { m.Body = []any{f.pin.Owner}; m.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(f.pin.Owner)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := nmPluginDisconnectMessage(f)
			tc.mutate(m)
			f.plugin.observe(m)
			if f.plugin.disconnected.Load() {
				t.Fatal("malformed Disconnect latched activation cancellation")
			}
		})
	}
	_ = f.connect(t)
}

func TestNMVPNWirePluginPendingDisconnectAndOwnerLoss(t *testing.T) {
	for _, mode := range []string{"pending Disconnect", "received Disconnect", "owner release", "owner reacquire", "owner replacement", "plugin close"} {
		t.Run(mode, func(t *testing.T) {
			f := nmPluginFixture(t)
			if err := f.call(f.service.conn, PluginInterface+".Connect", nmPluginProfile(f.plan, true)).Err; err != nil {
				t.Fatal(err)
			}
			a := f.plugin.activation.Load()
			if a == nil {
				t.Fatal("Connect did not capture activation")
			}
			if mode == "received Disconnect" {
				var err error
				a, err = f.plugin.Receive(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "pending Disconnect", "received Disconnect":
				if err := f.call(f.service.conn, PluginInterface+".Disconnect").Err; err != nil {
					t.Fatal(err)
				}
			case "owner release", "owner reacquire", "owner replacement":
				if _, err := f.service.conn.ReleaseName(NMName); err != nil {
					t.Fatal(err)
				}
				if mode != "owner release" {
					owner := f.service.conn
					if mode == "owner replacement" {
						owner = nmWireConn(t, f.socket)
					}
					if reply, err := owner.RequestName(NMName, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
						t.Fatal("synthetic replacement owner failed")
					}
				}
			case "plugin close":
				if err := f.plugin.Close(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-a.Context().Done():
			case <-f.ctx.Done():
				t.Fatal("disconnected/ownerless activation was not canceled")
			}
			called := false
			if err := a.UsePassword(f.ctx, func([]byte) error { called = true; return nil }); err == nil || called {
				t.Fatal("canceled activation consumed credential")
			}
			if a.Bind(f.ctx, f.binding, f.offer) == nil || a.MarkStarted(f.ctx) == nil {
				t.Fatal("canceled activation became usable")
			}
			if mode != "received Disconnect" {
				ctx, cancel := context.WithTimeout(f.ctx, 100*time.Millisecond)
				defer cancel()
				if pending, err := f.plugin.Receive(ctx); err == nil || pending != nil {
					t.Fatal("canceled queued Connect escaped Receive")
				}
			}
		})
	}
}
