//go:build linux

package nmvpn

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

func pluginProfileFixture(t *testing.T) (PluginPlan, map[string]map[string]dbus.Variant) {
	t.Helper()
	s, id := profileFixture()
	p, err := NewPluginPlan(id.UUID, id.Interface, "alice")
	if err != nil {
		t.Fatal(err)
	}
	s["vpn"]["user-name"] = dbus.MakeVariant(p.Username)
	s["vpn"]["data"] = dbus.MakeVariant(map[string]string{"meridian-activation": p.Nonce, "password-flags": "2"})
	s["vpn"]["secrets"] = dbus.MakeVariant(map[string]string{"password": "owned-test-password"})
	return p, s
}
func TestIncomingProfileSeparatesCredentialsAndFreezes(t *testing.T) {
	p, s := pluginProfileFixture(t)
	s["ipv4"]["dns-search"] = dbus.MakeVariant([]string{})
	s["connection"]["permissions"] = dbus.MakeVariant([]string{})
	profile, password, err := incomingProfile(s, p)
	if err != nil || password != "owned-test-password" {
		t.Fatal("valid credential envelope rejected")
	}
	for _, k := range []string{"user-name", "data", "secrets"} {
		if _, ok := profile["vpn"][k]; ok {
			t.Fatal("envelope leaked into immutable network profile")
		}
	}
	s["ipv4"]["method"] = dbus.MakeVariant("manual")
	s["vpn"]["secrets"].Value().(map[string]string)["password"] = "changed"
	if ValidateProfile(profile, Identity{UUID: p.UUID, Interface: p.Interface}) != nil {
		t.Fatal("captured profile aliased caller maps")
	}
	clone := cloneSafeProfile(profile)
	clone["connection"]["permissions"] = dbus.MakeVariant([]string{"user:other:"})
	if reflect.DeepEqual(clone, profile) {
		t.Fatal("profile snapshot writable alias")
	}
}
func TestIncomingProfileRejectsCredentialEnvelope(t *testing.T) {
	mutations := map[string]func(map[string]map[string]dbus.Variant){
		"missing_nonce": func(s map[string]map[string]dbus.Variant) {
			delete(s["vpn"]["data"].Value().(map[string]string), "meridian-activation")
		},
		"missing_not_saved": func(s map[string]map[string]dbus.Variant) {
			delete(s["vpn"]["data"].Value().(map[string]string), "password-flags")
		},
		"different_nonce": func(s map[string]map[string]dbus.Variant) {
			s["vpn"]["data"].Value().(map[string]string)["meridian-activation"] = strings.Repeat("0", 32)
		},
		"foreign_data": func(s map[string]map[string]dbus.Variant) {
			s["vpn"]["data"].Value().(map[string]string)["gateway"] = "other"
		},
		"wrong_user": func(s map[string]map[string]dbus.Variant) { s["vpn"]["user-name"] = dbus.MakeVariant("other") },
		"foreign_secret": func(s map[string]map[string]dbus.Variant) {
			s["vpn"]["secrets"] = dbus.MakeVariant(map[string]string{"cookie": "do-not-expose"})
		},
		"oversized_secret": func(s map[string]map[string]dbus.Variant) {
			s["vpn"]["secrets"] = dbus.MakeVariant(map[string]string{"password": strings.Repeat("x", 4096)})
		},
		"line_secret": func(s map[string]map[string]dbus.Variant) {
			s["vpn"]["secrets"] = dbus.MakeVariant(map[string]string{"password": "x\ny"})
		},
		"bad_type": func(s map[string]map[string]dbus.Variant) {
			s["vpn"]["secrets"] = dbus.MakeVariant(map[string]dbus.Variant{"password": dbus.MakeVariant("x")})
		},
		"network_change": func(s map[string]map[string]dbus.Variant) { s["ipv4"]["ignore-auto-dns"] = dbus.MakeVariant(false) },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			p, s := pluginProfileFixture(t)
			change(s)
			if _, _, err := incomingProfile(s, p); err == nil {
				t.Fatal("accepted unsupported envelope")
			}
		})
	}
	p, s := pluginProfileFixture(t)
	delete(s["vpn"], "secrets")
	if _, password, err := incomingProfile(s, p); err != nil || password != "" {
		t.Fatal("NeedSecrets cannot inspect missing password")
	}
}
func TestActivationOneShotPasswordAndFailureErasure(t *testing.T) {
	for _, fails := range []bool{false, true} {
		p, s := pluginProfileFixture(t)
		profile, _, _ := incomingProfile(s, p)
		ctx, cancel := context.WithCancel(context.Background())
		server := &Plugin{plan: p, bus: &PinnedBus{}, ctx: ctx}
		a := &Activation{plugin: server, profile: profile, ctx: ctx, cancel: cancel, password: []byte("owned-secret")}
		server.activation.Store(a)
		var retained []byte
		err := a.UsePassword(ctx, func(v []byte) error {
			retained = v
			if string(v) != "owned-secret" {
				t.Fatal("wrong secret")
			}
			if fails {
				return errors.New("owned-secret")
			}
			return nil
		})
		if (err != nil) != fails {
			t.Fatal("incorrect callback outcome")
		}
		if err != nil && strings.Contains(err.Error(), "owned-secret") {
			t.Fatal("callback error leaked secret")
		}
		for _, b := range retained {
			if b != 0 {
				t.Fatal("owned bytes not erased")
			}
		}
		if a.UsePassword(ctx, func([]byte) error { t.Fatal("secret replayed"); return nil }) == nil {
			t.Fatal("second consumption allowed")
		}
		if a.usedOK == fails {
			t.Fatal("failed callback produced launch authorization")
		}
		cancel()
	}
	zero := &Activation{}
	if zero.UsePassword(context.Background(), func([]byte) error { t.Fatal("forged activation invoked callback"); return nil }) == nil || zero.CheckLive(context.Background()) == nil {
		t.Fatal("zero activation accepted")
	}
}
func TestPluginDisconnectEnvelopeFence(t *testing.T) {
	b := &PinnedBus{pin: BusPin{Owner: ":1.42"}, unique: ":1.9"}
	valid := func() *dbus.Message {
		return &dbus.Message{Type: dbus.TypeMethodCall, Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldSender: dbus.MakeVariant(b.pin.Owner), dbus.FieldDestination: dbus.MakeVariant(b.unique), dbus.FieldPath: dbus.MakeVariant(PluginPath), dbus.FieldInterface: dbus.MakeVariant(PluginInterface), dbus.FieldMember: dbus.MakeVariant("Disconnect"),
		}}
	}
	for _, change := range []func(*dbus.Message){
		func(m *dbus.Message) { m.Headers[dbus.FieldSender] = dbus.MakeVariant(":1.8") },
		func(m *dbus.Message) { m.Headers[dbus.FieldInterface] = dbus.MakeVariant(propertiesInterface) },
		func(m *dbus.Message) { delete(m.Headers, dbus.FieldInterface) },
		func(m *dbus.Message) { m.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf("x")) },
		func(m *dbus.Message) { m.Body = []any{"x"} },
		func(m *dbus.Message) { m.Flags = dbus.FlagNoReplyExpected },
	} {
		p := &Plugin{bus: b, disconnectCh: make(chan struct{})}
		m := valid()
		change(m)
		p.observe(m)
		if p.disconnected.Load() {
			t.Fatal("invalid request fenced activation")
		}
	}
	p := &Plugin{bus: b, disconnectCh: make(chan struct{})}
	p.observe(valid())
	p.observe(valid())
	if !p.disconnected.Load() {
		t.Fatal("valid disconnect not fenced")
	}
	select {
	case <-p.disconnectCh:
	default:
		t.Fatal("disconnect did not notify lifecycle")
	}
}

func TestActivationUnusedSecretExpires(t *testing.T) {
	p, _ := pluginProfileFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &Plugin{plan: p, bus: &PinnedBus{}, ctx: ctx, disconnectCh: make(chan struct{})}
	owned := []byte("owned-secret")
	a := &Activation{plugin: server, ctx: ctx, cancel: cancel, password: owned}
	server.activation.Store(a)
	a.expireSecret()
	if a.Context().Err() == nil || !server.disconnected.Load() {
		t.Fatal("expired credential did not revoke activation")
	}
	for _, b := range owned {
		if b != 0 {
			t.Fatal("expired owned credential retained")
		}
	}
	if a.UsePassword(context.Background(), func([]byte) error { t.Fatal("expired credential consumed"); return nil }) == nil {
		t.Fatal("expired activation accepted")
	}
}
