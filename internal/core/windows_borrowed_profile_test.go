package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func windowsBorrowedProfile() Profile {
	return Profile{ID: "win", Name: "Existing VPN", Protocol: WindowsBorrowedProtocol, Gateway: "vpn.example.test", Username: "user", WindowsBorrowed: &WindowsBorrowedOptions{PhonebookPath: `C:\Users\User\vpn.pbk`, EntryName: "VPN", Domain: "CORP"}}
}
func TestWindowsBorrowedSchemaIsDistinctAndSecretFree(t *testing.T) {
	p := windowsBorrowedProfile()
	if err := ValidateProfile(p); err != nil {
		t.Fatal(err)
	}
	for _, protocol := range Protocols {
		if protocol == WindowsBorrowedProtocol {
			t.Fatal("dormant schema advertised in UI")
		}
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var round Profile
	if json.Unmarshal(data, &round) != nil || ValidateProfile(round) != nil || round.WindowsBorrowed.PhonebookPath != p.WindowsBorrowed.PhonebookPath {
		t.Fatal("selection roundtrip failed")
	}
	data, _ = json.Marshal(SessionAuthorization{true, true, true})
	if string(data) != "{}" {
		t.Fatal("consent serialized")
	}
	var injected SessionAuthorization
	if json.Unmarshal([]byte(`{"NetworkChanges":true,"WindowsCredentialPersistence":true,"WindowsSharedReference":true}`), &injected) != nil || injected != (SessionAuthorization{}) {
		t.Fatal("JSON granted consent")
	}
	cfg := Config{}
	original := windowsBorrowedProfile()
	if cfg.Upsert(original) != nil {
		t.Fatal("valid config rejected")
	}
	original.WindowsBorrowed.EntryName = "changed"
	if cfg.Profiles[0].WindowsBorrowed.EntryName != "VPN" {
		t.Fatal("stored selection aliases editor")
	}
	data, _ = json.Marshal(Credentials{Password: []byte("secret")})
	if strings.Contains(string(data), "secret") {
		t.Fatal("password serialized")
	}
	for _, mutate := range []func(*Profile){
		func(p *Profile) { p.WindowsBorrowed = nil }, func(p *Profile) { p.Protocol = "anyconnect"; p.Gateway = "https://vpn.example.test" },
		func(p *Profile) { p.WindowsBorrowed.PhonebookPath = `\\server\share\vpn.pbk` }, func(p *Profile) { p.WindowsBorrowed.PhonebookPath = `C:\CON\vpn.pbk` },
		func(p *Profile) { p.WindowsBorrowed.Domain = "*" }, func(p *Profile) { p.Username = "" }, func(p *Profile) { p.Gateway = "https://vpn.example.test" },
		func(p *Profile) { p.L2TP = &L2TPOptions{} }, func(p *Profile) { p.ProxyURL = "http://proxy.example.test" }, func(p *Profile) { p.MTU = 1400 }, func(p *Profile) { p.AdditionalGateways = []string{"other.example.test"} },
	} {
		p := windowsBorrowedProfile()
		mutate(&p)
		if ValidateProfile(p) == nil {
			t.Fatal("invalid borrowed profile accepted")
		}
	}
	for _, c := range []Credentials{{}, {Password: []byte("ok"), IPsecPSK: []byte("not-accepted")}, {Password: []byte("ok"), KeyPassword: []byte("not-accepted")}, {Password: []byte{0xff}}, {Password: []byte(strings.Repeat("a", 257))}} {
		if validateCredentials(windowsBorrowedProfile(), c) == nil {
			t.Fatal("invalid borrowed credentials accepted")
		}
	}
}

type authorizationTestAdapter struct {
	received chan SessionAuthorization
	profiles chan Profile
	session  Session
}

func (a *authorizationTestAdapter) VerificationScope() string {
	return WindowsBorrowedObservedInterface
}
func (a *authorizationTestAdapter) Capability() Capability { return Capability{Available: true} }
func (a *authorizationTestAdapter) Start(context.Context, Profile, []byte) (Session, error) {
	panic("legacy start must not run")
}
func (a *authorizationTestAdapter) StartWithAuthorization(_ context.Context, p Profile, _ Credentials, consent SessionAuthorization) (Session, error) {
	a.profiles <- p
	a.received <- consent
	return a.session, nil
}
func TestWindowsBorrowedNeedsFreshExplicitRequestAndAdapter(t *testing.T) {
	p := windowsBorrowedProfile()
	c := Credentials{Password: []byte("secret")}
	a := &authorizationTestAdapter{received: make(chan SessionAuthorization, 1), profiles: make(chan Profile, 1), session: newLifecycleSession()}
	e := NewEngine(a)
	for _, consent := range []SessionAuthorization{{}, {true, false, false}, {true, true, false}, {true, false, true}} {
		if e.ConnectWithAuthorization(p, c, consent) == nil {
			t.Fatal("missing per-use consent accepted")
		}
	}
	if e.ConnectWithCredentials(p, c, true) == nil {
		t.Fatal("legacy bool authorized Windows persistence")
	}
	if NewEngine(sessionAdapter{}).ConnectWithAuthorization(p, c, SessionAuthorization{true, true, true}) == nil {
		t.Fatal("legacy backend accepted borrowed mode")
	}
	if err := e.ConnectWithAuthorization(p, c, SessionAuthorization{true, true, true}); err != nil {
		t.Fatal(err)
	}
	p.WindowsBorrowed.EntryName = "changed-after-request"
	got := <-a.profiles
	if got.WindowsBorrowed.EntryName != "VPN" {
		t.Fatal("asynchronous profile aliased caller")
	}
	if got := <-a.received; got != (SessionAuthorization{true, true, true}) {
		t.Fatal("consent lost")
	}
	if string(c.Password) != "secret" {
		t.Fatal("caller secret modified")
	}
	if err := e.Disconnect(); err != nil {
		t.Fatal(err)
	}
	await(t, e, Disconnected)
	if string(c.Password) != "secret" {
		t.Fatal("caller secret modified after completion")
	}
}
