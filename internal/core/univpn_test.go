package core

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type uvTestBroker struct {
	s       *fakeSession
	args    []string
	secret  string
	started chan struct{}
}

func (b *uvTestBroker) Available() bool { return true }
func (b *uvTestBroker) Start(_ context.Context, _ string, args []string, secret []byte) (Session, error) {
	b.args = append([]string(nil), args...)
	b.secret = string(secret)
	if b.started != nil {
		close(b.started)
	}
	return b.s, nil
}
func uvProfile() Profile {
	return Profile{Name: "UniVPN", Protocol: "univpn", Gateway: "https://vpn.example.invalid", Username: "user", AuthGroup: "domain"}
}
func uvExecutable(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "native")
	if err := os.WriteFile(p, []byte("placeholder: tests never execute this file"), 0700); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestUniVPNArgs(t *testing.T) {
	p := uvProfile()
	p.MTU = 1400
	a, e := UniVPNArgs(p)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"--protocol=univpn", "--no-proxy", "--no-dtls", "--passwd-on-stdin", "--mtu=1400"} {
		if !slices.Contains(a, v) {
			t.Fatal(a)
		}
	}
	if slices.Contains(a, "--authenticate") {
		t.Fatal("cookie handoff forbidden")
	}
	if a[len(a)-1] != p.Gateway {
		t.Fatal(a)
	}
}
func TestUniVPNUnsupportedOptionsFailClosed(t *testing.T) {
	for _, edit := range []func(*Profile){func(p *Profile) { p.Protocol = "anyconnect" }, func(p *Profile) { p.InteractiveAuth = true }, func(p *Profile) { p.ProxyURL = "http://localhost:8080" }, func(p *Profile) { p.AuthGroup = strings.Repeat("x", 256) }, func(p *Profile) { p.Gateway += "/path" }} {
		p := uvProfile()
		edit(&p)
		if _, e := UniVPNArgs(p); e == nil {
			t.Fatalf("accepted unsupported profile %+v", p)
		}
	}
}
func TestUniVPNRequiresContinuousBroker(t *testing.T) {
	u := UniVPN{Executable: uvExecutable(t)}
	if u.Capability().Available || u.SupportsProtocol("univpn") {
		t.Fatal("native file alone must not enable connection")
	}
	if _, e := u.Start(context.Background(), uvProfile(), []byte("secret")); e == nil {
		t.Fatal("missing broker accepted")
	}
	var nilBroker *uvTestBroker
	u.Broker = nilBroker
	if u.Capability().Available {
		t.Fatal("typed nil broker")
	}
}
func TestUniVPNEngineLifecycle(t *testing.T) {
	s := &fakeSession{ready: make(chan error, 1), done: make(chan error, 1)}
	b := &uvTestBroker{s: s, started: make(chan struct{})}
	u := UniVPN{Executable: uvExecutable(t), Broker: b}
	e := NewEngine(u)
	if err := e.Connect(uvProfile(), "mock-secret", true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.started:
	case <-time.After(time.Second):
		t.Fatal("start timeout")
	}
	if e.Snapshot().State != Connecting {
		t.Fatal("process start must not imply ready")
	}
	if b.secret != "mock-secret" || strings.Contains(strings.Join(b.args, " "), "mock-secret") {
		t.Fatal("secret transport")
	}
	s.ready <- nil
	await(t, e, Connected)
	if err := e.Disconnect(); err != nil {
		t.Fatal(err)
	}
	await(t, e, Disconnected)
}
func TestUniVPNRouterNoFallback(t *testing.T) {
	r := ProtocolRouter{Primary: sessionAdapter{&fakeSession{}}}
	if r.SupportsProtocol("univpn") {
		t.Fatal("fallback must not advertise UniVPN")
	}
	if _, e := r.Start(context.Background(), uvProfile(), nil); e == nil {
		t.Fatal("fallback must not run UniVPN")
	}
}
