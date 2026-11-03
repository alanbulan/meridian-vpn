package core

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

const authFixture = "COOKIE='test-cookie-opaque'\nHOST='192.0.2.1'\nCONNECT_URL='https://vpn.example.com'\nFINGERPRINT='sha256:test-fixture-only'\nRESOLVE='vpn.example.com:192.0.2.1'\n"

type call struct {
	path  string
	args  []string
	input string
}
type mockRunner struct {
	mu                           sync.Mutex
	calls                        []call
	failUp, failDelete, notReady bool
}

func (r *mockRunner) Run(_ context.Context, p string, a []string, input []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call{p, append([]string(nil), a...), string(input)})
	joined := strings.Join(a, " ")
	switch {
	case p == "oc":
		return []byte(authFixture), nil
	case strings.Contains(joined, "connection up"):
		if r.failUp {
			return nil, errors.New("secret response")
		}
	case strings.Contains(joined, "-g UUID connection show"):
		if r.failDelete {
			return nil, errors.New("query denied")
		}
		return []byte(""), nil
	case strings.Contains(joined, "connection delete"):
		if r.failDelete {
			return nil, errors.New("denied")
		}
	case strings.Contains(joined, "GENERAL.STATE"):
		if r.notReady {
			return []byte("activating\n2 - VPN connecting\n"), nil
		}
		return []byte("activated\n5 - VPN connected\n"), nil
	}
	return []byte("ok"), nil
}
func testNM(r *mockRunner) *NetworkManager {
	return &NetworkManager{runner: r, nm: "nm", oc: "oc", cap: Capability{Available: true}, interfaceGone: func(string) bool { return true }, checkInterface: func(n string) bool { return strings.HasPrefix(n, "md") && len(n) == 12 }}
}
func TestNetworkManagerLifecycleNoSecretsInArgv(t *testing.T) {
	r := &mockRunner{}
	n := testNM(r)
	s, e := n.Start(context.Background(), profile(), []byte("secret-password"))
	if e != nil {
		t.Fatal(e)
	}
	if e = <-s.Ready(); e != nil {
		t.Fatal(e)
	}
	if e = s.Stop(); e != nil {
		t.Fatal(e)
	}
	if e = s.Stop(); e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	deletes := 0
	uuid := ""
	for _, c := range r.calls {
		args := strings.Join(c.args, " ")
		if strings.Contains(args, "secret-password") || strings.Contains(args, "test-cookie-opaque") {
			t.Fatal("secret in process argv")
		}
		if c.path == "oc" && c.input != "secret-password\n" {
			t.Fatal("password not sent through stdin")
		}
		if strings.Contains(args, "connection add") {
			if !strings.Contains(args, "save no") || !strings.Contains(args, "connection.autoconnect no") {
				t.Fatal("profile is persistent or autoconnects")
			}
			for i, v := range c.args {
				if v == "connection.uuid" {
					uuid = c.args[i+1]
				}
			}
		}
		if strings.Contains(args, "connection up") {
			if !strings.Contains(c.input, "vpn.secrets.cookie:test-cookie-opaque") || !strings.Contains(args, "/proc/self/fd/0") {
				t.Fatal("cookie not ephemeral stdin")
			}
		}
		if strings.Contains(args, "connection delete") {
			deletes++
			if c.args[len(c.args)-1] != uuid || uuid == "" {
				t.Fatal("cleanup touched unowned profile")
			}
		}
	}
	if deletes != 1 {
		t.Fatal("cleanup not idempotent")
	}
}
func TestNetworkManagerFailureCleansOwnProfile(t *testing.T) {
	for _, r := range []*mockRunner{{failUp: true}, {notReady: true}} {
		_, err := testNM(r).Start(context.Background(), profile(), nil)
		if err == nil {
			t.Fatal("failure accepted")
		}
		deleted := false
		for _, c := range r.calls {
			if strings.Contains(strings.Join(c.args, " "), "connection delete uuid") {
				deleted = true
			}
		}
		if !deleted {
			t.Fatal("failure leaked temporary profile")
		}
	}
}
func TestNetworkManagerCleanupFailureIsExplicit(t *testing.T) {
	r := &mockRunner{failUp: true, failDelete: true}
	_, err := testNM(r).Start(context.Background(), profile(), nil)
	var ce *CleanupError
	if !errors.As(err, &ce) {
		t.Fatal("cleanup failure hidden", err)
	}
}
func TestAuthenticationParserNeverEvaluates(t *testing.T) {
	if _, e := parseAuthentication([]byte(authFixture)); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"COOKIE=$(touch /tmp/owned)", "COOKIE='x'; touch /tmp/owned", authFixture + "EVIL='anything'\n", strings.Replace(authFixture, "https://vpn.example.com", "http://vpn.example.com", 1), strings.Replace(authFixture, "test-cookie-opaque", "one'\\''two", 1)} {
		if _, e := parseAuthentication([]byte(s)); e == nil {
			t.Fatal("accepted malformed auth output")
		}
	}
}
func TestNetworkManagerRejectsUnsupportedBeforeAnyProcess(t *testing.T) {
	r := &mockRunner{}
	p := profile()
	p.Protocol = "gp"
	if _, e := testNM(r).Start(context.Background(), p, nil); e == nil {
		t.Fatal("unsupported protocol")
	}
	if len(r.calls) != 0 {
		t.Fatal("process ran for unsupported protocol")
	}
}

type badStopSession struct{ fakeSession }

func (s *badStopSession) Stop() error { return &CleanupError{} }
func TestEngineShutdownPreservesCleanupFailure(t *testing.T) {
	s := &badStopSession{fakeSession{ready: make(chan error, 1), done: make(chan error)}}
	s.ready <- nil
	a := sessionAdapter{s}
	e := NewEngine(a)
	if err := e.Connect(profile(), "", true); err != nil {
		t.Fatal(err)
	}
	await(t, e, Connected)
	if err := e.Shutdown(context.Background()); err == nil {
		t.Fatal("shutdown ignored failed cleanup")
	}
	if e.Snapshot().State != CleanupFailed {
		t.Fatal(e.Snapshot())
	}
	if e.Connect(profile(), "", true) == nil {
		t.Fatal("reconnect allowed with uncertain cleanup")
	}
}

type sessionAdapter struct{ s Session }

func (a sessionAdapter) Capability() Capability                                  { return Capability{Available: true} }
func (a sessionAdapter) Start(context.Context, Profile, []byte) (Session, error) { return a.s, nil }
