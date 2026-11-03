package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func profile() Profile {
	return Profile{ID: "one", Name: "Office", Gateway: "https://vpn.example.com", Protocol: "anyconnect", Username: "alice"}
}
func TestProfileValidation(t *testing.T) {
	for _, u := range []string{"http://example.com", "https://alice:secret@example.com", "https://example.com?token=secret", "https://example.com#secret", "https://example.com\n--insecure", "https:///"} {
		p := profile()
		p.Gateway = u
		if ValidateProfile(p) == nil {
			t.Errorf("accepted %q", u)
		}
	}
	p := profile()
	p.Protocol = "--insecure"
	if ValidateProfile(p) == nil {
		t.Fatal("accepted protocol injection")
	}
	if err := ValidateProfile(profile()); err != nil {
		t.Fatal(err)
	}
}
func TestStoreCRUDAndPermissions(t *testing.T) {
	s := Store{filepath.Join(t.TempDir(), "private", "config.json")}
	c, err := s.Load()
	if err != nil || len(c.Profiles) != 0 {
		t.Fatal(err)
	}
	if err = c.Upsert(profile()); err != nil {
		t.Fatal(err)
	}
	if err = s.Save(c); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.Load()
	if err != nil || len(loaded.Profiles) != 1 || loaded.SelectedID != "one" {
		t.Fatalf("%+v %v", loaded, err)
	}
	st, _ := os.Stat(s.Path)
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
	p := profile()
	p.Name = "New office"
	loaded.Upsert(p)
	if len(loaded.Profiles) != 1 || loaded.Profiles[0].Name != p.Name {
		t.Fatal("update failed")
	}
	loaded.Delete(p.ID)
	if len(loaded.Profiles) != 0 || loaded.SelectedID != "" {
		t.Fatal("delete failed")
	}
	if err = s.Save(loaded); err != nil {
		t.Fatal(err)
	}
}
func TestStoreRejectsSecretAndCorruption(t *testing.T) {
	s := Store{filepath.Join(t.TempDir(), "config.json")}
	for _, data := range []string{`{"version":1,"password":"secret"}`, `{"version":2}`, `{"version":1} {}`, `bad json`} {
		os.WriteFile(s.Path, []byte(data), 0600)
		if _, e := s.Load(); e == nil {
			t.Errorf("accepted %s", data)
		}
	}
}
func TestArgsNoShellOrSecret(t *testing.T) {
	p := profile()
	p.Username = "alice; echo owned"
	args, e := OpenConnectArgs(p)
	if e != nil {
		t.Fatal(e)
	}
	if len(args) != 7 || args[3] != "--user=alice; echo owned" || args[4] != "--no-proxy" || args[5] != "--" {
		t.Fatal(args)
	}
	if !strings.Contains(strings.Join(args, " "), "--passwd-on-stdin") {
		t.Fatal(args)
	}
}

type fakeSession struct {
	ready, done chan error
	once        sync.Once
}

func (s *fakeSession) Ready() <-chan error { return s.ready }
func (s *fakeSession) Done() <-chan error  { return s.done }
func (s *fakeSession) Stop() error         { s.once.Do(func() { close(s.done) }); return nil }

type fakeAdapter struct {
	s       *fakeSession
	started chan struct{}
	err     error
}

func (a fakeAdapter) Capability() Capability { return Capability{Available: true} }
func (a fakeAdapter) Start(_ context.Context, _ Profile, _ []byte) (Session, error) {
	close(a.started)
	return a.s, a.err
}
func await(t *testing.T, e *Engine, want string) {
	t.Helper()
	deadline := time.Now().Add(time.Second * 5)
	for e.Snapshot().State != want {
		if time.Now().After(deadline) {
			t.Fatalf("wanted %s; got %+v", want, e.Snapshot())
		}
		runtime.Gosched()
	}
}
func TestVerifiedLifecycle(t *testing.T) {
	s := &fakeSession{make(chan error, 1), make(chan error, 1), sync.Once{}}
	a := fakeAdapter{s, make(chan struct{}), nil}
	e := NewEngine(a)
	if e.Connect(profile(), "never-log-me", false) == nil {
		t.Fatal("authorization not enforced")
	}
	if err := e.Connect(profile(), "never-log-me", true); err != nil {
		t.Fatal(err)
	}
	<-a.started
	if e.Snapshot().State != Connecting {
		t.Fatal("process spawn counted as connected")
	}
	if e.Connect(profile(), "", true) == nil {
		t.Fatal("double connect allowed")
	}
	s.ready <- nil
	await(t, e, Connected)
	e.Disconnect()
	await(t, e, Disconnected)
	for _, l := range e.Snapshot().Logs {
		if strings.Contains(l.Message, "never-log-me") {
			t.Fatal("secret leaked")
		}
	}
}
func TestBackendErrorRedacted(t *testing.T) {
	a := fakeAdapter{nil, make(chan struct{}), errors.New("password=SUPERSECRET")}
	e := NewEngine(a)
	e.Connect(profile(), "SUPERSECRET", true)
	await(t, e, Failed)
	snap := e.Snapshot()
	if strings.Contains(snap.Message, "SUPERSECRET") {
		t.Fatal("secret leaked")
	}
	for _, l := range snap.Logs {
		if strings.Contains(l.Message, "SUPERSECRET") {
			t.Fatal("secret logged")
		}
	}
}
func TestClosedReadinessNeverConnected(t *testing.T) {
	s := &fakeSession{make(chan error), make(chan error), sync.Once{}}
	close(s.ready)
	a := fakeAdapter{s, make(chan struct{}), nil}
	e := NewEngine(a)
	e.Connect(profile(), "", true)
	await(t, e, Failed)
}
func TestOpenConnectBlockedWithoutBroker(t *testing.T) {
	o := OpenConnect{}
	if o.Capability().Available {
		t.Fatal("unbrokered route changes enabled")
	}
	if _, err := o.Start(context.Background(), profile(), nil); err == nil {
		t.Fatal("unbrokered start allowed")
	}
}

type blockingAdapter struct{ started chan struct{} }

func (a blockingAdapter) Capability() Capability { return Capability{Available: true} }
func (a blockingAdapter) Start(ctx context.Context, _ Profile, _ []byte) (Session, error) {
	close(a.started)
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestDisconnectDuringStart(t *testing.T) {
	a := blockingAdapter{make(chan struct{})}
	e := NewEngine(a)
	if err := e.Connect(profile(), "", true); err != nil {
		t.Fatal(err)
	}
	<-a.started
	e.Disconnect()
	await(t, e, Disconnected)
	if err := e.Disconnect(); err != nil {
		t.Fatal(err)
	}
}
func TestInvalidSavePreservesLastGoodConfig(t *testing.T) {
	s := Store{filepath.Join(t.TempDir(), "config.json")}
	c := Config{Profiles: []Profile{profile()}, SelectedID: "one"}
	if err := s.Save(c); err != nil {
		t.Fatal(err)
	}
	c.Profiles[0].Gateway = "http://unsafe.example"
	if s.Save(c) == nil {
		t.Fatal("invalid config persisted")
	}
	loaded, err := s.Load()
	if err != nil || loaded.Profiles[0].Gateway != "https://vpn.example.com" {
		t.Fatalf("previous valid config damaged: %+v %v", loaded, err)
	}
}
