package core

import (
	"bytes"
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

func TestStoreRejectsOversizeHiddenSuffix(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	data := append([]byte(`{"version":1}`), bytes.Repeat([]byte(" "), maxConfigBytes)...)
	data = append(data, []byte(`{"password":"hidden"}`)...)
	if e := os.WriteFile(p, data, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := (Store{p}).Load(); e == nil {
		t.Fatal("oversized suffix ignored")
	}
}
func TestValidationBoundariesAndControls(t *testing.T) {
	for _, gateway := range []string{"https://example.com:", "https://example.com:0", "https://example.com:65536", "https://example.com?", "https://example.com#", "https://example.com/" + strings.Repeat("x", 2048)} {
		p := profile()
		p.Gateway = gateway
		if ValidateProfile(p) == nil {
			t.Fatalf("accepted %q", gateway)
		}
	}
	for _, name := range []string{"x\nsecret", "x\x00", strings.Repeat("中", 81)} {
		p := profile()
		p.Name = name
		if ValidateProfile(p) == nil {
			t.Fatal("invalid name accepted")
		}
	}
	p := profile()
	p.Name = strings.Repeat("中", 80)
	p.Gateway = "https://example.com:65535"
	if e := ValidateProfile(p); e != nil {
		t.Fatal(e)
	}
}
func TestConfigLimitsDoNotMutateSavedFile(t *testing.T) {
	s := Store{filepath.Join(t.TempDir(), "settings.json")}
	c := Config{Profiles: []Profile{profile()}}
	if e := s.Save(c); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(s.Path)
	for _, bad := range []Config{{Settings: Settings{Language: "unsupported"}}, {Profiles: []Profile{{ID: strings.Repeat("x", 129), Name: "x", Protocol: "anyconnect", Gateway: "https://example.com"}}}} {
		if s.Save(bad) == nil {
			t.Fatal("invalid metadata accepted")
		}
		after, _ := os.ReadFile(s.Path)
		if !bytes.Equal(before, after) {
			t.Fatal("invalid save changed old file")
		}
	}
}
func TestFailedRenameRemovesPrivateTempFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.json")
	os.Mkdir(target, 0700)
	s := Store{target}
	if s.Save(Config{}) == nil {
		t.Fatal("directory destination accepted")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "config.json" {
		t.Fatal("temporary file leaked")
	}
	if _, e := s.Load(); e == nil {
		t.Fatal("directory accepted as config")
	}
}
func TestProfileLimitBeforeMutation(t *testing.T) {
	c := Config{}
	for i := 0; i < MaxProfiles; i++ {
		p := profile()
		p.ID = NewID()
		if e := c.Upsert(p); e != nil {
			t.Fatal(e)
		}
	}
	p := profile()
	p.ID = "new"
	if c.Upsert(p) == nil || len(c.Profiles) != MaxProfiles {
		t.Fatal("profile limit not enforced")
	}
	p = c.Profiles[0]
	p.Name = "updated"
	if c.Upsert(p) != nil || len(c.Profiles) != MaxProfiles {
		t.Fatal("limit prevented valid update")
	}
}
func TestAuthenticationDuplicateEmptyAndControlFields(t *testing.T) {
	for _, data := range []string{authFixture + "RESOLVE=''\n", strings.Replace(authFixture, "RESOLVE=", "RESOLVE=''\nRESOLVE=", 1), strings.Replace(authFixture, "test-cookie-opaque", "x\tmalicious", 1), strings.Repeat("x", 65537)} {
		if _, e := parseAuthentication([]byte(data)); e == nil {
			t.Fatal("malformed auth accepted")
		}
	}
}
func TestTerminalSessionCannotAdvertiseConnected(t *testing.T) {
	s := &fakeSession{ready: make(chan error, 1), done: make(chan error)}
	s.ready <- nil
	close(s.done)
	s.once.Do(func() {})
	e := NewEngine(sessionAdapter{s})
	if err := e.Connect(profile(), "", true); err != nil {
		t.Fatal(err)
	}
	await(t, e, Failed)
	for _, l := range e.Snapshot().Logs {
		if l.Message == "Tunnel readiness verified." {
			t.Fatal("dead session advertised connected")
		}
	}
}

type partialSessionAdapter struct{ s Session }

func (a partialSessionAdapter) Capability() Capability { return Capability{Available: true} }
func (a partialSessionAdapter) Start(context.Context, Profile, []byte) (Session, error) {
	return a.s, errors.New("failed after acquiring session")
}
func TestPartialStartCleansReturnedSession(t *testing.T) {
	s := &fakeSession{ready: make(chan error), done: make(chan error)}
	e := NewEngine(partialSessionAdapter{s})
	e.Connect(profile(), "", true)
	await(t, e, Failed)
	select {
	case <-s.done:
	default:
		t.Fatal("partial session leaked")
	}
}
func TestReplaceAdapterPreservesHistoryAndRejectsActive(t *testing.T) {
	a := blockingAdapter{make(chan struct{})}
	e := NewEngine(a)
	before := len(e.Snapshot().Logs)
	if err := e.ReplaceAdapter(a); err != nil {
		t.Fatal(err)
	}
	if len(e.Snapshot().Logs) != before+1 {
		t.Fatal("history dropped")
	}
	e.Connect(profile(), "", true)
	<-a.started
	if e.ReplaceAdapter(a) == nil {
		t.Fatal("active replacement allowed")
	}
	if err := e.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.ReplaceAdapter(a) == nil || e.Connect(profile(), "", true) == nil {
		t.Fatal("shutdown gate bypassed")
	}
}
func TestShutdownDeadlineDoesNotClaimCleanup(t *testing.T) {
	s := &blockingStopSession{ready: make(chan error, 1), done: make(chan error), release: make(chan struct{}), entered: make(chan struct{})}
	s.ready <- nil
	e := NewEngine(sessionAdapter{s})
	e.Connect(profile(), "", true)
	await(t, e, Connected)
	e.Disconnect()
	<-s.entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(e.Shutdown(ctx), context.Canceled) {
		t.Fatal("deadline ignored")
	}
	if e.Snapshot().State != Disconnecting {
		t.Fatal("cleanup falsely completed")
	}
	close(s.release)
	if err := e.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type blockingStopSession struct {
	ready, done      chan error
	release, entered chan struct{}
	once             sync.Once
}

func (s *blockingStopSession) Ready() <-chan error { return s.ready }
func (s *blockingStopSession) Done() <-chan error  { return s.done }
func (s *blockingStopSession) Stop() error {
	s.once.Do(func() { close(s.entered); <-s.release; close(s.done) })
	return nil
}
func TestUnexpectedTunnelLossPreservesFailure(t *testing.T) {
	r := &mockRunner{}
	raw, err := testNM(r).Start(context.Background(), profile(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := raw.(*nmSession)
	e := NewEngine(sessionAdapter{s})
	e.Connect(profile(), "", true)
	await(t, e, Connected)
	s.stopWithCause(errors.New("lost tunnel"))
	await(t, e, Failed)
}

// TestRunnerChild is only invoked as an isolated local test process. It never
// invokes networking tools, modifies routes, or reads credentials.
func TestRunnerChild(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "meridian-test-child" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	if mode == "large" {
		os.Stdout.Write(bytes.Repeat([]byte("x"), 70000))
		os.Exit(0)
	}
	if strings.HasPrefix(mode, "hang:") {
		os.WriteFile(strings.TrimPrefix(mode, "hang:"), []byte("ready"), 0600)
		time.Sleep(time.Hour)
		os.Exit(0)
	}
}
func TestExecRunnerBoundsOutputAndCancelsHungProcess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, e := (execRunner{}).Run(ctx, exe, []string{"-test.run=^TestRunnerChild$", "meridian-test-child", "large"}, nil); e == nil || out != nil {
		t.Fatal("output limit not enforced")
	}
	marker := filepath.Join(t.TempDir(), "ready")
	hangCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, e := (execRunner{}).Run(hangCtx, exe, []string{"-test.run=^TestRunnerChild$", "meridian-test-child", "hang:" + marker}, nil)
		done <- e
	}()
	for {
		if _, e := os.Stat(marker); e == nil {
			break
		}
		select {
		case e := <-done:
			t.Fatalf("child ended early: %v", e)
		case <-ctx.Done():
			t.Fatal("test child did not start")
		default:
			runtime.Gosched()
		}
	}
	stop()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not preserved: %v", err)
	}
}

func TestTypedNilAndMissingAdapterFailClosed(t *testing.T) {
	e := NewEngine(nil)
	if e.Connect(profile(), "", true) == nil {
		t.Fatal("nil adapter accepted")
	}
	var a *nilAdapter
	if e.ReplaceAdapter(a) == nil {
		t.Fatal("typed nil adapter accepted")
	}
	var s *fakeSession
	e = NewEngine(partialSessionAdapter{s})
	e.Connect(profile(), "", true)
	await(t, e, Failed)
}

type nilAdapter struct{}

func (*nilAdapter) Capability() Capability { panic("typed nil adapter invoked") }
func (*nilAdapter) Start(context.Context, Profile, []byte) (Session, error) {
	panic("typed nil adapter invoked")
}

type cancelAuthRunner struct {
	mockRunner
	cancel context.CancelFunc
}

func (r *cancelAuthRunner) Run(ctx context.Context, p string, a []string, input []byte) ([]byte, error) {
	out, e := r.mockRunner.Run(ctx, p, a, input)
	if p == "oc" {
		r.cancel()
	}
	return out, e
}
func TestCancelledAuthenticationNeverAddsProfile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &cancelAuthRunner{cancel: cancel}
	n := testNM(&r.mockRunner)
	n.runner = r
	if _, e := n.Start(ctx, profile(), nil); !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation not returned", e)
	}
	if len(r.calls) != 1 || r.calls[0].path != "oc" {
		t.Fatal("cancelled auth mutated NetworkManager")
	}
}

type partialAddRunner struct{ mockRunner }

func (r *partialAddRunner) Run(ctx context.Context, p string, a []string, input []byte) ([]byte, error) {
	out, e := r.mockRunner.Run(ctx, p, a, input)
	if strings.Contains(strings.Join(a, " "), "connection add") {
		return nil, context.DeadlineExceeded
	}
	return out, e
}
func TestUncertainAddAttemptsUUIDOnlyCleanup(t *testing.T) {
	r := &partialAddRunner{}
	n := testNM(&r.mockRunner)
	n.runner = r
	if _, e := n.Start(context.Background(), profile(), nil); e == nil {
		t.Fatal("uncertain add accepted")
	}
	deleted := false
	for _, c := range r.calls {
		args := strings.Join(c.args, " ")
		if strings.Contains(args, "connection up") {
			t.Fatal("activated after failed add")
		}
		if strings.Contains(args, "connection delete uuid") {
			deleted = true
		}
	}
	if !deleted {
		t.Fatal("partial add not cleaned")
	}
}
func TestMalformedInventoryCannotProveCleanup(t *testing.T) {
	id := "12345678-1234-4123-a123-123456789abc"
	for _, data := range []string{"ERROR", "garbage\n", "123", id + "\ninvalid"} {
		if _, valid := uuidAbsent([]byte(data), id); valid {
			t.Fatal("invalid inventory accepted")
		}
	}
	if absent, valid := uuidAbsent([]byte(strings.ToUpper(id)), id); absent || !valid {
		t.Fatal("active UUID ignored")
	}
	if absent, valid := uuidAbsent(nil, id); !absent || !valid {
		t.Fatal("empty inventory rejected")
	}
}
