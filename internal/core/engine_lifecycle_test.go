package core

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type lifecycleSession struct {
	ready, done chan error
	stopping    chan struct{}
	release     chan struct{}
	stopErr     error
	once        sync.Once
}

func (s *lifecycleSession) Ready() <-chan error { return s.ready }
func (s *lifecycleSession) Done() <-chan error  { return s.done }
func (s *lifecycleSession) Stop() error {
	s.once.Do(func() {
		close(s.stopping)
		if s.release != nil {
			<-s.release
		}
	})
	return s.stopErr
}

func newLifecycleSession() *lifecycleSession {
	return &lifecycleSession{
		ready: make(chan error, 1), done: make(chan error, 1), stopping: make(chan struct{}),
	}
}

func waitLifecycleSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for session lifecycle")
	}
}

func TestEngineUnexpectedTerminationRequiresFreshAuthentication(t *testing.T) {
	for _, mode := range []string{"nil-result", "closed-channel", "backend-error"} {
		t.Run(mode, func(t *testing.T) {
			s := newLifecycleSession()
			e := NewEngine(sessionAdapter{s})
			if err := e.Connect(profile(), "", true); err != nil {
				t.Fatal(err)
			}
			s.ready <- nil
			await(t, e, Connected)
			switch mode {
			case "closed-channel":
				close(s.done)
			case "backend-error":
				s.done <- errors.New("secret-backend-detail")
			default:
				s.done <- nil
			}
			await(t, e, Failed)
			waitLifecycleSignal(t, s.stopping)
			snapshot := e.Snapshot()
			if !strings.Contains(snapshot.Message, "Sign in again") || strings.Contains(snapshot.Message, "secret-backend-detail") {
				t.Fatalf("unexpected loss message: %s", snapshot.Message)
			}
			if !snapshot.ConnectedAt.IsZero() || snapshot.MetricsAvailable {
				t.Fatal("terminated session advertised connection metadata")
			}
		})
	}
}

func TestEngineUnexpectedLossShowsCleanupInProgress(t *testing.T) {
	s := newLifecycleSession()
	s.release = make(chan struct{})
	var released sync.Once
	release := func() { released.Do(func() { close(s.release) }) }
	defer release()
	e := NewEngine(sessionAdapter{s})
	if err := e.Connect(profile(), "", true); err != nil {
		t.Fatal(err)
	}
	s.ready <- nil
	await(t, e, Connected)
	s.done <- errors.New("lost")
	waitLifecycleSignal(t, s.stopping)
	snapshot := e.Snapshot()
	if snapshot.State != Disconnecting || !snapshot.ConnectedAt.IsZero() || snapshot.MetricsAvailable {
		t.Fatalf("cleanup advertised a usable tunnel: %+v", snapshot)
	}
	if e.Connect(profile(), "", true) == nil {
		t.Fatal("reconnect allowed before cleanup confirmation")
	}
	release()
	await(t, e, Failed)
}

type lifecycleAdapter struct{ start func(context.Context) (Session, error) }

func (a lifecycleAdapter) Capability() Capability { return Capability{Available: true} }
func (a lifecycleAdapter) Start(ctx context.Context, _ Profile, _ []byte) (Session, error) {
	return a.start(ctx)
}

func TestEngineCancellationWinsReadinessAndTerminationRace(t *testing.T) {
	for _, mode := range []string{"ready-error", "ready-closed", "done-error", "done-closed", "ready-success"} {
		t.Run(mode, func(t *testing.T) {
			// Make cancellation and the backend signal ready before Start returns,
			// so the result cannot depend on which select arm Go chooses.
			for i := 0; i < 30; i++ {
				s := newLifecycleSession()
				started := make(chan struct{})
				a := lifecycleAdapter{start: func(ctx context.Context) (Session, error) {
					close(started)
					<-ctx.Done()
					switch mode {
					case "ready-error":
						s.ready <- errors.New("cancelled authentication")
					case "ready-closed":
						close(s.ready)
					case "done-error":
						s.done <- errors.New("cancelled connection")
					case "done-closed":
						close(s.done)
					case "ready-success":
						s.ready <- nil
					}
					return s, nil
				}}
				e := NewEngine(a)
				if err := e.Connect(profile(), "", true); err != nil {
					t.Fatal(err)
				}
				waitLifecycleSignal(t, started)
				if err := e.Disconnect(); err != nil {
					t.Fatal(err)
				}
				await(t, e, Disconnected)
				for _, entry := range e.Snapshot().Logs {
					if entry.Message == "Tunnel readiness verified." {
						t.Fatal("cancelled session advertised connected")
					}
				}
			}
		})
	}
}

func TestEngineCancellationDoesNotHideCleanupFailure(t *testing.T) {
	s := newLifecycleSession()
	s.stopErr = errors.New("unconfirmed cleanup")
	e := NewEngine(sessionAdapter{s})
	if err := e.Connect(profile(), "", true); err != nil {
		t.Fatal(err)
	}
	if err := e.Disconnect(); err != nil {
		t.Fatal(err)
	}
	await(t, e, CleanupFailed)
	if e.Connect(profile(), "", true) == nil {
		t.Fatal("cleanup failure did not block reconnect")
	}
}

func TestEngineDisconnectDuringLossCleanupIsIntentional(t *testing.T) {
	s := newLifecycleSession()
	s.release = make(chan struct{})
	var released sync.Once
	release := func() { released.Do(func() { close(s.release) }) }
	defer release()
	e := NewEngine(sessionAdapter{s})
	if err := e.Connect(profile(), "", true); err != nil {
		t.Fatal(err)
	}
	s.ready <- nil
	await(t, e, Connected)
	s.done <- errors.New("lost")
	waitLifecycleSignal(t, s.stopping)
	if err := e.Disconnect(); err != nil {
		t.Fatal(err)
	}
	release()
	await(t, e, Disconnected)
}

func TestEnginePartialStartShowsCleanupInProgress(t *testing.T) {
	s := newLifecycleSession()
	s.release = make(chan struct{})
	var released sync.Once
	release := func() { released.Do(func() { close(s.release) }) }
	defer release()
	e := NewEngine(partialSessionAdapter{s})
	if err := e.Connect(profile(), "", true); err != nil {
		t.Fatal(err)
	}
	waitLifecycleSignal(t, s.stopping)
	if e.Snapshot().State != Disconnecting {
		t.Fatalf("partial start cleanup not shown: %s", e.Snapshot().State)
	}
	release()
	await(t, e, Failed)
}

func TestEngineCancellationDuringStartFailure(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "no-session", true: "partial-session"}[partial], func(t *testing.T) {
			started := make(chan struct{})
			s := newLifecycleSession()
			a := lifecycleAdapter{start: func(ctx context.Context) (Session, error) {
				close(started)
				<-ctx.Done()
				if partial {
					return s, errors.New("start failed after acquiring session")
				}
				return nil, errors.New("start failed")
			}}
			e := NewEngine(a)
			if err := e.Connect(profile(), "", true); err != nil {
				t.Fatal(err)
			}
			waitLifecycleSignal(t, started)
			if err := e.Disconnect(); err != nil {
				t.Fatal(err)
			}
			await(t, e, Disconnected)
			if partial {
				waitLifecycleSignal(t, s.stopping)
			}
		})
	}
}

func TestEngineCancellationDuringPartialStartCleanup(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "cleanup-confirmed", true: "cleanup-failed"}[cleanupFails], func(t *testing.T) {
			s := newLifecycleSession()
			s.release = make(chan struct{})
			var released sync.Once
			release := func() { released.Do(func() { close(s.release) }) }
			defer release()
			if cleanupFails {
				s.stopErr = errors.New("cleanup unconfirmed")
			}
			e := NewEngine(partialSessionAdapter{s})
			if err := e.Connect(profile(), "", true); err != nil {
				t.Fatal(err)
			}
			waitLifecycleSignal(t, s.stopping)
			if err := e.Disconnect(); err != nil {
				t.Fatal(err)
			}
			release()
			want := Disconnected
			if cleanupFails {
				want = CleanupFailed
			}
			await(t, e, want)
		})
	}
}

func TestSnapshotAttemptIdentityChangesOnlyOnAdmission(t *testing.T) {
	s := newLifecycleSession()
	e := NewEngine(sessionAdapter{s})
	if e.Snapshot().AttemptID != 0 {
		t.Fatal("idle engine has an attempt identity")
	}
	if err := e.Connect(profile(), "", false); err == nil || e.Snapshot().AttemptID != 0 {
		t.Fatal("rejected authorization advanced attempt identity")
	}
	if err := e.Connect(profile(), "", true); err != nil {
		t.Fatal(err)
	}
	first := e.Snapshot().AttemptID
	if first == 0 {
		t.Fatal("admitted attempt has no identity")
	}
	if err := e.Connect(profile(), "", true); err == nil || e.Snapshot().AttemptID != first {
		t.Fatal("duplicate connect changed attempt identity")
	}
	s.ready <- nil
	await(t, e, Connected)
	if e.Snapshot().AttemptID != first {
		t.Fatal("readiness changed attempt identity")
	}
	s.done <- NewConnectionError(FailureTransport)
	await(t, e, Failed)
	if e.Snapshot().AttemptID != first {
		t.Fatal("terminal result lost attempt identity")
	}
	next := newLifecycleSession()
	if err := e.ReplaceAdapter(sessionAdapter{next}); err != nil {
		t.Fatal(err)
	}
	if err := e.Connect(profile(), "", true); err != nil {
		t.Fatal(err)
	}
	if e.Snapshot().AttemptID == first {
		t.Fatal("fresh admitted attempt retained old identity")
	}
	if err := e.Disconnect(); err != nil {
		t.Fatal(err)
	}
	await(t, e, Disconnected)
	if e.Snapshot().AttemptID == first || e.Snapshot().AttemptID == 0 {
		t.Fatal("cancellation lost the new attempt identity")
	}
}
