package core

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type retryableTestSession struct {
	*lifecycleSession
	retries atomic.Int32
	retry   func(context.Context) error
}

func (s *retryableTestSession) RetryCleanup(ctx context.Context) error {
	s.retries.Add(1)
	if s.retry != nil {
		return s.retry(ctx)
	}
	return nil
}
func failedCleanupEngine(t *testing.T, s Session) *Engine {
	t.Helper()
	e := NewEngine(sessionAdapter{s})
	if err := e.Connect(profile(), "", true); err != nil {
		t.Fatal(err)
	}
	if err := e.Disconnect(); err != nil {
		t.Fatal(err)
	}
	await(t, e, CleanupFailed)
	e.mu.Lock()
	finished := e.finished
	e.mu.Unlock()
	waitLifecycleSignal(t, finished)
	return e
}
func TestEngineRetainsAndRetriesCleanupOnlyWhenOptedIn(t *testing.T) {
	base := newLifecycleSession()
	base.stopErr = &CleanupError{}
	s := &retryableTestSession{lifecycleSession: base}
	e := failedCleanupEngine(t, s)
	e.mu.Lock()
	retained := e.session == s
	e.mu.Unlock()
	if !retained {
		t.Fatal("cleanup owner discarded")
	}
	s.retry = func(context.Context) error { return errors.New("private failure detail") }
	if err := e.RetryCleanup(context.Background()); err == nil {
		t.Fatal("failed retry accepted")
	}
	if e.Snapshot().State != CleanupFailed {
		t.Fatal("failed retry unlocked session")
	}
	s.retry = nil
	if err := e.RetryCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.Snapshot().State != Disconnected || s.retries.Load() != 2 {
		t.Fatal("successful retry not completed")
	}
	e.mu.Lock()
	released := e.session == nil
	e.mu.Unlock()
	if !released {
		t.Fatal("cleaned session retained")
	}
	legacy := newLifecycleSession()
	legacy.stopErr = &CleanupError{}
	old := failedCleanupEngine(t, legacy)
	if old.RetryCleanup(context.Background()) == nil {
		t.Fatal("legacy Stop automatically retried")
	}
}
func TestEngineCleanupRetrySerializesAndBlocksQuit(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	base := newLifecycleSession()
	base.stopErr = &CleanupError{}
	s := &retryableTestSession{lifecycleSession: base, retry: func(context.Context) error { close(entered); <-release; return nil }}
	e := failedCleanupEngine(t, s)
	done := make(chan error, 1)
	go func() { done <- e.RetryCleanup(context.Background()) }()
	waitLifecycleSignal(t, entered)
	if e.RetryCleanup(context.Background()) == nil {
		t.Fatal("concurrent retry entered")
	}
	if e.Connect(profile(), "", true) == nil {
		t.Fatal("connect during retry accepted")
	}
	if e.ReplaceAdapter(sessionAdapter{}) == nil {
		t.Fatal("adapter replaced during retry")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e.Shutdown(ctx) == nil {
		t.Fatal("quit succeeded during cleanup retry")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := e.Shutdown(ctx); err != nil {
		t.Fatal("quit failed after verified cleanup", err)
	}
	if s.retries.Load() != 1 {
		t.Fatal("duplicate native retry")
	}
}
func TestEngineCleanupRetryCancellationAndPanicRemainOwned(t *testing.T) {
	base := newLifecycleSession()
	base.stopErr = &CleanupError{}
	s := &retryableTestSession{lifecycleSession: base}
	e := failedCleanupEngine(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e.RetryCleanup(ctx) == nil || s.retries.Load() != 0 {
		t.Fatal("canceled retry invoked backend")
	}
	s.retry = func(context.Context) error { panic("private panic") }
	if e.RetryCleanup(context.Background()) == nil || e.Snapshot().State != CleanupFailed {
		t.Fatal("panic lost ownership")
	}
	s.retry = nil
	if err := e.RetryCleanup(context.Background()); err != nil {
		t.Fatal("panic left retry stuck", err)
	}
}

type partialStartAdapter struct{ s Session }

func (a partialStartAdapter) Capability() Capability { return Capability{Available: true} }
func (a partialStartAdapter) Start(context.Context, Profile, []byte) (Session, error) {
	return a.s, errors.New("partial start")
}
func TestEngineRetainsPartialStartCleanupOwner(t *testing.T) {
	base := newLifecycleSession()
	base.stopErr = &CleanupError{}
	s := &retryableTestSession{lifecycleSession: base}
	e := NewEngine(partialStartAdapter{s})
	if err := e.Connect(profile(), "", true); err != nil {
		t.Fatal(err)
	}
	await(t, e, CleanupFailed)
	e.mu.Lock()
	finished := e.finished
	e.mu.Unlock()
	waitLifecycleSignal(t, finished)
	if err := e.RetryCleanup(context.Background()); err != nil {
		t.Fatal("partial-start owner missing", err)
	}
}
