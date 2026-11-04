package core

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type combinedScopeAdapter struct {
	scope   string
	session Session
	starts  int
}

func (a *combinedScopeAdapter) Capability() Capability    { return Capability{Available: true} }
func (a *combinedScopeAdapter) VerificationScope() string { return a.scope }
func (a *combinedScopeAdapter) Start(context.Context, Profile, []byte) (Session, error) {
	a.starts++
	return a.session, nil
}
func (a *combinedScopeAdapter) StartWithAuthorization(ctx context.Context, p Profile, c Credentials, _ SessionAuthorization) (Session, error) {
	return a.Start(ctx, p, c.Password)
}

type combinedScopeSession struct {
	*retryableTestSession
	scope string
}

func (s *combinedScopeSession) VerificationScope() string { return s.scope }
func connectCombined(e *Engine, p Profile) error {
	c := Credentials{}
	if p.Protocol == WindowsBorrowedProtocol {
		c.Password = []byte("synthetic")
	}
	return e.ConnectWithAuthorization(p, c, SessionAuthorization{true, true, true})
}
func TestLimitedIntegrationRejectsCrossScopeAdaptersAndSessions(t *testing.T) {
	for _, p := range []Profile{windowsBorrowedProfile(), systemServiceProfile(), profile()} {
		expected := profileVerificationScope(p)
		for _, scope := range []string{"", WindowsBorrowedObservedInterface, SystemServiceTargetRoutes, "unknown"} {
			if scope == expected {
				continue
			}
			a := &combinedScopeAdapter{scope: scope}
			if connectCombined(NewEngine(a), p) == nil || a.starts != 0 {
				t.Fatalf("scope %q admitted protocol %q", scope, p.Protocol)
			}
			base := newLifecycleSession()
			base.ready <- nil
			s := &combinedScopeSession{retryableTestSession: &retryableTestSession{lifecycleSession: base}, scope: scope}
			e := NewEngine(&combinedScopeAdapter{scope: expected, session: s})
			if err := connectCombined(e, p); err != nil {
				t.Fatal(err)
			}
			await(t, e, Failed)
			if got := e.Snapshot(); got.Failure != FailureReadiness || got.VerificationScope != "" {
				t.Fatalf("wrong scope became ready: %+v", got)
			}
		}
	}
	if _, err := OpenConnectArgs(windowsBorrowedProfile()); err == nil {
		t.Fatal("Windows profile reached OpenConnect")
	}
}
func TestLimitedIntegrationRetainsScopeAndOwnerAcrossCleanupRetry(t *testing.T) {
	for _, p := range []Profile{windowsBorrowedProfile(), systemServiceProfile()} {
		t.Run(p.Protocol, func(t *testing.T) {
			scope := profileVerificationScope(p)
			base := newLifecycleSession()
			base.ready <- nil
			base.stopErr = &CleanupError{}
			s := &combinedScopeSession{retryableTestSession: &retryableTestSession{lifecycleSession: base}, scope: scope}
			e := NewEngine(&combinedScopeAdapter{scope: scope, session: s})
			if err := connectCombined(e, p); err != nil {
				t.Fatal(err)
			}
			await(t, e, Connected)
			attempt := e.Snapshot().AttemptID
			if e.Snapshot().VerificationScope != scope {
				t.Fatal("scope not exposed on verified session")
			}
			_ = e.Disconnect()
			await(t, e, CleanupFailed)
			e.mu.Lock()
			done := e.finished
			e.mu.Unlock()
			waitLifecycleSignal(t, done)
			s.retry = func(context.Context) error { return errors.New("private native detail") }
			err := e.RetryCleanup(context.Background())
			var cleanup *CleanupError
			if !errors.As(err, &cleanup) || cleanup.scope != scope || strings.Contains(err.Error(), "private") {
				t.Fatal("retry lost scoped failure", err)
			}
			if got := e.Snapshot(); got.State != CleanupFailed || got.AttemptID != attempt || got.VerificationScope != "" {
				t.Fatalf("retry changed identity/readiness: %+v", got)
			}
			e.mu.Lock()
			owned := e.session == s && e.attemptScope == scope
			e.mu.Unlock()
			if !owned {
				t.Fatal("retry lost owner")
			}
			s.retry = nil
			if err := e.RetryCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := e.Snapshot(); got.State != Disconnected || got.Message != disconnectedMessage(scope) || got.VerificationScope != "" {
				t.Fatalf("incorrect scoped cleanup completion: %+v", got)
			}
		})
	}
}

func TestLimitedIntegrationRejectsMixedProfileSelections(t *testing.T) {
	w := windowsBorrowedProfile()
	m := systemServiceProfile()
	w.SystemService = m.SystemService
	if ValidateProfile(w) == nil {
		t.Fatal("Windows accepted macOS selection")
	}
	m.WindowsBorrowed = w.WindowsBorrowed
	if ValidateProfile(m) == nil {
		t.Fatal("macOS accepted Windows selection")
	}
}
