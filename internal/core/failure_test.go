package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestConnectionFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want FailureKind
	}{
		{"nil", nil, FailureStart},
		{"raw", errors.New("password=secret authentication timeout certificate"), FailureStart},
		{"typed", NewConnectionError(FailureAuthentication), FailureAuthentication},
		{"wrapped", fmt.Errorf("secret: %w", NewConnectionError(FailureTrust)), FailureTrust},
		{"cleanup", errors.Join(NewConnectionError(FailureTransport), &CleanupError{}), FailureCleanup},
		{"typed-cleanup", errors.Join(NewConnectionError(FailureTransport), NewConnectionError(FailureCleanup)), FailureCleanup},
		{"invalid", NewConnectionError(255), FailureUnknown},
		{"zero", &ConnectionError{}, FailureUnknown},
		{"nil-typed", (*ConnectionError)(nil), FailureUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyFailure(tc.err, FailureStart); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestEngineFailureKindsAndRedaction(t *testing.T) {
	for _, stage := range []string{"start", "ready", "lost"} {
		for _, typed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/typed=%v", stage, typed), func(t *testing.T) {
				s := newLifecycleSession()
				err := errors.New("password=secret-token")
				want := map[string]FailureKind{"start": FailureStart, "ready": FailureReadiness, "lost": FailureConnectionLost}[stage]
				if typed {
					err = fmt.Errorf("secret-token: %w", NewConnectionError(FailureAuthentication))
					want = FailureAuthentication
				}
				e := NewEngine(lifecycleAdapter{start: func(context.Context) (Session, error) {
					if stage == "start" {
						return nil, err
					}
					return s, nil
				}})
				if err := e.Connect(profile(), "secret-token", true); err != nil {
					t.Fatal(err)
				}
				switch stage {
				case "ready":
					s.ready <- err
				case "lost":
					s.ready <- nil
					await(t, e, Connected)
					s.done <- err
				}
				await(t, e, Failed)
				if got := e.Snapshot().Failure; got != want {
					t.Fatalf("got %v want %v", got, want)
				}
				data, err := json.Marshal(e.Snapshot())
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), "secret-token") {
					t.Fatal("secret leaked")
				}
				// A fresh authorized attempt clears old failures. No attempt is automatic.
				next := newLifecycleSession()
				if err := e.ReplaceAdapter(sessionAdapter{next}); err != nil {
					t.Fatal(err)
				}
				if err := e.Connect(profile(), "", true); err != nil {
					t.Fatal(err)
				}
				if e.Snapshot().Failure != FailureNone {
					t.Fatal("stale failure")
				}
				if err := e.Disconnect(); err != nil {
					t.Fatal(err)
				}
				await(t, e, Disconnected)
				if e.Snapshot().Failure != FailureNone {
					t.Fatal("cancellation reported as failure")
				}
			})
		}
	}
}

func TestEngineFailureCleanupOverridesCancellation(t *testing.T) {
	for _, typed := range []bool{false, true} {
		s := newLifecycleSession()
		if typed {
			s.stopErr = NewConnectionError(FailureCleanup)
		} else {
			s.stopErr = errors.New("secret-token")
		}
		e := NewEngine(sessionAdapter{s})
		if err := e.Connect(profile(), "", true); err != nil {
			t.Fatal(err)
		}
		if err := e.Disconnect(); err != nil {
			t.Fatal(err)
		}
		await(t, e, CleanupFailed)
		if e.Snapshot().Failure != FailureCleanup {
			t.Fatal("cleanup failure lost")
		}
		if e.Connect(profile(), "", true) == nil {
			t.Fatal("cleanup quarantine bypassed")
		}
	}
}

type unavailableFailureAdapter struct{ lifecycleAdapter }

func (unavailableFailureAdapter) Capability() Capability {
	return Capability{Message: "secret-token"}
}

func TestEngineUnavailableFailureRedactsCapability(t *testing.T) {
	e := NewEngine(unavailableFailureAdapter{})
	err := e.Connect(profile(), "", true)
	if err == nil || classifyFailure(err, FailureUnknown) != FailureBackendUnavailable {
		t.Fatal("missing typed capability failure")
	}
	if e.Snapshot().Failure != FailureBackendUnavailable {
		t.Fatal("missing snapshot classification")
	}
	data, marshalErr := json.Marshal(e.Snapshot())
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(data)+err.Error(), "secret-token") {
		t.Fatal("capability detail leaked")
	}
}

func TestEngineTypedCleanupQuarantine(t *testing.T) {
	for _, stage := range []string{"start", "ready", "done"} {
		t.Run(stage, func(t *testing.T) {
			s := newLifecycleSession()
			failure := errors.Join(NewConnectionError(FailureTransport), NewConnectionError(FailureCleanup))
			e := NewEngine(lifecycleAdapter{start: func(context.Context) (Session, error) {
				if stage == "start" {
					return nil, failure
				}
				return s, nil
			}})
			if err := e.Connect(profile(), "", true); err != nil {
				t.Fatal(err)
			}
			switch stage {
			case "ready":
				s.ready <- failure
			case "done":
				s.done <- failure
			}
			await(t, e, CleanupFailed)
			if e.Snapshot().Failure != FailureCleanup {
				t.Fatal("typed cleanup lost")
			}
			if e.Connect(profile(), "", true) == nil {
				t.Fatal("cleanup quarantine bypassed")
			}
		})
	}
}

func TestEngineCancelledStartClearsFailure(t *testing.T) {
	started := make(chan struct{})
	e := NewEngine(lifecycleAdapter{start: func(ctx context.Context) (Session, error) {
		close(started)
		<-ctx.Done()
		return nil, NewConnectionError(FailureAuthentication)
	}})
	if err := e.Connect(profile(), "", true); err != nil {
		t.Fatal(err)
	}
	waitLifecycleSignal(t, started)
	if err := e.Disconnect(); err != nil {
		t.Fatal(err)
	}
	await(t, e, Disconnected)
	if e.Snapshot().Failure != FailureNone {
		t.Fatal("cancelled start recorded a failure")
	}
}

func TestEngineCancellationCannotHideQueuedCleanupFailure(t *testing.T) {
	for _, channel := range []string{"ready", "done"} {
		t.Run(channel, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				s := newLifecycleSession()
				started := make(chan struct{})
				e := NewEngine(lifecycleAdapter{start: func(ctx context.Context) (Session, error) {
					close(started)
					<-ctx.Done()
					failure := NewConnectionError(FailureCleanup)
					if channel == "ready" {
						s.ready <- failure
					} else {
						s.done <- failure
					}
					return s, nil
				}})
				if err := e.Connect(profile(), "", true); err != nil {
					t.Fatal(err)
				}
				waitLifecycleSignal(t, started)
				if err := e.Disconnect(); err != nil {
					t.Fatal(err)
				}
				await(t, e, CleanupFailed)
				if e.Snapshot().Failure != FailureCleanup {
					t.Fatal("cancellation hid queued cleanup failure")
				}
				if e.Connect(profile(), "", true) == nil {
					t.Fatal("cleanup quarantine bypassed")
				}
			}
		})
	}
}
