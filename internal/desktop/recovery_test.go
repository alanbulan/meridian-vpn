package desktop

import (
	"errors"
	"mygo-vpn/internal/core"
	"path/filepath"
	"testing"
	"time"
)

func TestLossReminderRequiresConnectedAndConfirmedCleanup(t *testing.T) {
	for _, mode := range []string{"unexpected", "manual", "cleanup-failed", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			s := &switchSession{ready: make(chan error, 1), done: make(chan error, 1)}
			if mode == "cleanup-failed" {
				s.stopError = errors.New("unknown cleanup")
			}
			a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), switchAdapter{s})
			p := core.Profile{ID: "a", Name: "Office", Gateway: "https://example.com", Protocol: "anyconnect"}
			a.Config.Profiles = []core.Profile{p}
			a.Config.SelectedID = p.ID
			a.Config.Settings.ReauthOnLoss = mode != "disabled"
			if err := a.Engine.Connect(p, "synthetic", true); err != nil {
				t.Fatal(err)
			}
			s.ready <- nil
			awaitState(t, a, core.Connected)
			now := time.Now()
			a.pollReauthentication(now)
			if mode == "manual" {
				if err := a.Engine.Disconnect(); err != nil {
					t.Fatal(err)
				}
				awaitState(t, a, core.Disconnected)
			} else {
				s.done <- errors.New("tunnel lost")
				want := core.Failed
				if mode == "cleanup-failed" {
					want = core.CleanupFailed
				}
				awaitState(t, a, want)
			}
			a.pollReauthentication(now)
			if a.reauthVisible {
				t.Fatal("reminder bypassed bounded delay")
			}
			a.pollReauthentication(now.Add(6 * time.Second))
			if a.reauthVisible != (mode == "unexpected") {
				t.Fatalf("unexpected reminder for %s", mode)
			}
			if a.Password != "" || a.KeyPassword != "" || a.Authorized || a.ConnectPanel {
				t.Fatal("reminder replayed authentication")
			}
			a.clearReauthentication()
			a.pollReauthentication(now.Add(time.Minute))
			if a.reauthVisible {
				t.Fatal("dismissed reminder repeated")
			}
		})
	}
}
func TestRecoveryPreferencePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	a := NewWithAdapter(path, unavailableTestAdapter{})
	cfg := a.copyConfig()
	cfg.Settings.ReauthOnLoss = true
	if !a.commit(cfg) {
		t.Fatal(a.Notice)
	}
	b := NewWithAdapter(path, unavailableTestAdapter{})
	if !b.Config.Settings.ReauthOnLoss {
		t.Fatal("preference lost")
	}
	b.pollReauthentication(time.Now().Add(time.Hour))
	if b.reauthVisible {
		t.Fatal("never-connected app prompted")
	}
}

func TestRecoveryReminderRespectsFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kind   core.FailureKind
		remind bool
	}{
		{"connection-lost", core.FailureConnectionLost, true},
		{"transport", core.FailureTransport, true},
		{"authentication", core.FailureAuthentication, false},
		{"trust", core.FailureTrust, false},
		{"configuration", core.FailureConfiguration, false},
		{"unknown", core.FailureUnknown, false},
		{"backend", core.FailureBackendUnavailable, false},
		{"start", core.FailureStart, false},
		{"readiness", core.FailureReadiness, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &switchSession{ready: make(chan error, 1), done: make(chan error, 1)}
			a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), switchAdapter{s})
			p := core.Profile{ID: "a", Name: "Office", Gateway: "https://example.com", Protocol: "anyconnect"}
			a.Config.Profiles = []core.Profile{p}
			a.Config.SelectedID = p.ID
			a.Config.Settings.ReauthOnLoss = true
			if err := a.Engine.Connect(p, "synthetic", true); err != nil {
				t.Fatal(err)
			}
			s.ready <- nil
			awaitState(t, a, core.Connected)
			now := time.Now()
			a.pollReauthentication(now)
			s.done <- errors.Join(core.NewConnectionError(core.FailureTransport), core.NewConnectionError(tc.kind))
			awaitState(t, a, core.Failed)
			a.pollReauthentication(now)
			a.pollReauthentication(now.Add(6 * time.Second))
			if a.reauthVisible != tc.remind {
				t.Fatal("recovery reminder ignored classified failure")
			}
			if !a.canConnect(&p) {
				t.Fatal("classification removed the explicit manual connection action")
			}
			if a.ConnectPanel || a.Authorized || a.ProxyConsent || a.Password != "" || a.KeyPassword != "" || a.IPsecPSK != "" {
				t.Fatal("recovery reminder acquired credentials or authorized a new connection")
			}
			a.openConnectForm()
			if !a.ConnectPanel || a.Authorized || a.Password != "" {
				t.Fatal("manual connection did not require fresh authentication and authorization")
			}
		})
	}
}

func TestClassifiedFailuresHaveLocalizedMessages(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), unavailableTestAdapter{})
	a.Config.Settings.Language = "zh"
	for kind := core.FailureUnknown; kind <= core.FailureTransport; kind++ {
		message := core.NewConnectionError(kind).Error()
		if a.tr(message) == message {
			t.Fatalf("missing Chinese failure message for kind %v", kind)
		}
	}
}

// The UI timer need not observe every engine transition. A fresh attempt may
// start and fail between ticks, so profile identity alone is not enough.
func TestRecoveryReminderCannotCrossAttempts(t *testing.T) {
	for _, mode := range []string{"missed-loss", "pending-reminder", "visible-reminder"} {
		t.Run(mode, func(t *testing.T) {
			s := &switchSession{ready: make(chan error, 1), done: make(chan error, 1)}
			a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), switchAdapter{s})
			p := core.Profile{ID: "a", Name: "Office", Gateway: "https://example.com", Protocol: "anyconnect"}
			a.Config.Profiles = []core.Profile{p}
			a.Config.SelectedID = p.ID
			a.Config.Settings.ReauthOnLoss = true
			if err := a.Engine.Connect(p, "synthetic", true); err != nil {
				t.Fatal(err)
			}
			s.ready <- nil
			awaitState(t, a, core.Connected)
			now := time.Now()
			a.pollReauthentication(now)
			firstAttempt := a.Engine.Snapshot().AttemptID
			s.done <- core.NewConnectionError(core.FailureTransport)
			awaitState(t, a, core.Failed)
			if mode != "missed-loss" {
				a.pollReauthentication(now)
			}
			if mode == "visible-reminder" {
				a.pollReauthentication(now.Add(6 * time.Second))
				if !a.reauthVisible {
					t.Fatal("test did not establish a visible reminder")
				}
			}
			// Reuse only the in-memory test session after the prior Stop result
			// was drained by the engine. No real authentication/networking runs.
			if err := a.Engine.Connect(p, "fresh-synthetic", true); err != nil {
				t.Fatal(err)
			}
			if a.Engine.Snapshot().AttemptID == firstAttempt {
				t.Fatal("new attempt reused the previous identity")
			}
			s.ready <- core.NewConnectionError(core.FailureTransport)
			awaitState(t, a, core.Failed)
			if mode == "visible-reminder" {
				// Render can happen before the next timer poll. A nil context is
				// deliberate: stale notices must return before constructing UI.
				if !a.reauthVisible || a.reauthAttemptID == a.Engine.Snapshot().AttemptID {
					t.Fatal("test did not retain a stale visible attempt")
				}
				a.reauthenticationNotice(nil)
				if a.reauthVisible || a.observedConnected || !a.reauthAt.IsZero() {
					t.Fatal("render retained the previous attempt's notice")
				}
			}
			a.pollReauthentication(now.Add(6 * time.Second))
			a.pollReauthentication(now.Add(time.Minute))
			if a.reauthVisible || a.observedConnected || !a.reauthAt.IsZero() {
				t.Fatal("old connected evidence leaked into an unestablished attempt")
			}
			// A later established attempt must still get its own reminder.
			if err := a.Engine.Connect(p, "another-fresh-synthetic", true); err != nil {
				t.Fatal(err)
			}
			s.ready <- nil
			awaitState(t, a, core.Connected)
			a.pollReauthentication(now.Add(2 * time.Minute))
			s.done <- core.NewConnectionError(core.FailureTransport)
			awaitState(t, a, core.Failed)
			a.pollReauthentication(now.Add(2 * time.Minute))
			a.pollReauthentication(now.Add(2*time.Minute + 6*time.Second))
			if !a.reauthVisible {
				t.Fatal("fresh established session lost its reminder")
			}
		})
	}
}

func TestRecoveryReminderInvalidatesChangedProfile(t *testing.T) {
	for _, mode := range []string{"pending", "visible-poll", "visible-render"} {
		t.Run(mode, func(t *testing.T) {
			s := &switchSession{ready: make(chan error, 1), done: make(chan error, 1)}
			a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), switchAdapter{s})
			p := core.Profile{ID: "a", Name: "Office", Gateway: "https://example.com", Protocol: "anyconnect"}
			other := core.Profile{ID: "b", Name: "Other", Gateway: "https://other.example.com", Protocol: "anyconnect"}
			a.Config.Profiles = []core.Profile{p, other}
			a.Config.SelectedID = p.ID
			a.Config.Settings.ReauthOnLoss = true
			if err := a.Engine.Connect(p, "synthetic", true); err != nil {
				t.Fatal(err)
			}
			s.ready <- nil
			awaitState(t, a, core.Connected)
			now := time.Now()
			a.pollReauthentication(now)
			s.done <- core.NewConnectionError(core.FailureTransport)
			awaitState(t, a, core.Failed)
			a.pollReauthentication(now)
			if a.reauthAt.IsZero() {
				t.Fatal("test did not schedule a reminder")
			}
			if mode != "pending" {
				a.pollReauthentication(now.Add(6 * time.Second))
				if !a.reauthVisible {
					t.Fatal("test did not show a reminder")
				}
			}
			a.Config.SelectedID = other.ID
			if mode == "visible-render" {
				// The profile guard must also work before the next timer tick.
				a.reauthenticationNotice(nil)
			} else {
				a.pollReauthentication(now.Add(7 * time.Second))
			}
			if a.reauthVisible || a.observedConnected || !a.reauthAt.IsZero() || a.reauthProfileID != "" || a.reauthAttemptID != 0 {
				t.Fatal("profile change retained reminder evidence")
			}
			// Returning to the old profile must not revive a discarded reminder.
			a.Config.SelectedID = p.ID
			a.pollReauthentication(now.Add(time.Minute))
			if a.reauthVisible || !a.reauthAt.IsZero() || a.ConnectPanel || a.Authorized {
				t.Fatal("profile round-trip revived a reminder or authentication")
			}
		})
	}
}
