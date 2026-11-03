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
