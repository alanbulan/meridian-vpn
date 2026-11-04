package desktop

import (
	"context"
	"errors"
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
	"testing"
)

type windowsSelectionAdapter struct {
	*fakeWindowsAdapter
	profiles chan core.Profile
}

func (a *windowsSelectionAdapter) StartWithAuthorization(ctx context.Context, p core.Profile, c core.Credentials, auth core.SessionAuthorization) (core.Session, error) {
	a.profiles <- p
	return a.fakeWindowsAdapter.StartWithAuthorization(ctx, p, c, auth)
}
func TestWindowsTerminalCleanupShowsAndConnectsSelectedProfile(t *testing.T) {
	for _, terminal := range []string{core.Disconnected, core.Failed} {
		t.Run(terminal, func(t *testing.T) {
			a := macUIFixture(t)
			a.WindowsBorrowedEnabled = true
			a.Config.Settings.Language = "en"
			adapter := &windowsSelectionAdapter{fakeWindowsAdapter: &fakeWindowsAdapter{started: make(chan core.SessionAuthorization, 2), s: &switchSession{ready: make(chan error, 1), done: make(chan error, 1)}}, profiles: make(chan core.Profile, 2)}
			a.Adapter = adapter
			a.Engine = core.NewEngine(adapter)
			a.Capability = adapter.Capability()
			first, second := desktopWindowsProfile(), desktopWindowsProfile()
			second.ID = "second"
			second.Name = "Second VPN"
			second.Gateway = "second.example.test"
			second.WindowsBorrowed.EntryName = "Second entry"
			a.Config.Profiles = []core.Profile{first, second}
			a.Config.SelectedID = first.ID
			submit := func() {
				a.openConnectForm()
				a.Password = "synthetic"
				a.Authorized = true
				a.WindowsPersistenceConsent = true
				a.WindowsSharedConsent = true
				a.submitConnection()
				<-adapter.started
			}
			submit()
			<-adapter.profiles
			adapter.s.ready <- nil
			awaitState(t, a, core.Connected)
			if terminal == core.Disconnected {
				_ = a.Engine.Disconnect()
			} else {
				adapter.s.done <- errors.New("synthetic connection loss")
			}
			awaitState(t, a, terminal)
			a.Config.SelectedID = second.ID
			if terminal == core.Disconnected && a.windowsOwnsAttempt(a.Engine.Snapshot()) {
				t.Fatal("clean disconnected attempt still overrides selection")
			}
			view := ui.NewTester(a.connectionStatus, 500, 900)
			if !view.HasText(second.Name) || view.HasText(first.Name) {
				t.Fatal("sidebar does not show selected next VPN")
			}
			adapter.s = &switchSession{ready: make(chan error, 1), done: make(chan error, 1)}
			submit()
			got := <-adapter.profiles
			if got.ID != second.ID || got.Gateway != second.Gateway || got.WindowsBorrowed.EntryName != second.WindowsBorrowed.EntryName {
				t.Fatal("connect did not use displayed selection")
			}
			_ = a.Engine.Disconnect()
			awaitState(t, a, core.Disconnected)
		})
	}
}
func TestWindowsAttemptIdentityRetainedOnlyForRelevantStates(t *testing.T) {
	a := macUIFixture(t)
	p := desktopWindowsProfile()
	a.windowsActiveProfile = &p
	a.windowsActiveAttemptID = 7
	for _, state := range []string{core.Connecting, core.Connected, core.Disconnecting, core.CleanupFailed, core.Failed} {
		if !a.windowsOwnsAttempt(core.Snapshot{AttemptID: 7, State: state}) {
			t.Fatalf("lost %s attempt identity", state)
		}
	}
	for _, state := range []string{core.Disconnected, "", "unknown"} {
		if a.windowsOwnsAttempt(core.Snapshot{AttemptID: 7, State: state}) {
			t.Fatalf("stale %s attempt identity", state)
		}
	}
	if a.windowsOwnsAttempt(core.Snapshot{AttemptID: 8, State: core.CleanupFailed}) {
		t.Fatal("old identity adopted another attempt")
	}
}
func TestWindowsEditorLabelsRequiredUsernameOnlyForWindows(t *testing.T) {
	a := macUIFixture(t)
	a.Config.Settings.Language = "en"
	a.WindowsBorrowedEnabled = true
	p := desktopWindowsProfile()
	p.Username = ""
	a.startEdit(&p)
	view := ui.NewTester(a.editor, 1100, 1400)
	if !view.HasText("Username (required)") {
		t.Fatal("required Windows username not disclosed")
	}
	if core.ValidateProfile(a.Draft) == nil {
		t.Fatal("empty Windows username accepted")
	}
	a.WindowsBorrowedEnabled = false
	a.startEdit(&core.Profile{ID: "ordinary", Name: "Ordinary", Protocol: "anyconnect", Gateway: "https://example.test"})
	view.Frame()
	if view.HasText("Username (required)") {
		t.Fatal("changed ordinary username semantics")
	}
}
