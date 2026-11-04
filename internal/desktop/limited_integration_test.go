package desktop

import (
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
	"testing"
	"time"
)

func TestLimitedIntegrationClonesSystemServiceAndClearsOnProtocolChange(t *testing.T) {
	a := macUIFixture(t)
	p := core.Profile{ID: "mac", Protocol: core.ProtocolMacOSSystemL2TP, SystemService: &core.SystemServiceOptions{ServiceID: "service", Targets: []string{"10.0.0.1"}}}
	a.Config.Profiles = []core.Profile{p}
	copy := a.copyConfig()
	copy.Profiles[0].SystemService.Targets[0] = "10.0.0.2"
	a.startEdit(&a.Config.Profiles[0])
	a.Draft.SystemService.Targets[0] = "10.0.0.3"
	if a.Config.Profiles[0].SystemService.Targets[0] != "10.0.0.1" {
		t.Fatal("profile clone aliases targets")
	}
	a.setDraftProtocol(core.WindowsBorrowedProtocol)
	if a.Draft.SystemService != nil || a.Draft.WindowsBorrowed == nil {
		t.Fatal("protocol switch retained another platform selection")
	}
}
func TestLimitedIntegrationWindowsIdentitySurvivesSelectedProfileChange(t *testing.T) {
	a := macUIFixture(t)
	a.WindowsBorrowedEnabled = true
	a.Config.Settings.Language = "en"
	adapter := &fakeWindowsAdapter{started: make(chan core.SessionAuthorization, 1), s: &switchSession{ready: make(chan error, 1), done: make(chan error, 1)}}
	a.Adapter = adapter
	a.Engine = core.NewEngine(adapter)
	a.Capability = adapter.Capability()
	p := desktopWindowsProfile()
	a.Config.Profiles = []core.Profile{p, {ID: "other", Name: "Other selected", Protocol: "anyconnect", Gateway: "https://other.test"}}
	a.Config.SelectedID = p.ID
	a.openConnectForm()
	a.Password = "synthetic"
	a.Authorized = true
	a.WindowsPersistenceConsent = true
	a.WindowsSharedConsent = true
	a.submitConnection()
	<-adapter.started
	adapter.s.ready <- nil
	awaitState(t, a, core.Connected)
	a.beginSwitch("other")
	if a.SwitchPending {
		t.Fatal("limited attempt entered ordinary switch path")
	}
	a.Config.SelectedID = "other"
	snapshot := a.Engine.Snapshot()
	if !a.windowsOwnsAttempt(snapshot) {
		t.Fatal("lost original limited attempt identity")
	}
	v := ui.NewTester(a.connectionStatus, 500, 900)
	if !v.HasText(p.Name) || v.HasText("Other selected") {
		t.Fatal("sidebar adopted selected profile instead of active Windows attempt")
	}
	a.Config.Settings.ReauthOnLoss = true
	a.pollReauthentication(time.Now())
	if a.observedConnected || a.reauthVisible {
		t.Fatal("limited attempt entered ordinary recovery")
	}
	_ = a.Engine.Disconnect()
	awaitState(t, a, core.Disconnected)
	if a.windowsOwnsAttempt(core.Snapshot{AttemptID: snapshot.AttemptID + 1}) {
		t.Fatal("old identity matched newer attempt")
	}
}
