package desktop

import (
	"context"
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
	"path/filepath"
	"testing"
)

type fakeWindowsAdapter struct {
	started chan core.SessionAuthorization
	s       *switchSession
}

func (a *fakeWindowsAdapter) VerificationScope() string   { return core.WindowsBorrowedObservedInterface }
func (a *fakeWindowsAdapter) Capability() core.Capability { return core.Capability{Available: true} }
func (a *fakeWindowsAdapter) SupportsProtocol(p string) bool {
	return p == core.WindowsBorrowedProtocol
}
func (a *fakeWindowsAdapter) Start(context.Context, core.Profile, []byte) (core.Session, error) {
	panic("legacy Windows start")
}
func (a *fakeWindowsAdapter) StartWithAuthorization(_ context.Context, _ core.Profile, _ core.Credentials, c core.SessionAuthorization) (core.Session, error) {
	a.started <- c
	return windowsTestSession{a.s}, nil
}
func desktopWindowsProfile() core.Profile {
	return core.Profile{ID: "win", Name: "Existing VPN", Protocol: core.WindowsBorrowedProtocol, Gateway: "vpn.example.test", Username: "user", WindowsBorrowed: &core.WindowsBorrowedOptions{PhonebookPath: `C:\Users\Test\vpn.pbk`, EntryName: "VPN"}}
}
func TestWindowsUIRequiresFreshConsentAndResets(t *testing.T) {
	adapter := &fakeWindowsAdapter{started: make(chan core.SessionAuthorization, 1), s: &switchSession{ready: make(chan error, 1), done: make(chan error, 1)}}
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), adapter)
	a.WindowsBorrowedEnabled = true
	a.Config.Settings.Language = "en"
	a.Config.Profiles = []core.Profile{desktopWindowsProfile()}
	a.Config.SelectedID = "win"
	a.openConnectForm()
	a.Password = "synthetic"
	a.Authorized = true
	v := ui.NewTester(a.connectForm, 1000, 900)
	if !v.HasText("Allow Windows credential caching for this attempt") {
		t.Fatal("persistence disclosure absent")
	}
	if err := v.Click("Connect"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-adapter.started:
		t.Fatal("missing consent invoked backend")
	default:
	}
	a.WindowsPersistenceConsent = true
	v.Frame()
	_ = v.Click("Connect")
	select {
	case <-adapter.started:
		t.Fatal("missing shared-reference consent invoked backend")
	default:
	}
	a.WindowsSharedConsent = true
	v.Frame()
	if err := v.Click("Connect"); err != nil {
		t.Fatal(err)
	}
	got := <-adapter.started
	if !got.NetworkChanges || !got.WindowsCredentialPersistence || !got.WindowsSharedReference {
		t.Fatal("UI lost per-use authorization")
	}
	if a.Password != "" || a.WindowsPersistenceConsent || a.WindowsSharedConsent || a.Authorized {
		t.Fatal("connect retained credentials/consents")
	}
	_ = a.Engine.Disconnect()
	awaitState(t, a, core.Disconnected)
	a.openConnectForm()
	a.Password = "synthetic"
	a.WindowsPersistenceConsent = true
	a.WindowsSharedConsent = true
	v.Frame()
	_ = v.Click("Cancel")
	if a.Password != "" || a.WindowsPersistenceConsent || a.WindowsSharedConsent {
		t.Fatal("cancel retained consent")
	}
}
func TestWindowsEditorIsolationAndExplicitMode(t *testing.T) {
	a := New(filepath.Join(t.TempDir(), "profiles.json"))
	for _, p := range a.profileProtocols() {
		if p == core.WindowsBorrowedProtocol {
			t.Fatal("default UI activated Windows mode")
		}
	}
	a.WindowsBorrowedEnabled = true
	a.Config.Settings.Language = "en"
	p := desktopWindowsProfile()
	a.Config.Profiles = []core.Profile{p}
	a.startEdit(&a.Config.Profiles[0])
	a.Draft.WindowsBorrowed.EntryName = "edited"
	if a.Config.Profiles[0].WindowsBorrowed.EntryName != "VPN" {
		t.Fatal("editing changed committed selection")
	}
	v := ui.NewTester(a.editor, 1100, 1400)
	if !v.HasText("Exact local phonebook path (.pbk)") || v.HasText("IPsec pre-shared key (this session only)") {
		t.Fatal("wrong Windows profile controls")
	}
	cfg := a.copyConfig()
	cfg.Profiles[0].WindowsBorrowed.EntryName = "copy"
	if a.Config.Profiles[0].WindowsBorrowed.EntryName != "VPN" {
		t.Fatal("copied config aliased source")
	}
	a.WindowsPersistenceConsent = true
	a.WindowsSharedConsent = true
	a.setDraftProtocol("l2tp")
	if a.Draft.WindowsBorrowed != nil || a.WindowsPersistenceConsent || a.WindowsSharedConsent {
		t.Fatal("protocol switch retained selection or consent")
	}
	if _, ok := a.platformAdapter().(*core.WindowsBorrowedAdapter); !ok {
		t.Fatal("recheck lost explicit Windows adapter")
	}
}

type windowsTestSession struct{ *switchSession }

func (windowsTestSession) VerificationScope() string { return core.WindowsBorrowedObservedInterface }
