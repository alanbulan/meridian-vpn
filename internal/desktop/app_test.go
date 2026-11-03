package desktop

import (
	"context"
	"errors"
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeNavigationAndProfilePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	a := New(path)
	a.Config.Settings.Language = "en"
	v := ui.NewTester(a.View, 1040, 780)
	if !v.HasText("Disconnected") {
		t.Fatal("must start disconnected")
	}
	if err := v.Click("+  Add profile"); err != nil {
		t.Fatal(err)
	}
	if !a.Editing {
		t.Fatal("add did not open editor")
	}
	a.Draft = core.Profile{Name: "QA profile", Gateway: "https://vpn.example.com", Protocol: "anyconnect"}
	v.Frame()
	if err := v.Click("Save profile"); err != nil {
		t.Fatal(err)
	}
	if a.Editing {
		t.Fatal("save did not dismiss editor")
	}
	b := New(path)
	if len(b.Config.Profiles) != 1 || b.Config.Profiles[0].Name != "QA profile" {
		t.Fatal("profile not persisted")
	}
	if err := v.Click("Settings"); err != nil {
		t.Fatal(err)
	}
	if a.Page != "Settings" {
		t.Fatal("navigation failed")
	}
	if err := v.Click("Back to connections"); err != nil {
		t.Fatal(err)
	}
	if !v.HasText("Disconnected") {
		t.Fatal("status changed unexpectedly")
	}
}
func TestCancelAndInvalidSave(t *testing.T) {
	a := New(filepath.Join(t.TempDir(), "profiles.json"))
	a.startEdit(nil)
	a.Config.Settings.Language = "en"
	v := ui.NewTester(a.View, 1040, 780)
	if err := v.Click("Save profile"); err != nil {
		t.Fatal(err)
	}
	if !a.Editing || len(a.Config.Profiles) != 0 {
		t.Fatal("invalid profile saved")
	}
	if err := v.Click("Cancel"); err != nil {
		t.Fatal(err)
	}
	if a.Editing {
		t.Fatal("cancel failed")
	}
}
func TestCorruptFileNeverOverwritten(t *testing.T) {
	p := filepath.Join(t.TempDir(), "profiles.json")
	os.WriteFile(p, []byte("broken"), 0600)
	a := New(p)
	a.Draft = core.Profile{Name: "x", Gateway: "https://vpn.example.com", Protocol: "anyconnect"}
	a.saveDraft()
	b, _ := os.ReadFile(p)
	if string(b) != "broken" {
		t.Fatal("corrupt file overwritten")
	}
}

func TestChineseDefaultAndVisibleSafetyAtMinimumSize(t *testing.T) {
	a := New(filepath.Join(t.TempDir(), "profiles.json"))
	a.Config.Profiles = []core.Profile{{ID: "test", Name: "企业内网 · 示例", Gateway: "https://vpn.example.com", Protocol: "anyconnect"}}
	a.Config.SelectedID = "test"
	a.Capability = core.Capability{Message: "NetworkManager CLI is not installed; live connection unavailable."}
	v := ui.NewTester(a.View, 880, 700)
	if !v.HasText("选择 VPN 连接") || !v.HasText("未连接") {
		t.Fatal("Chinese default or offline state missing")
	}
	r, ok := v.Find(a.tr("Setup needed"))
	if !ok || r.Y+r.H > 700 {
		t.Fatalf("prerequisite notice is below fold: %+v", r)
	}
	if err := v.Click("连接此网关"); err != nil {
		t.Fatal(err)
	}
	if a.ConnectPanel {
		t.Fatal("missing prerequisites must not open live connection form")
	}
}
func TestCredentialCancelAndConsentGate(t *testing.T) {
	a := New(filepath.Join(t.TempDir(), "profiles.json"))
	a.Config.Settings.Language = "en"
	a.Password = "ephemeral-test-secret"
	a.ConnectPanel = true
	v := ui.NewTester(a.connectForm, 700, 400)
	if err := v.Click("Connect"); err != nil {
		t.Fatal(err)
	}
	if !a.ConnectPanel {
		t.Fatal("connection without consent was not blocked")
	}
	if err := v.Click("Cancel"); err != nil {
		t.Fatal(err)
	}
	if a.Password != "" || a.Authorized || a.ConnectPanel {
		t.Fatal("cancel retained session credential state")
	}
}
func TestFailedSaveKeepsDraftAndCommittedConfig(t *testing.T) {
	dir := t.TempDir()
	a := New(filepath.Join(dir, "profiles.json"))
	a.Store.Path = dir
	a.Editing = true
	a.Draft = core.Profile{Name: "unsaved", Gateway: "https://vpn.example.com", Protocol: "anyconnect"}
	a.saveDraft()
	if !a.Editing || len(a.Config.Profiles) != 0 {
		t.Fatal("failed save committed in-memory config or closed draft")
	}
}

func TestAppearanceSwitchPersistsWithoutProfileOrCredentialLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	a := New(path)
	a.Config.Settings.Language = "en"
	a.Config.Profiles = []core.Profile{{ID: "test", Name: "Work", Gateway: "https://vpn.example.com", Protocol: "anyconnect"}}
	a.Config.SelectedID = "test"
	a.Password = "memory-only-test"
	v := ui.NewTester(a.View, 1040, 700)
	if a.Config.Settings.DarkMode {
		t.Fatal("default must be light")
	}
	if err := v.Click("Dark appearance"); err != nil {
		t.Fatal(err)
	}
	if !a.Config.Settings.DarkMode {
		t.Fatal("theme did not switch")
	}
	b := New(path)
	if !b.Config.Settings.DarkMode || len(b.Config.Profiles) != 1 {
		t.Fatal("theme or profiles not persisted")
	}
	if a.Password != "memory-only-test" {
		t.Fatal("theme switch changed in-memory credential")
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "memory-only-test") {
		t.Fatal("credential persisted")
	}
	if err := v.Click("Light appearance"); err != nil {
		t.Fatal(err)
	}
	if a.Config.Settings.DarkMode {
		t.Fatal("light theme did not restore")
	}
}

func TestReferenceLayoutSearchFiltersWithoutMutatingProfiles(t *testing.T) {
	a := New(filepath.Join(t.TempDir(), "profiles.json"))
	a.Config.Settings.Language = "en"
	a.Config.Profiles = []core.Profile{{ID: "one", Name: "Office", Gateway: "https://office.example.com", Protocol: "anyconnect"}, {ID: "two", Name: "Lab", Gateway: "https://lab.example.com", Protocol: "anyconnect"}}
	a.Config.SelectedID = "one"
	v := ui.NewTester(a.View, 960, 620)
	for _, field := range []string{"VPN name", "Uploaded", "Downloaded", "Connection duration", "Username", "Virtual IP", "Authentication"} {
		if !v.HasText(field) {
			t.Fatalf("missing reference field %s", field)
		}
	}
	a.Search = "lab"
	v.Frame()
	if !v.HasText("Lab") || v.HasText("office.example.com") {
		t.Fatal("search did not filter list")
	}
	if len(a.Config.Profiles) != 2 || a.Config.SelectedID != "one" {
		t.Fatal("search mutated profiles")
	}
	a.Search = "none"
	v.Frame()
	if !v.HasText("No matching connections") {
		t.Fatal("empty search state missing")
	}
}

type unavailableTestAdapter struct{ message string }

func (a unavailableTestAdapter) Capability() core.Capability {
	return core.Capability{Message: a.message}
}
func (a unavailableTestAdapter) Start(context.Context, core.Profile, []byte) (core.Session, error) {
	return nil, errors.New("must not start")
}
func TestTraySaveFailureRollsBackMemory(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), unavailableTestAdapter{})
	a.Store.Path = t.TempDir()
	a.setTray(true)
	if a.Config.Settings.MinimizeToTray {
		t.Fatal("failed save changed tray behavior")
	}
	if a.Notice == "" {
		t.Fatal("failure not surfaced")
	}
}
func TestDiagnosticsDismissesCredentialPanel(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), unavailableTestAdapter{})
	a.Config.Settings.Language = "en"
	a.ConnectPanel = true
	a.Password = "memory-test"
	a.Authorized = true
	v := ui.NewTester(a.View, 960, 620)
	if err := v.Click("View details"); err != nil {
		t.Fatal(err)
	}
	if a.Page != "Settings" || a.ConnectPanel || a.Password != "" || a.Authorized {
		t.Fatal("diagnostics left credential panel or secret active")
	}
	if !v.HasText("Diagnostics") {
		t.Fatal("settings not visible")
	}
}
func TestShutdownBlocksConnectAndClearsCredentials(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), unavailableTestAdapter{})
	a.Capability.Available = true
	p := core.Profile{ID: "p", Name: "work", Gateway: "https://vpn.example.com", Protocol: "anyconnect"}
	a.Config.Profiles = []core.Profile{p}
	a.Config.SelectedID = p.ID
	a.Password = "transient"
	a.ConnectPanel = true
	a.Authorized = true
	if !a.canConnect(&p) {
		t.Fatal("setup invalid")
	}
	a.BeginShutdown()
	if a.canConnect(&p) || a.Password != "" || a.ConnectPanel || a.Authorized {
		t.Fatal("shutdown retained connection authority")
	}
	called := false
	a.beginRecheck(func() core.Adapter { called = true; return unavailableTestAdapter{} })
	if called || a.Checking {
		t.Fatal("recheck started during shutdown")
	}
}
func TestRecheckPreservesEngineAndLogs(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), unavailableTestAdapter{message: "old"})
	original := a.Engine
	oldLogs := len(original.Snapshot().Logs)
	a.Checking = true
	a.recheckResults = make(chan adapterCheck, 1)
	a.recheckResults <- adapterCheck{adapter: unavailableTestAdapter{message: "new"}}
	a.pollRecheck()
	if a.Engine != original || a.Checking || a.Capability.Message != "new" {
		t.Fatal("recheck replaced engine or did not finish")
	}
	if len(a.Engine.Snapshot().Logs) <= oldLogs {
		t.Fatal("recheck discarded history")
	}
}
func TestRecheckResultIgnoredAfterShutdown(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), unavailableTestAdapter{message: "old"})
	a.Checking = true
	a.recheckResults = make(chan adapterCheck, 1)
	a.recheckResults <- adapterCheck{adapter: unavailableTestAdapter{message: "new"}}
	a.BeginShutdown()
	a.pollRecheck()
	if a.Checking || a.Capability.Message != "old" {
		t.Fatal("late recheck changed shutdown adapter")
	}
}
func TestThemeSaveFailureDoesNotChangeAppearance(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), unavailableTestAdapter{})
	a.Store.Path = t.TempDir()
	a.switchTheme(true)
	if a.Config.Settings.DarkMode {
		t.Fatal("failed save changed theme")
	}
}
func TestFollowSystemLanguageIsExplicitAndPersists(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "p.json"), unavailableTestAdapter{})
	a.Config.Settings.Language = "system"
	a.SetSystemLanguages([]string{"en-US"})
	if a.tr("Settings") != "Settings" {
		t.Fatal("system English ignored")
	}
	a.SetSystemLanguages([]string{"zh-Hans-CN", "en"})
	if a.tr("Settings") != "设置" {
		t.Fatal("system Chinese ignored")
	}
	a.Config.Settings.Language = "en"
	a.SetSystemLanguages([]string{"zh-CN"})
	if a.tr("Settings") != "Settings" {
		t.Fatal("system overrode explicit language")
	}
	a.Config.Settings.Language = "system"
	if !a.commit(a.Config) {
		t.Fatal(a.Notice)
	}
	b := NewWithAdapter(a.Store.Path, unavailableTestAdapter{})
	if b.Config.Settings.Language != "system" {
		t.Fatal("system preference not persisted")
	}
}
func TestSidebarConnectVisibleAtMinimumClientHeightWithAdvancedEditor(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "p.json"), unavailableTestAdapter{})
	a.Config.Settings.Language = "en"
	p := profileForFiles("p", "Office")
	a.Config.Profiles = []core.Profile{p}
	a.Config.SelectedID = p.ID
	a.startEdit(&p)
	a.AdvancedOpen = true
	v := ui.NewTester(a.View, 880, 544)
	r, ok := v.Find("Connect to this gateway")
	if !ok || r.Y+r.H > 544 || r.Y < 0 {
		t.Fatalf("connect clipped in minimum client: %+v", r)
	}
}
