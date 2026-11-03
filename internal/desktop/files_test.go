package desktop

import (
	"mygo-vpn/internal/core"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func profileForFiles(id, name string) core.Profile {
	return core.Profile{ID: id, Name: name, Gateway: "https://vpn.example.com", Protocol: "anyconnect"}
}
func TestImportMergeDeduplicatesWithoutOverwriting(t *testing.T) {
	dir := t.TempDir()
	a := NewWithAdapter(filepath.Join(dir, "active.json"), unavailableTestAdapter{})
	p := profileForFiles("same", "Existing")
	a.Config.Profiles = []core.Profile{p}
	a.Config.SelectedID = p.ID
	a.Config.Settings.DarkMode = true
	a.Config.Settings.Language = "en"
	a.commit(a.Config)
	other := profileForFiles("other", "Imported")
	path := filepath.Join(dir, "import.json")
	cfg := core.Config{Version: 1, Profiles: []core.Profile{p, other}, SelectedID: other.ID}
	if err := (core.Store{Path: path}).Save(cfg); err != nil {
		t.Fatal(err)
	}
	if err := a.ImportProfiles(path); err != nil {
		t.Fatal(err)
	}
	if len(a.Config.Profiles) != 2 || a.Config.SelectedID != p.ID || !a.Config.Settings.DarkMode || a.Config.Settings.Language != "en" {
		t.Fatal("import overwrote local config")
	}
	if a.Config.Profiles[1].ID == other.ID {
		t.Fatal("import did not assign independent ID")
	}
	if err := a.ImportProfiles(path); err != nil {
		t.Fatal(err)
	}
	if len(a.Config.Profiles) != 2 {
		t.Fatal("repeated import duplicated profiles")
	}
}
func TestImportRejectsSecretAndPreservesFile(t *testing.T) {
	dir := t.TempDir()
	a := NewWithAdapter(filepath.Join(dir, "active.json"), unavailableTestAdapter{})
	a.commit(a.Config)
	before, _ := os.ReadFile(a.Store.Path)
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte(`{"version":1,"profiles":[],"password":"do-not-accept"}`), 0600)
	if a.ImportProfiles(path) == nil {
		t.Fatal("secret field accepted")
	}
	after, _ := os.ReadFile(a.Store.Path)
	if string(before) != string(after) {
		t.Fatal("failed import changed disk")
	}
	if a.ImportProfiles(filepath.Join(dir, "missing.json")) == nil {
		t.Fatal("missing import silently accepted")
	}
}
func TestExportDoesNotContainMemorySecretsOrConsent(t *testing.T) {
	dir := t.TempDir()
	a := NewWithAdapter(filepath.Join(dir, "active.json"), unavailableTestAdapter{})
	p := profileForFiles("one", "One")
	p.Description = "office"
	p.ProxyURL = "http://proxy.example.com:8080"
	p.AllowProxySystemAuth = true
	a.Config.Profiles = []core.Profile{p}
	a.Config.SelectedID = p.ID
	a.Password = "memory-password"
	a.ProxyConsent = true
	dest := filepath.Join(dir, "export.json")
	if err := a.ExportProfiles(dest, &p); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(dest)
	if strings.Contains(string(raw), a.Password) || strings.Contains(string(raw), "allow_proxy_system_auth") {
		t.Fatal("export persisted secret or proxy consent")
	}
	cfg, err := (core.Store{Path: dest}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Profiles) != 1 || cfg.Profiles[0].Description != "office" || cfg.Profiles[0].AllowProxySystemAuth {
		t.Fatal("incorrect export")
	}
	info, _ := os.Stat(dest)
	// Windows mode bits do not describe ACL privacy; no Windows ACL claim is made.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("export not private")
	}
}
func TestExportProtectsActiveConfigAndLogsAreRedacted(t *testing.T) {
	dir := t.TempDir()
	a := NewWithAdapter(filepath.Join(dir, "active.json"), unavailableTestAdapter{})
	a.commit(a.Config)
	a.Password = "never-in-logs"
	if a.ExportProfiles(a.Store.Path, nil) == nil || a.ExportActivity(a.Store.Path) == nil {
		t.Fatal("export replaced active configuration")
	}
	alias := filepath.Join(dir, "alias.json")
	if err := os.Link(a.Store.Path, alias); err == nil {
		if a.ExportActivity(alias) == nil {
			t.Fatal("hardlink bypassed protected config")
		}
	}
	dest := filepath.Join(dir, "logs.json")
	if err := a.ExportActivity(dest); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(dest)
	if strings.Contains(string(raw), a.Password) || !strings.Contains(string(raw), "events") {
		t.Fatal("bad log export")
	}
}
func TestAdvancedDraftRejectsInvalidMTUAndMissingCA(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "p.json"), unavailableTestAdapter{})
	a.startEdit(nil)
	a.Draft = profileForFiles("", "advanced")
	a.MTUText = "1280x"
	a.saveDraft()
	if !a.Editing || len(a.Config.Profiles) > 0 {
		t.Fatal("invalid mtu saved")
	}
	a.MTUText = "1280"
	a.Draft.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	a.saveDraft()
	if !a.Editing || len(a.Config.Profiles) > 0 {
		t.Fatal("missing CA accepted")
	}
}
func TestProxyConsentNeverSurvivesNavigation(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "p.json"), unavailableTestAdapter{})
	a.ProxyConsent = true
	a.Password = "temporary"
	a.Authorized = true
	a.ConnectPanel = true
	a.navigate("Settings")
	if a.ProxyConsent || a.Password != "" || a.Authorized || a.ConnectPanel {
		t.Fatal("navigation retained credentials/consent")
	}
}
func TestByteFormattingOnlyKnownValues(t *testing.T) {
	for n, want := range map[uint64]string{0: "0 B", 512: "512 B", 1024: "1.0 KiB", 1048576: "1.0 MiB"} {
		if got := formatBytes(n); got != want {
			t.Fatalf("%d: %s", n, got)
		}
	}
}
