//go:build linux

package desktop

import (
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/autostart"
	"os"
	"path/filepath"
	"testing"
)

func TestStartupConfirmationCancelNeverCreatesEntry(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "meridian")
	if err := os.WriteFile(exe, []byte("test fixture, never executed"), 0700); err != nil {
		t.Fatal(err)
	}
	manager, err := autostart.New(autostart.Options{ConfigDir: filepath.Join(root, "config"), Executable: exe})
	if err != nil {
		t.Fatal(err)
	}
	a := NewWithAdapter(filepath.Join(root, "profiles.json"), unavailableTestAdapter{})
	a.Config.Settings.Language = "en"
	a.Page = "Settings"
	a.Startup = manager
	a.StartupStatus, err = manager.Status()
	if err != nil {
		t.Fatal(err)
	}
	a.StartupError = ""
	v := ui.NewTester(a.View, 960, 620)
	if err := v.Click("Enable"); err != nil {
		t.Fatal(err)
	}
	if !a.StartupConfirm {
		t.Fatal("enable skipped confirmation")
	}
	if _, err := os.Stat(filepath.Join(root, "config")); !os.IsNotExist(err) {
		t.Fatal("opening confirmation mutated startup config")
	}
	if err := v.Click("Cancel"); err != nil {
		t.Fatal(err)
	}
	if a.StartupConfirm {
		t.Fatal("cancel did not dismiss")
	}
	if _, err := os.Stat(filepath.Join(root, "config")); !os.IsNotExist(err) {
		t.Fatal("cancel mutated startup config")
	}
}
