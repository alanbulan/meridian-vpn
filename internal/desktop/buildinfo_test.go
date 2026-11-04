package desktop

import (
	"context"
	"encoding/json"
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/buildinfo"
	"mygo-vpn/internal/diagnostics"
	"os"
	"path/filepath"
	"testing"
)

func TestPackagedVersionInSettingsAndDiagnostics(t *testing.T) {
	old := buildinfo.Version
	buildinfo.Version = "0.1.0-test.7"
	t.Cleanup(func() { buildinfo.Version = old })
	dir := t.TempDir()
	a := New(filepath.Join(dir, "profiles.json"))
	a.Page = "Settings"
	for _, language := range []string{"en", "zh"} {
		a.Config.Settings.Language = language
		tester := ui.NewTester(a.View, 1040, 780)
		if !tester.HasText("Meridian " + buildinfo.Version + " / MyGo 0.7.4 / " + map[string]string{"en": "pure Go native UI", "zh": "纯 Go 原生界面"}[language]) {
			t.Fatal("settings lack version", language)
		}
	}
	out := filepath.Join(dir, "diagnostics.json")
	if err := a.ExportDiagnostics(context.Background(), out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var report diagnostics.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Application.Version != buildinfo.Version {
		t.Fatal("diagnostics lack version")
	}
}
