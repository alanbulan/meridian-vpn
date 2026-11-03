package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mygo-vpn/internal/core"
	"mygo-vpn/internal/diagnostics"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func testApplication(t *testing.T) application {
	t.Helper()
	a := newApplication()
	a.version = "test-version"
	a.configDir = func() (string, error) { return t.TempDir(), nil }
	a.diagnostics = func(context.Context, string) diagnostics.Report {
		t.Fatal("unexpected host diagnostics")
		return diagnostics.Report{}
	}
	return a
}

func runCLI(a application, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := a.run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func sampleProfile() core.Profile {
	return core.Profile{ID: "private-profile-id", Name: "private-profile-name", Gateway: "https://private.example", Protocol: "anyconnect", Username: "private-account", Description: "private-description", AuthGroup: "private-group", CAFile: filepath.Join(os.TempDir(), "meridian-private-ca-fixture", "ca.pem"), ProxyURL: "http://private-proxy.example:8080", InteractiveAuth: true, DisableUDP: true, MTU: 1400}
}

func sampleConfig() core.Config {
	p := sampleProfile()
	return core.Config{Version: 1, Profiles: []core.Profile{p}, SelectedID: p.ID, Settings: core.Settings{Language: "en", DarkMode: true}}
}

func writeConfig(t *testing.T, path string, cfg core.Config) {
	t.Helper()
	if err := (core.Store{Path: path}).Save(cfg); err != nil {
		t.Fatal(err)
	}
}

func readConfig(t *testing.T, path string) core.Config {
	t.Helper()
	cfg, err := (core.Store{Path: path}).Load()
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func assertNoProfileData(t *testing.T, text string) {
	t.Helper()
	for _, value := range []string{"private-profile-id", "private-profile-name", "private.example", "private-account", "private-description", "private-group", "/private/", "meridian-private-ca-fixture", "private-proxy.example"} {
		if strings.Contains(text, value) {
			t.Fatalf("redacted output disclosed %q", value)
		}
	}
}

func TestListRedactedByDefaultAndExplicitPrivateOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	writeConfig(t, path, sampleConfig())
	a := testApplication(t)
	for _, jsonMode := range []bool{false, true} {
		args := []string{"--config", path, "profiles", "list"}
		if jsonMode {
			args = append(args, "--json")
		}
		code, out, errOut := runCLI(a, args...)
		if code != 0 || errOut != "" {
			t.Fatalf("list failed: %d %q", code, errOut)
		}
		assertNoProfileData(t, out)
		if !strings.Contains(out, "anyconnect") {
			t.Fatal("protocol missing")
		}
		if jsonMode {
			var r struct {
				Redacted bool            `json:"redacted"`
				Profiles []listedProfile `json:"profiles"`
			}
			if json.Unmarshal([]byte(out), &r) != nil || !r.Redacted || len(r.Profiles) != 1 || !r.Profiles[0].Selected || !r.Profiles[0].InteractiveAuth || r.Profiles[0].Private != nil {
				t.Fatal("invalid redacted report")
			}
		}
	}
	code, out, _ := runCLI(a, "--config", path, "profiles", "list", "--show-private", "--json")
	if code != 0 || !strings.Contains(out, "private-account") || !strings.Contains(out, "private.example") {
		t.Fatal("explicit private data unavailable")
	}
	if strings.Contains(out, "AllowProxySystemAuth") {
		t.Fatal("runtime authorization exported")
	}
}

func TestMissingConfigListIsEmptyButValidationFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.json")
	a := testApplication(t)
	code, out, _ := runCLI(a, "--config", path, "profiles", "list", "--json")
	if code != 0 || !strings.Contains(out, `"config_exists": false`) || !strings.Contains(out, `"profiles": []`) {
		t.Fatalf("missing list incorrect: %d %s", code, out)
	}
	code, out, _ = runCLI(a, "--config", path, "validate", "--json")
	if code != 1 || !strings.Contains(out, "missing_config") {
		t.Fatal("missing config passed validation")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only operation created config")
	}
}

func TestValidateSchemaAndOptionalCertificateChecks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	writeConfig(t, path, sampleConfig())
	a := testApplication(t)
	code, out, errOut := runCLI(a, "--config", path, "validate", "--json")
	if code != 0 || errOut != "" {
		t.Fatalf("validation failed: %s %s", out, errOut)
	}
	var r validationReport
	if json.Unmarshal([]byte(out), &r) != nil || !r.Valid || r.CertificateFilesChecked || r.ProfileCount != 1 {
		t.Fatal("invalid validation result")
	}
	code, out, _ = runCLI(a, "--config", path, "validate", "--check-files", "--json")
	if code != 1 || !strings.Contains(out, "invalid_ca_file") {
		t.Fatal("missing CA file passed --check-files")
	}
	assertNoProfileData(t, out)
	cfg := sampleConfig()
	cfg.Profiles[0].CAFile = ""
	writeConfig(t, path, cfg)
	code, out, _ = runCLI(a, "--config", path, "validate", "--check-files", "--json")
	if code != 0 {
		t.Fatalf("profiles without custom cert files failed: %s", out)
	}
}

func TestUntrustedValidationErrorsAreNotPrinted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"profiles":[],"private-account password=secret":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	a := testApplication(t)
	for _, command := range [][]string{{"validate", "--json"}, {"profiles", "list", "--json"}} {
		args := append([]string{"--config", path}, command...)
		code, out, errOut := runCLI(a, args...)
		if code != 1 || strings.Contains(out+errOut, "password=secret") || strings.Contains(out+errOut, "private-account") || strings.Contains(out+errOut, path) {
			t.Fatalf("private error leaked: %d %s %s", code, out, errOut)
		}
	}
}

func TestDiagnosticsDoesNotReadConfigAndUsesExitStatus(t *testing.T) {
	a := testApplication(t)
	a.configDir = func() (string, error) { t.Fatal("diagnostics read config dir"); return "", nil }
	for _, ready := range []bool{false, true} {
		a.diagnostics = func(ctx context.Context, version string) diagnostics.Report {
			if version != "test-version" {
				t.Fatal("version not forwarded")
			}
			return diagnostics.Report{SchemaVersion: 1, ReadOnly: true, Backend: diagnostics.Backend{PrerequisitesAvailable: ready}, Checks: []diagnostics.Check{{ID: "platform", Status: diagnostics.Available, Message: "Linux supported."}}}
		}
		code, out, errOut := runCLI(a, "diagnostics", "--json")
		if (code == 0) != ready || errOut != "" {
			t.Fatalf("wrong exit code: %d ready=%t", code, ready)
		}
		var report diagnostics.Report
		if json.Unmarshal([]byte(out), &report) != nil || !report.ReadOnly {
			t.Fatal("invalid diagnostic JSON")
		}
	}
}

func TestImportPreviewDeduplicatesWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	path, input := filepath.Join(dir, "active.json"), filepath.Join(dir, "import.json")
	cfg := sampleConfig()
	writeConfig(t, path, cfg)
	imported := sampleConfig()
	imported.Profiles[0].ID = "different-id"
	imported.SelectedID = "different-id"
	second := sampleProfile()
	second.ID = "second"
	second.Name = "Second"
	imported.Profiles = append(imported.Profiles, second)
	writeConfig(t, input, imported)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI(testApplication(t), "--config", path, "profiles", "import", "--file", input, "--json")
	if code != 0 || errOut != "" || !strings.Contains(out, `"added": 1`) || !strings.Contains(out, `"duplicates": 1`) || !strings.Contains(out, `"saved": false`) {
		t.Fatalf("import failed: %d %s %s", code, out, errOut)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("preview changed active config")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 2 {
		t.Fatal("preview created files")
	}
	assertNoProfileData(t, out+errOut)
}

func TestImportWritesOnlyNewMergedConfigAndPreservesSettings(t *testing.T) {
	dir := t.TempDir()
	path, input, output := filepath.Join(dir, "active.json"), filepath.Join(dir, "import.json"), filepath.Join(dir, "merged.json")
	cfg := sampleConfig()
	writeConfig(t, path, cfg)
	imported := sampleConfig()
	imported.Profiles[0].Name = "Second"
	imported.Settings.Language = "zh"
	writeConfig(t, input, imported)
	code, out, errOut := runCLI(testApplication(t), "--config", path, "profiles", "import", "--file", input, "--output", output, "--json")
	if code != 0 || errOut != "" || !strings.Contains(out, `"saved": true`) || !strings.Contains(out, `"active_config_changed": false`) {
		t.Fatalf("save merge failed: %s %s", out, errOut)
	}
	merged := readConfig(t, output)
	if len(merged.Profiles) != 2 || merged.Settings != cfg.Settings || merged.SelectedID != cfg.SelectedID || merged.Profiles[1].ID == imported.Profiles[0].ID {
		t.Fatalf("incorrect merged config: %+v", merged)
	}
	if !reflect.DeepEqual(readConfig(t, path), cfg) {
		t.Fatal("active config changed")
	}
	assertPrivateMode(t, output)
	files, _ := os.ReadDir(dir)
	if len(files) != 3 {
		t.Fatal("staging files leaked")
	}
}

func TestImportRefusesOverwriteAndMissingSource(t *testing.T) {
	dir := t.TempDir()
	path, input := filepath.Join(dir, "active.json"), filepath.Join(dir, "input.json")
	writeConfig(t, path, sampleConfig())
	writeConfig(t, input, sampleConfig())
	a := testApplication(t)
	for _, output := range []string{path, input} {
		code, _, _ := runCLI(a, "--config", path, "profiles", "import", "--file", input, "--output", output)
		if code != 1 {
			t.Fatal("import overwrote existing file")
		}
	}
	code, _, _ := runCLI(a, "--config", path, "profiles", "import", "--file", filepath.Join(dir, "missing.json"))
	if code != 1 {
		t.Fatal("missing import source accepted")
	}
}

func TestImportLimitFailureWritesNothing(t *testing.T) {
	dir := t.TempDir()
	path, input, output := filepath.Join(dir, "active.json"), filepath.Join(dir, "input.json"), filepath.Join(dir, "output.json")
	cfg := sampleConfig()
	cfg.Profiles = nil
	cfg.SelectedID = ""
	for i := 0; i < core.MaxProfiles; i++ {
		p := sampleProfile()
		p.ID = core.NewID()
		p.Name = p.ID
		if err := cfg.Upsert(p); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(t, path, cfg)
	writeConfig(t, input, sampleConfig())
	code, _, _ := runCLI(testApplication(t), "--config", path, "profiles", "import", "--file", input, "--output", output)
	if code != 1 {
		t.Fatal("overflow accepted")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed import created output")
	}
	if len(readConfig(t, path).Profiles) != core.MaxProfiles {
		t.Fatal("failed import mutated active config")
	}
}

func TestExportSelectedProfileAndPrivateMode(t *testing.T) {
	dir := t.TempDir()
	path, output := filepath.Join(dir, "active.json"), filepath.Join(dir, "export.json")
	cfg := sampleConfig()
	p := sampleProfile()
	p.ID = "second"
	p.Name = "Second"
	p.AllowProxySystemAuth = true
	cfg.Profiles = append(cfg.Profiles, p)
	writeConfig(t, path, cfg)
	code, out, errOut := runCLI(testApplication(t), "--config", path, "profiles", "export", "--output", output, "--profile", "2")
	if code != 0 || errOut != "" {
		t.Fatalf("export failed: %s %s", out, errOut)
	}
	exported := readConfig(t, output)
	if len(exported.Profiles) != 1 || exported.SelectedID != "second" || exported.Profiles[0].ID != "second" || exported.Settings != (core.Settings{}) || exported.Profiles[0].AllowProxySystemAuth {
		t.Fatal("export retained settings or runtime authorization")
	}
	assertPrivateMode(t, output)
	assertNoProfileData(t, out+errOut)
}

func assertPrivateMode(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("output permissions = %o", st.Mode().Perm())
	}
}

func TestExportRefusesOverwriteAndInvalidIndex(t *testing.T) {
	dir := t.TempDir()
	path, output := filepath.Join(dir, "active.json"), filepath.Join(dir, "existing.json")
	writeConfig(t, path, sampleConfig())
	if err := os.WriteFile(output, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	a := testApplication(t)
	for _, target := range []string{path, output} {
		code, _, _ := runCLI(a, "--config", path, "profiles", "export", "--output", target)
		if code != 1 {
			t.Fatal("export overwrote existing file")
		}
	}
	if b, _ := os.ReadFile(output); string(b) != "keep" {
		t.Fatal("existing export replaced")
	}
	code, _, _ := runCLI(a, "--config", path, "profiles", "export", "--output", filepath.Join(dir, "new.json"), "--profile", "2")
	if code != 1 {
		t.Fatal("invalid index accepted")
	}
}

func TestSaveNewConfigNeverReplacesSymlinkOrHardlink(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	if err := os.WriteFile(original, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"symlink", "hardlink"} {
		path := filepath.Join(dir, name)
		var err error
		if name == "symlink" {
			err = os.Symlink(original, path)
		} else {
			err = os.Link(original, path)
		}
		if err != nil {
			continue
		}
		if saveNewConfig(path, sampleConfig()) == nil {
			t.Fatalf("%s replaced", name)
		}
		if b, _ := os.ReadFile(original); string(b) != "keep" {
			t.Fatal("linked original changed")
		}
	}
}

func TestOutputParentMustExist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "newdir", "output.json")
	if saveNewConfig(path, sampleConfig()) == nil {
		t.Fatal("unexpected success")
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("output created directory")
	}
}

func TestHelpVersionAndRejectedCommands(t *testing.T) {
	a := testApplication(t)
	a.configDir = func() (string, error) { return "", errors.New("no config home") }
	for _, args := range [][]string{{}, {"help"}, {"--help"}, {"version"}, {"--version"}} {
		code, out, _ := runCLI(a, args...)
		if code != 0 || out == "" {
			t.Fatalf("help/version failed: %q", args)
		}
	}
	for _, args := range [][]string{{"connect", "--password", "secret-password"}, {"disconnect"}, {"profiles", "delete"}, {"diagnostics", "--gateway", "private.example"}, {"--bad=private-account"}, {"--version", "extra"}} {
		code, out, errOut := runCLI(a, args...)
		if code == 0 || strings.Contains(out+errOut, "secret-password") || strings.Contains(out+errOut, "private.example") || strings.Contains(out+errOut, "private-account") {
			t.Fatalf("unsafe/invalid command accepted or leaked: %q", args)
		}
	}
	code, _, errOut := runCLI(a, "profiles", "list")
	if code != 1 || !strings.Contains(errOut, "--config") {
		t.Fatal("config fallback missing")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestBrokenOutputIsFailure(t *testing.T) {
	a := testApplication(t)
	var errOut bytes.Buffer
	if code := a.run(context.Background(), []string{"version"}, failingWriter{}, &errOut); code != 1 {
		t.Fatal("broken output reported success")
	}
}
