package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestINIPreviewCLIWithoutConfig(t *testing.T) {
	a := testApplication(t)
	a.configDir = func() (string, error) { t.Fatal("INI preview must not resolve config"); return "", nil }
	path := filepath.Join(t.TempDir(), "input.ini")
	os.WriteFile(path, []byte("[private-section]\npassword=private-password\naddress=https://private.example\n"), 0600)
	for _, format := range [][]string{{}, {"--json"}} {
		args := append([]string{"profiles", "preview-ini", "--file", path}, format...)
		code, out, errs := runCLI(a, args...)
		if code != 0 || errs != "" || strings.Contains(out, "private") {
			t.Fatalf("%d %s %s", code, out, errs)
		}
	}
	code, out, errs := runCLI(a, "profiles", "preview-ini", "--file", path, "--output", "new.json")
	if code != 2 || out != "" || strings.Contains(errs, path) {
		t.Fatal("unsafe flags accepted")
	}
}
