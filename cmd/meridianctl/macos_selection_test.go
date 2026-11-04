package main

import (
	"mygo-vpn/internal/core"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestExportOmitsLocalMacSelection(t *testing.T) {
	for _, profile := range []string{"0", "1"} {
		t.Run(profile, func(t *testing.T) {
			path, output := filepath.Join(t.TempDir(), "active.json"), filepath.Join(t.TempDir(), "export.json")
			cfg := sampleConfig()
			cfg.MacServiceSelection = &core.SavedMacServiceSelection{ServiceID: "private-mac-service", Gateway: "local.example.test", Targets: []string{"10.99.88.77"}}
			writeConfig(t, path, cfg)
			code, out, errOut := runCLI(testApplication(t), "--config", path, "profiles", "export", "--output", output, "--profile", profile)
			if code != 0 {
				t.Fatalf("export failed: %s %s", out, errOut)
			}
			exported := readConfig(t, output)
			if exported.MacServiceSelection != nil {
				t.Fatal("export included device-local selection")
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"mac_service_selection", "private-mac-service", "local.example.test", "10.99.88.77"} {
				if strings.Contains(string(data)+out+errOut, forbidden) {
					t.Fatal("selection leaked", forbidden)
				}
			}
			original := readConfig(t, path)
			if !reflect.DeepEqual(original.MacServiceSelection, cfg.MacServiceSelection) {
				t.Fatal("export changed source")
			}
		})
	}
}
