package desktop

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mygo-vpn/internal/core"
	"mygo-vpn/internal/macosvpn"
)

func TestMacSelectionRestartNeverRestoresAuthority(t *testing.T) {
	a := macUIFixture(t)
	a.macService.input.Targets = "2001:0db8:0:0:0:0:0:1 10.2.3.4"
	a.macService.consent = macosvpn.ExistingServiceConsent{NetworkChanges: true, SavedSystemCredentials: true, SharedSystemService: true, LimitedVerification: true}
	a.macService.prepared = &macServicePrepared{input: a.macService.input}
	a.saveMacServiceSelection()
	if a.Config.MacServiceSelection == nil {
		t.Fatal(a.Notice)
	}
	data, err := os.ReadFile(a.Store.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"consent", "password", "credentials", "prepared", "NetworkChanges"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatal("authority persisted", forbidden)
		}
	}
	b := NewWithAdapter(a.Store.Path, unavailableTestAdapter{})
	if b.LoadBlocked || b.macService.input.Targets != "2001:db8::1 10.2.3.4" || b.macService.input.ID != a.macService.input.ID {
		t.Fatal("selection not restored", b.Notice)
	}
	if b.macService.prepared != nil || b.macService.consent != (macosvpn.ExistingServiceConsent{}) || b.macService.result != nil || b.Engine.Snapshot().AttemptID != 0 {
		t.Fatal("restart restored authority")
	}
	b.connectMacService()
	if b.Engine.Snapshot().AttemptID != 0 {
		t.Fatal("saved selection connected without consent")
	}
	clone := b.copyConfig()
	clone.MacServiceSelection.Targets[0] = "10.0.0.1"
	if b.Config.MacServiceSelection.Targets[0] != "2001:db8::1" {
		t.Fatal("aliased saved targets")
	}
	b.forgetMacServiceSelection()
	c := NewWithAdapter(a.Store.Path, unavailableTestAdapter{})
	if c.Config.MacServiceSelection != nil || b.macService.input != (macServiceInput{}) || c.macService.input != (macServiceInput{}) {
		t.Fatal("forget did not persist")
	}
}

func TestMacSelectionStaleServiceRequiresFreshCheck(t *testing.T) {
	for _, reason := range []string{"service deleted", "gateway changed", "service connected"} {
		t.Run(reason, func(t *testing.T) {
			a := macUIFixture(t)
			a.saveMacServiceSelection()
			b := NewWithAdapter(a.Store.Path, unavailableTestAdapter{})
			b.Page = "MacSystemService"
			b.beginMacServiceCheck(func(_ context.Context, input macServiceInput) (macServicePrepared, error) {
				if input.ID != "service-id" {
					t.Error("wrong saved selection")
				}
				return macServicePrepared{}, errors.New(reason)
			})
			deadline := time.Now().Add(time.Second)
			for b.macService.result != nil && time.Now().Before(deadline) {
				b.pollMacService()
				time.Sleep(time.Millisecond)
			}
			if b.macService.result != nil || b.macService.prepared != nil || b.macService.consent != (macosvpn.ExistingServiceConsent{}) {
				t.Fatal("stale service admitted")
			}
			b.connectMacService()
			if b.Engine.Snapshot().AttemptID != 0 {
				t.Fatal("stale service connected")
			}
			if b.Config.MacServiceSelection == nil {
				t.Fatal("failure silently deleted expectations")
			}
		})
	}
}

func TestMacSelectionFailedSaveAndForgetPreserveData(t *testing.T) {
	a := macUIFixture(t)
	a.saveMacServiceSelection()
	original := a.macService.input
	a.Store.Path = filepath.Join(t.TempDir(), "directory")
	if err := os.Mkdir(a.Store.Path, 0700); err != nil {
		t.Fatal(err)
	}
	a.forgetMacServiceSelection()
	if a.Config.MacServiceSelection == nil || a.macService.input != original {
		t.Fatal("failed forget falsely cleared state")
	}
	a.macService.input.ID = "different-id"
	a.saveMacServiceSelection()
	if a.Config.MacServiceSelection.ServiceID != original.ID {
		t.Fatal("failed save changed persisted state")
	}
	a.LoadBlocked = true
	a.forgetMacServiceSelection()
	if a.Config.MacServiceSelection == nil {
		t.Fatal("blocked load overwritten")
	}
}

func TestMacSelectionInvalidConfigFailsClosed(t *testing.T) {
	a := macUIFixture(t)
	a.macService.input.Targets = "127.0.0.1"
	a.saveMacServiceSelection()
	if a.Config.MacServiceSelection != nil {
		t.Fatal("invalid target saved")
	}
	cfg := core.Config{Version: 1, MacServiceSelection: &core.SavedMacServiceSelection{ServiceID: "service-id", Gateway: "vpn.example.test", Targets: []string{"127.0.0.1"}}}
	if err := a.Store.Save(cfg); err == nil {
		t.Fatal("storage accepted invalid selection")
	}
	if err := os.WriteFile(a.Store.Path, []byte(`{"version":1,"profiles":[],"settings":{},"mac_service_selection":{"service_id":"service-id","gateway":"vpn.example.test","targets":[]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	b := NewWithAdapter(a.Store.Path, unavailableTestAdapter{})
	if !b.LoadBlocked || b.macService.input != (macServiceInput{}) {
		t.Fatal("invalid persisted selection admitted")
	}
}

func TestMacSelectionStorageRejectsAuthorityAndPreservesLegacy(t *testing.T) {
	for _, extra := range []string{`,"consent":true`, `,"password":"secret"`, `,"credentials":{}`, `,"prepared":true`} {
		t.Run(extra, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profiles.json")
			data := `{"version":1,"profiles":[],"settings":{},"mac_service_selection":{"service_id":"service-id","gateway":"vpn.example.test","targets":["10.2.3.4"]` + extra + `}}`
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			a := NewWithAdapter(path, unavailableTestAdapter{})
			if !a.LoadBlocked || a.macService.input != (macServiceInput{}) {
				t.Fatal("authority accepted from storage")
			}
			a.forgetMacServiceSelection()
			after, err := os.ReadFile(path)
			if err != nil || string(after) != data {
				t.Fatal("invalid file overwritten")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"profiles":[],"settings":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	a := NewWithAdapter(path, unavailableTestAdapter{})
	if a.LoadBlocked || a.Config.MacServiceSelection != nil {
		t.Fatal("legacy config broken")
	}
}

func TestMacSelectionNotExportedOrImported(t *testing.T) {
	a := macUIFixture(t)
	a.saveMacServiceSelection()
	p := core.Profile{ID: "ordinary", Name: "ordinary", Protocol: "anyconnect", Gateway: "https://other.example.test"}
	a.Config.Profiles = []core.Profile{p}
	for _, selected := range []*core.Profile{nil, &p} {
		path := filepath.Join(t.TempDir(), "export.json")
		if err := a.ExportProfiles(path, selected); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "mac_service_selection") || strings.Contains(string(data), "service-id") || strings.Contains(string(data), "10.2.3.4") {
			t.Fatal("export exposed local selection")
		}
		if a.Config.MacServiceSelection == nil || a.Config.MacServiceSelection.ServiceID != "service-id" {
			t.Fatal("export changed local selection")
		}
	}
	imported := core.Config{Version: 1, Profiles: []core.Profile{{ID: "new", Name: "new", Protocol: "anyconnect", Gateway: "https://new.example.test"}}, MacServiceSelection: &core.SavedMacServiceSelection{ServiceID: "foreign-service", Gateway: "foreign.example.test", Targets: []string{"10.9.8.7"}}}
	path := filepath.Join(t.TempDir(), "import.json")
	if err := (core.Store{Path: path}).Save(imported); err != nil {
		t.Fatal(err)
	}
	if err := a.ImportProfiles(path); err != nil {
		t.Fatal(err)
	}
	if a.Config.MacServiceSelection.ServiceID != "service-id" || a.macService.input.ID != "service-id" {
		t.Fatal("import replaced local selection")
	}
}
