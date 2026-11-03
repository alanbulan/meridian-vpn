package desktop

import (
	"context"
	"errors"
	"mygo-vpn/internal/core"
	"path/filepath"
	"testing"
	"time"
)

type switchAdapter struct{ session *switchSession }

func (a switchAdapter) Capability() core.Capability { return core.Capability{Available: true} }
func (a switchAdapter) Start(context.Context, core.Profile, []byte) (core.Session, error) {
	return a.session, nil
}

type switchSession struct {
	ready     chan error
	done      chan error
	stopError error
}

func (s *switchSession) Ready() <-chan error { return s.ready }
func (s *switchSession) Done() <-chan error  { return s.done }
func (s *switchSession) Stop() error {
	if s.stopError != nil {
		return s.stopError
	}
	s.done <- nil
	return nil
}
func awaitState(t *testing.T, a *App, state string) {
	t.Helper()
	end := time.Now().Add(time.Second)
	for time.Now().Before(end) {
		if a.Engine.Snapshot().State == state {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state=%s want %s", a.Engine.Snapshot().State, state)
}
func TestSwitchWaitsForCleanupAndRequiresFreshAuthentication(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean", true: "failed"}[cleanupFails], func(t *testing.T) {
			s := &switchSession{ready: make(chan error, 1), done: make(chan error, 1)}
			if cleanupFails {
				s.stopError = errors.New("cleanup unknown")
			}
			a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), switchAdapter{s})
			a.Config.Profiles = []core.Profile{{ID: "a", Name: "First", Gateway: "https://a.example", Protocol: "anyconnect"}, {ID: "b", Name: "Second", Gateway: "https://b.example", Protocol: "anyconnect"}}
			a.Config.SelectedID = "a"
			if err := a.Engine.Connect(a.Config.Profiles[0], "synthetic", true); err != nil {
				t.Fatal(err)
			}
			s.ready <- nil
			awaitState(t, a, core.Connected)
			a.Password = "must-clear"
			a.KeyPassword = "must-clear"
			a.ProxyConsent = true
			a.Authorized = true
			a.beginSwitch("b")
			if a.Config.SelectedID != "a" || a.Password != "" || a.KeyPassword != "" || a.Authorized || a.ProxyConsent {
				t.Fatal("switch changed profile or retained credentials before cleanup")
			}
			want := core.Disconnected
			if cleanupFails {
				want = core.CleanupFailed
			}
			awaitState(t, a, want)
			a.pollSwitch()
			if cleanupFails {
				if a.Config.SelectedID != "a" || a.ConnectPanel {
					t.Fatal("unsafe switch after failed cleanup")
				}
			} else {
				if a.Config.SelectedID != "b" || !a.ConnectPanel || a.Authorized || a.Password != "" || a.GatewayChoice != "https://b.example" {
					t.Fatal("fresh authentication not opened")
				}
			}
		})
	}
}
func TestGatewayAndCertificateDraftPersistence(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), unavailableTestAdapter{})
	a.startEdit(nil)
	a.Draft.Name = "Office"
	a.Draft.Gateway = "https://one.example"
	a.AdditionalGatewaysText = "https://two.example https://three.example"
	a.saveDraft()
	if a.Editing {
		t.Fatal(a.Notice)
	}
	b := NewWithAdapter(a.Store.Path, unavailableTestAdapter{})
	if len(b.Config.Profiles[0].AdditionalGateways) != 2 {
		t.Fatal("gateway list not persisted")
	}
	b.startEdit(b.selected())
	if b.AdditionalGatewaysText != "https://two.example https://three.example" {
		t.Fatal("single-line gateway field must reload with spaces")
	}
	b.AdditionalGatewaysText = "http://invalid.example"
	b.saveDraft()
	if !b.Editing || b.Config.Profiles[0].AdditionalGateways[0] != "https://two.example" {
		t.Fatal("invalid gateway mutated saved profile")
	}
}

func TestCertificateFormatSwitchClearsIncompatibleReferences(t *testing.T) {
	a := &App{Draft: core.Profile{ClientCertificate: "/private/cert", ClientKey: "/private/key"}, KeyPassword: "secret"}
	generation := a.editorGeneration
	a.setCertificateFormat("pkcs12")
	if a.Draft.CertificateFormat != "pkcs12" || a.Draft.ClientCertificate != "" || a.Draft.ClientKey != "" || a.KeyPassword != "" || a.editorGeneration != generation+1 {
		t.Fatal("format switch retained stale state")
	}
	a.Draft.ClientCertificate = "/bundle.p12"
	a.setCertificateFormat("pkcs12")
	if a.Draft.ClientCertificate != "/bundle.p12" {
		t.Fatal("same format cleared reference")
	}
	a.setCertificateFormat("unsupported")
	if a.Draft.CertificateFormat != "pkcs12" {
		t.Fatal("accepted unknown format")
	}
}
func TestL2TPEditDoesNotMutateCommittedProfile(t *testing.T) {
	a := &App{}
	p := core.Profile{Protocol: "l2tp", Gateway: "vpn.example", L2TP: &core.L2TPOptions{Domain: "original"}}
	a.startEdit(&p)
	a.Draft.L2TP.Domain = "draft"
	if p.L2TP.Domain != "original" {
		t.Fatal("editing mutated original")
	}
	a.Config.Profiles = []core.Profile{p}
	copy := a.copyConfig()
	copy.Profiles[0].L2TP.Domain = "copy"
	if a.Config.Profiles[0].L2TP.Domain != "original" {
		t.Fatal("copy aliased original")
	}
}
func TestProtocolSwitchClearsTransportAndSecrets(t *testing.T) {
	a := &App{Draft: core.Profile{Protocol: "anyconnect", Gateway: "https://private.example", ClientCertificate: "/cert", ClientKey: "/key", ProxyURL: "http://proxy", InteractiveAuth: true}, IPsecPSK: "psk", Password: "password", KeyPassword: "pin"}
	a.setDraftProtocol("l2tp")
	if a.Draft.L2TP == nil || a.Draft.L2TP.PPPAuth != "mschapv2" || a.Draft.Gateway != "" || a.Draft.ClientCertificate != "" || a.Draft.ProxyURL != "" || a.Draft.InteractiveAuth || a.IPsecPSK != "" || a.Password != "" || a.KeyPassword != "" {
		t.Fatal("protocol switch leaked incompatible state")
	}
	a.IPsecPSK = "private"
	a.clearCredentials()
	if a.IPsecPSK != "" {
		t.Fatal("PSK survived dismissal")
	}
	if gatewayHost("vpn.example") != "vpn.example" {
		t.Fatal("bare gateway hidden")
	}
}

func TestL2TPNativeMRUPersistenceAndInvalidDraft(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), unavailableTestAdapter{})
	a.startEdit(nil)
	a.setDraftProtocol("l2tp")
	a.Draft.Name = "Test"
	a.Draft.Gateway = "vpn.example"
	a.MRUText = "1400"
	a.MTUText = "1380"
	a.saveDraft()
	if len(a.Config.Profiles) != 1 || a.Config.Profiles[0].L2TP.MRU != 1400 || a.Config.Profiles[0].MTU != 1380 {
		t.Fatalf("save failed: %s", a.Notice)
	}
	a.startEdit(&a.Config.Profiles[0])
	if a.MRUText != "1400" {
		t.Fatal("MRU draft not restored")
	}
	a.MRUText = "not-a-number"
	a.saveDraft()
	if !a.Editing || a.Config.Profiles[0].L2TP.MRU != 1400 {
		t.Fatal("invalid MRU changed saved configuration")
	}
}
