package desktop

import (
	"context"
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
	"path/filepath"
	"testing"
	"time"
)

func TestGatewayChangeClearsSecretsAndConsent(t *testing.T) {
	s := &switchSession{ready: make(chan error, 1), done: make(chan error, 1)}
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), switchAdapter{s})
	a.Config.Settings.Language = "en"
	a.Config.Profiles = []core.Profile{{ID: "office", Name: "Office", Gateway: "https://first.example", AdditionalGateways: []string{"https://second.example"}, Protocol: "anyconnect"}}
	a.Config.SelectedID = "office"
	a.openConnectForm()
	a.Password, a.KeyPassword, a.IPsecPSK = "password", "pin", "psk"
	a.Authorized, a.ProxyConsent = true, true
	for _, unchanged := range []string{"https://first.example", "https://foreign.example"} {
		a.selectSessionGateway(unchanged)
		if a.GatewayChoice != "https://first.example" || a.Password != "password" || a.KeyPassword != "pin" || a.IPsecPSK != "psk" || !a.Authorized || !a.ProxyConsent {
			t.Fatal("unchanged or invalid gateway changed the existing form")
		}
	}
	a.selectSessionGateway("https://second.example")
	if a.GatewayChoice != "https://second.example" || !a.ConnectPanel || a.Password != "" || a.KeyPassword != "" || a.IPsecPSK != "" || a.Authorized || a.ProxyConsent {
		t.Fatal("gateway change retained old credentials/authorization or closed the form")
	}
	v := ui.NewTester(a.connectForm, 700, 700)
	if err := v.Click("Connect"); err != nil {
		t.Fatal(err)
	}
	if a.Engine.Snapshot().State != core.Disconnected || !a.ConnectPanel {
		t.Fatal("new gateway connected without renewed authorization")
	}
	a.Password = "new-gateway-only"
	a.selectSessionGateway("https://first.example")
	if a.Password != "" || a.Authorized || a.ProxyConsent || a.GatewayChoice != "https://first.example" {
		t.Fatal("returning to the initial gateway resurrected secrets or consent")
	}
	if err := v.Click("Cancel"); err != nil {
		t.Fatal(err)
	}
	if a.ConnectPanel || a.GatewayChoice != "" || a.Password != "" || a.Authorized || a.ProxyConsent {
		t.Fatal("cancel retained gateway authentication state")
	}
}

type recoveryTargetAdapter struct {
	session *switchSession
	targets chan string
}

func (a recoveryTargetAdapter) Capability() core.Capability {
	return core.Capability{Available: true}
}
func (a recoveryTargetAdapter) Start(_ context.Context, p core.Profile, _ []byte) (core.Session, error) {
	a.targets <- p.Gateway
	return a.session, nil
}

func backupGatewayLoss(t *testing.T) (*App, chan string) {
	t.Helper()
	s := &switchSession{ready: make(chan error, 1), done: make(chan error, 1)}
	targets := make(chan string, 2)
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), recoveryTargetAdapter{s, targets})
	a.Config.Settings.Language = "en"
	a.Config.Settings.ReauthOnLoss = true
	a.Config.Profiles = []core.Profile{{ID: "office", Name: "Office", Gateway: "https://primary.example", AdditionalGateways: []string{"https://backup.example"}, Protocol: "anyconnect"}}
	a.Config.SelectedID = "office"
	a.openConnectForm()
	a.selectSessionGateway("https://backup.example")
	a.Password, a.Authorized = "synthetic-first", true
	v := ui.NewTester(a.connectForm, 700, 700)
	if !v.HasText("https://backup.example") {
		t.Fatal("form did not show the exact authorized target")
	}
	if err := v.Click("Connect"); err != nil {
		t.Fatal(err)
	}
	s.ready <- nil
	awaitState(t, a, core.Connected)
	if got := <-targets; got != "https://backup.example" {
		t.Fatal("initial GUI attempt used the wrong gateway", got)
	}
	if a.Password != "" || a.Authorized || a.ConnectPanel {
		t.Fatal("submission retained credentials or consent")
	}
	now := time.Now()
	a.pollReauthentication(now)
	s.done <- core.NewConnectionError(core.FailureTransport)
	awaitState(t, a, core.Failed)
	a.pollReauthentication(now)
	a.pollReauthentication(now.Add(6 * time.Second))
	if !a.reauthVisible {
		t.Fatal("test did not establish a loss reminder")
	}
	return a, targets
}

func TestBackupGatewayRecoveryRequiresFreshAuthAtSameTarget(t *testing.T) {
	a, targets := backupGatewayLoss(t)
	a.Password, a.KeyPassword, a.IPsecPSK = "must-clear", "must-clear", "must-clear"
	a.Authorized, a.ProxyConsent = true, true
	v := ui.NewTester(a.reauthenticationNotice, 700, 700)
	if err := v.Click("Sign in again"); err != nil {
		t.Fatal(err)
	}
	if !a.ConnectPanel || a.GatewayChoice != "https://backup.example" || a.Password != "" || a.KeyPassword != "" || a.IPsecPSK != "" || a.Authorized || a.ProxyConsent {
		t.Fatal("recovery changed the target or retained authentication")
	}
	form := ui.NewTester(a.connectForm, 700, 700)
	if !form.HasText("https://backup.example") {
		t.Fatal("recovery form hid its target")
	}
	if err := form.Click("Connect"); err != nil {
		t.Fatal(err)
	}
	if a.Engine.Snapshot().State != core.Failed || len(targets) != 0 {
		t.Fatal("recovery started without fresh authorization")
	}
	a.Password, a.Authorized = "synthetic-fresh", true
	form.Frame()
	if err := form.Click("Connect"); err != nil {
		t.Fatal(err)
	}
	select {
	case target := <-targets:
		if target != "https://backup.example" {
			t.Fatal("recovery silently fell back to the primary gateway", target)
		}
	case <-time.After(time.Second):
		t.Fatal("fresh authorized GUI attempt did not reach the fake backend")
	}
	if err := a.Engine.Disconnect(); err != nil {
		t.Fatal(err)
	}
	awaitState(t, a, core.Disconnected)
}

func TestRecoveryNeverFallsBackFromInvalidSessionTarget(t *testing.T) {
	for _, mode := range []string{"removed", "other-profile", "stale-attempt", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			a, targets := backupGatewayLoss(t)
			switch mode {
			case "removed":
				a.Config.Profiles[0].AdditionalGateways = nil
			case "other-profile":
				a.sessionTarget.profileID = "other"
			case "stale-attempt":
				a.sessionTarget.attemptID++
			case "disabled":
				a.Config.Settings.ReauthOnLoss = false
			}
			a.openRecoveryForm()
			if a.ConnectPanel || a.reauthVisible || a.Authorized || a.GatewayChoice != "" || a.Notice == "" || len(targets) != 0 {
				t.Fatal("invalid recovery target silently opened or connected a replacement")
			}
			a.openConnectForm()
			if !a.ConnectPanel || a.GatewayChoice != "https://primary.example" || a.Authorized {
				t.Fatal("ordinary explicit connection flow became unavailable")
			}
		})
	}
}

func TestSubmissionRechecksConfiguredGatewayAndConsent(t *testing.T) {
	for _, mode := range []string{"removed", "network-consent", "proxy-consent"} {
		t.Run(mode, func(t *testing.T) {
			a, targets := backupGatewayLoss(t)
			a.openRecoveryForm()
			a.Password, a.Authorized = "synthetic-fresh", true
			switch mode {
			case "removed":
				a.Config.Profiles[0].AdditionalGateways = nil
			case "network-consent":
				a.Authorized = false
			case "proxy-consent":
				a.Config.Profiles[0].ProxyURL = "http://proxy.example:8080"
			}
			a.submitConnection()
			if a.Engine.Snapshot().State != core.Failed || len(targets) != 0 || a.Password != "" || a.Authorized || a.ConnectPanel || a.Notice == "" {
				t.Fatal("submission accepted stale target/consent or retained secrets")
			}
		})
	}
}
