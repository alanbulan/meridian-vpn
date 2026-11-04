package desktop

import (
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
	"path/filepath"
	"testing"
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
