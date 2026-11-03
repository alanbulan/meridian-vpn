package desktop

import (
	"mygo-vpn/internal/core"
	"path/filepath"
	"testing"
)

func TestUniVPNGUIUnavailableWithoutExplicitBroker(t *testing.T) {
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), core.ProtocolRouter{Primary: unavailableTestAdapter{}, UniVPN: &core.UniVPN{}})
	p := core.Profile{Protocol: "univpn", Gateway: "https://vpn.example.invalid", Name: "Experimental"}
	if a.canConnect(&p) || a.supportsProtocol("univpn") {
		t.Fatal("unconfigured experimental broker advertised ready")
	}
	a.startEdit(&p)
	a.Draft.ProxyURL = "http://proxy.example.invalid"
	a.saveDraft()
	if len(a.Config.Profiles) != 0 || !a.Editing {
		t.Fatal("unsupported UniVPN proxy profile saved")
	}
}
