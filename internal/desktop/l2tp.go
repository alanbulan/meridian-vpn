package desktop

import (
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
)

func (a *App) l2tpFields(c *ui.Context) {
	if a.Draft.L2TP == nil {
		a.Draft.L2TP = &core.L2TPOptions{}
	}
	p := a.Draft.L2TP
	a.label(c, "L2TP/IPsec requires a host or IP, not an HTTPS URL")
	a.label(c, "PPP authentication")
	if p.PPPAuth == "" {
		p.PPPAuth = "mschapv2"
	}
	ui.Select(c.Key("ppp-auth"), &p.PPPAuth, []string{"mschapv2", "chap", "pap"}).FillWidth()
	a.label(c, "PPP domain (optional)")
	ui.TextInput(c.Key("ppp-domain"), &p.Domain).FillWidth()
	a.label(c, "IPsec remote identity (optional)")
	ui.TextInput(c.Key("ipsec-id"), &p.RemoteID).FillWidth()
	a.label(c, "IKE proposals (blank = system default)")
	ui.TextInput(c.Key("ipsec-ike"), &p.IKE).FillWidth()
	a.label(c, "ESP proposals (blank = system default)")
	ui.TextInput(c.Key("ipsec-esp"), &p.ESP).FillWidth()
	ui.Checkbox(c.Key("ipsec-encap"), &p.ForceEncapsulation, a.tr("Force IPsec encapsulation"))
	a.label(c, "MTU (blank = automatic)")
	ui.TextInput(c.Key("mtu"), &a.MTUText).FillWidth()
	a.label(c, "MRU (blank = automatic)")
	ui.TextInput(c.Key("mru"), &a.MRUText).FillWidth()
	a.label(c, "IPsec PSK is requested per session and is never stored")
}
func (a *App) setDraftProtocol(protocol string) {
	if a.Draft.Protocol == protocol {
		return
	}
	a.Draft.Protocol = protocol
	a.Draft.Gateway = ""
	a.Draft.AdditionalGateways = nil
	a.AdditionalGatewaysText = ""
	a.Draft.L2TP = nil
	a.MRUText = ""
	a.Draft.ClientCertificate = ""
	a.Draft.ClientKey = ""
	a.Draft.CertificateFormat = ""
	a.Draft.CAFile = ""
	a.Draft.AuthGroup = ""
	a.Draft.ProxyURL = ""
	a.Draft.InteractiveAuth = false
	a.Draft.DisableUDP = false
	a.clearCredentials()
	a.editorGeneration++
	if protocol == "l2tp" {
		a.Draft.L2TP = &core.L2TPOptions{PPPAuth: "mschapv2"}
	}
}

// Production adapters advertise protocol-specific readiness; injected legacy
// adapters retain their original AnyConnect-only test contract.
func (a *App) supportsProtocol(protocol string) bool {
	if adapter, ok := a.Adapter.(interface{ SupportsProtocol(string) bool }); ok {
		return adapter.SupportsProtocol(protocol)
	}
	return protocol == "anyconnect"
}
