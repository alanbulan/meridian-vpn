package desktop

import "github.com/egoist/mygo/ui"

// Reference fields stay discoverable without presenting unimplemented controls.
func (a *App) support(c *ui.Context) {
	t := c.Theme()
	ui.Text(c, a.tr("Capabilities & reference fields")).FontSize(18).Bold()
	a.label(c, "Reference: LeagSoft UniVPN 20260903; exact deployed version unconfirmed")
	sections := []struct{ title, ready, pending string }{
		{"Connection types", "Linux AnyConnect and L2TP/IPsec adapters via NetworkManager", "LeagSoft SSL VPN, national crypto and QUIC have no verified production support"},
		{"Authentication", "Password, PEM/PKCS#12/PKCS#11 reference handling, custom CA and optional MFA helper", "PKCS#12 unlock and hardware token use still require real-client validation; SSO/posture and password change remain unsupported"},
		{"Connection policy", "Up to 16 explicit gateways, safe switching and fresh-authentication loss reminder", "Automatic gateway failover/reconnect/login and saved passwords are not implemented"},
		{"Transport", "HTTP/SOCKS proxy with fresh consent, MTU, TCP-only mode", "System proxy, embedded proxy credentials and proprietary TLS options are not supported"},
		{"Diagnostics & files", "Interface metrics, redacted diagnostics, profiles, CLI and opt-in Linux login startup", "Proprietary import, full system reports and automatic updates remain unsupported"},
	}
	for _, section := range sections {
		s := section
		ui.Column(c).FillWidth().Padding(16).Gap(9).Background(t.Background).Radius(10).Children(func() {
			ui.Text(c, a.tr(s.title)).FontSize(13).Bold()
			ui.Text(c, a.tr(s.ready)).FontSize(12).FillWidth()
			ui.Text(c, a.tr(s.pending)).FontSize(12).TextColor(t.TextMuted).FillWidth()
		})
	}
	a.label(c, "A configured protocol is not proof of enterprise gateway interoperability")
}
