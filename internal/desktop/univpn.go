package desktop

import (
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
)

func defaultAdapter() core.Adapter {
	return core.ProtocolRouter{Primary: core.NewNetworkManager(), UniVPN: &core.UniVPN{}}
}
func (a *App) univpnFields(c *ui.Context) {
	a.label(c, "Experimental UniVPN: direct TLS password authentication only")
	a.label(c, "A reviewed native engine and trusted continuous-session broker must be explicitly configured")
	a.label(c, "Authentication domain (blank = gateway host)")
	ui.TextInput(c.Key("auth-group"), &a.Draft.AuthGroup).FillWidth()
	a.label(c, "Custom CA certificate")
	ui.Row(c).FillWidth().Gap(8).Children(func() {
		ui.TextInput(c.Key("ca-file"), &a.Draft.CAFile).Grow(1)
		if iconButton(c, "choose-ca", a.tr("Choose CA certificate"), icons["import"]).Disabled(a.FileBusy).Clicked() {
			a.chooseCA()
		}
	})
	a.label(c, "MTU (blank = automatic)")
	ui.TextInput(c.Key("mtu"), &a.MTUText).FillWidth()
	a.label(c, "Proxy, client certificates and interactive MFA are not supported by this experimental transport")
}
