package desktop

import (
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
)

func (a *App) openConnectForm() {
	a.clearReauthentication()
	a.clearCredentials()
	if p := a.selected(); p != nil {
		a.GatewayChoice = p.Gateway
	}
	a.ConnectPanel = true
	a.Page = "Overview"
}

// Credentials and consent belong to the exact gateway shown when entered.
// Changing the dropdown cannot carry them to another gateway in the profile.
func (a *App) selectSessionGateway(gateway string) {
	if gateway == a.GatewayChoice {
		return
	}
	p := a.selected()
	if p == nil {
		return
	}
	if !gatewayAllowed(p, gateway) {
		return
	}
	a.clearCredentials()
	a.GatewayChoice = gateway
	a.ConnectPanel = true
}

func gatewayAllowed(p *core.Profile, gateway string) bool {
	if p == nil || gateway == "" {
		return false
	}
	if gateway == p.Gateway {
		return true
	}
	for _, other := range p.AdditionalGateways {
		if gateway == other {
			return true
		}
	}
	return false
}

// Every GUI attempt records the exact admitted target after fresh consent.
// Validating the target again prevents a stale form from selecting an endpoint
// removed from the profile while the form was open.
func (a *App) submitConnection() {
	defer a.clearCredentials()
	p := a.selected()
	if !a.canConnect(p) || !a.Authorized || !a.windowsConsentReady(p) || !gatewayAllowed(p, a.GatewayChoice) || (p.ProxyURL != "" && !a.ProxyConsent) {
		a.Notice = "Review the connection and authorize network changes before connecting"
		return
	}
	sessionProfile := *p
	sessionProfile.AllowProxySystemAuth = a.ProxyConsent
	sessionProfile.Gateway = a.GatewayChoice
	sessionProfile.AdditionalGateways = nil
	credentials := core.Credentials{Password: []byte(a.Password), KeyPassword: []byte(a.KeyPassword), IPsecPSK: []byte(a.IPsecPSK)}
	var err error
	if sessionProfile.Protocol == core.WindowsBorrowedProtocol {
		err = a.Engine.ConnectWithAuthorization(sessionProfile, credentials, core.SessionAuthorization{NetworkChanges: a.Authorized, WindowsCredentialPersistence: a.WindowsPersistenceConsent, WindowsSharedReference: a.WindowsSharedConsent})
	} else {
		err = a.Engine.ConnectWithCredentials(sessionProfile, credentials, a.Authorized)
	}
	clear(credentials.Password)
	clear(credentials.KeyPassword)
	clear(credentials.IPsecPSK)
	if err != nil {
		a.Notice = err.Error()
		return
	}
	if sessionProfile.Protocol == core.WindowsBorrowedProtocol {
		owned := sessionProfile
		options := *sessionProfile.WindowsBorrowed
		owned.WindowsBorrowed = &options
		a.windowsActiveProfile = &owned
		a.windowsActiveAttemptID = a.Engine.Snapshot().AttemptID
	}
	a.sessionTarget = sessionTarget{attemptID: a.Engine.Snapshot().AttemptID, profileID: p.ID, gateway: sessionProfile.Gateway}
	a.Notice = ""
}

// Recovery stays on the lost session's explicitly chosen gateway. It opens a
// blank form, never retries or transfers authorization. If that target is no
// longer configured, the ordinary manual connection flow remains available.
func (a *App) openRecoveryForm() {
	if a.macServiceOwnsAttempt(a.Engine.Snapshot()) || a.windowsOwnsAttempt(a.Engine.Snapshot()) {
		a.clearReauthentication()
		return
	}
	target := a.sessionTarget
	snapshot := a.Engine.Snapshot()
	p := a.selected()
	if !a.canConnect(p) || !a.Config.Settings.ReauthOnLoss || a.SwitchPending || !a.reauthVisible || snapshot.State != core.Failed || (snapshot.Failure != core.FailureConnectionLost && snapshot.Failure != core.FailureTransport) || target.attemptID != snapshot.AttemptID || target.attemptID != a.reauthAttemptID || p == nil || target.profileID != p.ID || !gatewayAllowed(p, target.gateway) {
		a.clearReauthentication()
		a.clearCredentials()
		a.Notice = "The previous session gateway is unavailable; choose a connection and sign in again"
		return
	}
	a.openConnectForm()
	a.selectSessionGateway(target.gateway)
	a.Notice = ""
}

// Switching never carries credentials or proxy consent to another connection.
// The next authentication form opens only after the old tunnel's cleanup succeeds.
func (a *App) beginSwitch(id string) {
	if a.ShuttingDown || a.SwitchPending || a.Engine.Snapshot().State != core.Connected || a.macServiceOwnsAttempt(a.Engine.Snapshot()) || a.windowsOwnsAttempt(a.Engine.Snapshot()) {
		return
	}
	found := false
	for _, p := range a.Config.Profiles {
		if p.ID == id && p.ID != a.Config.SelectedID {
			found = true
		}
	}
	if !found {
		return
	}
	a.clearCredentials()
	a.SwitchID = id
	if err := a.Engine.Disconnect(); err != nil {
		a.Notice = err.Error()
		a.SwitchID = ""
		return
	}
	a.SwitchPending = true
}
func (a *App) pollSwitch() {
	if !a.SwitchPending || a.ShuttingDown {
		return
	}
	state := a.Engine.Snapshot().State
	if state == core.Disconnecting || state == core.Connected {
		return
	}
	id := a.SwitchID
	a.SwitchPending = false
	a.SwitchID = ""
	if state != core.Disconnected {
		a.Notice = "Connection switch stopped because cleanup was not confirmed"
		return
	}
	cfg := a.copyConfig()
	found := false
	for _, p := range cfg.Profiles {
		if p.ID == id {
			found = true
		}
	}
	if !found {
		return
	}
	cfg.SelectedID = id
	if a.commit(cfg) {
		a.openConnectForm()
	}
}
func (a *App) clientCertificateFields(c *ui.Context) {
	a.label(c, "Certificate format")
	format := a.Draft.CertificateFormat
	if format == "" {
		format = "pem"
	}
	selected := format
	ui.Select(c.Key("certificate-format"), &selected, []string{"pem", "pkcs12", "pkcs11"}).FillWidth()
	if selected != format {
		a.setCertificateFormat(selected)
	}
	switch selected {
	case "pkcs11":
		a.label(c, "PKCS#11 certificate URI")
		ui.TextInput(c.Key("client-certificate"), &a.Draft.ClientCertificate).FillWidth()
		a.label(c, "PKCS#11 private key URI (optional)")
		ui.TextInput(c.Key("client-key"), &a.Draft.ClientKey).FillWidth()
		a.label(c, "Token provider must already be configured; PIN is requested per session")
	case "pkcs12":
		a.label(c, "Client certificate bundle (PKCS#12)")
		ui.Row(c).FillWidth().Gap(8).Children(func() {
			ui.TextInput(c.Key("client-certificate"), &a.Draft.ClientCertificate).Grow(1)
			if iconButton(c, "choose-client-cert", a.tr("Choose client certificate"), icons["import"]).Disabled(a.FileBusy).Clicked() {
				a.chooseClientFile(false)
			}
		})
	default:
		a.label(c, "Client certificate (PEM)")
		ui.Row(c).FillWidth().Gap(8).Children(func() {
			ui.TextInput(c.Key("client-certificate"), &a.Draft.ClientCertificate).Grow(1)
			if iconButton(c, "choose-client-cert", a.tr("Choose client certificate"), icons["import"]).Disabled(a.FileBusy).Clicked() {
				a.chooseClientFile(false)
			}
		})
		a.label(c, "Client private key (PEM)")
		ui.Row(c).FillWidth().Gap(8).Children(func() {
			ui.TextInput(c.Key("client-key"), &a.Draft.ClientKey).Grow(1)
			if iconButton(c, "choose-client-key", a.tr("Choose private key"), icons["import"]).Disabled(a.FileBusy).Clicked() {
				a.chooseClientFile(true)
			}
		})
	}
	a.label(c, "Only file references are saved; key passphrase is requested per session")
}

func (a *App) setCertificateFormat(format string) {
	if format != "pem" && format != "pkcs12" && format != "pkcs11" {
		return
	}
	old := a.Draft.CertificateFormat
	if old == "" {
		old = "pem"
	}
	if old == format {
		return
	}
	a.Draft.CertificateFormat = format
	a.Draft.ClientCertificate = ""
	a.Draft.ClientKey = ""
	a.KeyPassword = ""
	// Invalidate an outstanding picker started for the previous format.
	a.editorGeneration++
}
func (a *App) chooseClientFile(key bool) {
	if a.FileBusy || a.ShuttingDown {
		return
	}
	a.FileBusy = true
	generation := a.editorGeneration
	format := a.Draft.CertificateFormat
	filters := []mygo.FileFilter{{Name: "PEM", Extensions: []string{"pem", "crt", "cer", "key"}}}
	if format == "pkcs12" {
		filters = []mygo.FileFilter{{Name: "PKCS#12", Extensions: []string{"p12", "pfx"}}}
	}
	title := a.tr("Choose client certificate")
	if key {
		title = a.tr("Choose private key")
	}
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: a.Window, Title: title, Filters: filters})
		mygo.RunOnMain(func() {
			if err == nil && len(paths) > 0 && !a.ShuttingDown && a.Editing && a.editorGeneration == generation {
				if key {
					a.Draft.ClientKey = paths[0]
				} else {
					a.Draft.ClientCertificate = paths[0]
				}
			}
			a.fileResult(err)
		})
	}()
}

// OpenConnectionFromTray only opens the same fresh-authentication workflow.
func (a *App) OpenConnectionFromTray() {
	if a.ShuttingDown {
		return
	}
	if a.Window != nil {
		a.Window.Show()
		a.Window.Focus()
	}
	if a.canConnect(a.selected()) {
		a.openConnectForm()
	} else {
		a.Page = "Overview"
	}
}
func (a *App) DisconnectFromTray() {
	if a.ShuttingDown {
		return
	}
	a.SwitchPending = false
	a.SwitchID = ""
	a.clearCredentials()
	if err := a.Engine.Disconnect(); err != nil {
		a.Notice = err.Error()
	}
	if a.Window != nil {
		a.Window.Invalidate()
	}
}
