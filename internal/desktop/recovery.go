package desktop

import (
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
	"time"
)

func (a *App) clearReauthentication() {
	a.reauthAt = time.Time{}
	a.reauthProfileID = ""
	a.reauthVisible = false
	a.observedConnected = false
}

// This is a bounded reminder, NOT an automatic credential replay/reconnect.
func (a *App) pollReauthentication(now time.Time) {
	snapshot := a.Engine.Snapshot()
	state := snapshot.State
	if a.ShuttingDown || !a.Config.Settings.ReauthOnLoss || state == core.CleanupFailed || a.SwitchPending {
		a.clearReauthentication()
		return
	}
	// Known authentication/trust/configuration failures need investigation, not
	// another sign-in nudge. The normal explicit Connect action remains available.
	if state == core.Failed && snapshot.Failure != core.FailureConnectionLost && snapshot.Failure != core.FailureTransport {
		a.clearReauthentication()
		return
	}
	if state == core.Connected {
		a.observedConnected = true
		a.reauthProfileID = a.Config.SelectedID
		return
	}
	if state == core.Disconnected {
		a.clearReauthentication()
		return
	}
	if state == core.Failed && a.observedConnected {
		a.observedConnected = false
		a.reauthAt = now.Add(5 * time.Second)
	}
	if !a.reauthAt.IsZero() && !now.Before(a.reauthAt) {
		a.reauthAt = time.Time{}
		if state == core.Failed && a.reauthProfileID == a.Config.SelectedID {
			a.reauthVisible = true
		}
	}
}
func (a *App) reauthenticationNotice(c *ui.Context) {
	if !a.reauthVisible {
		return
	}
	if a.reauthProfileID != a.Config.SelectedID || a.Engine.Snapshot().State != core.Failed {
		a.clearReauthentication()
		return
	}
	ui.Column(c).FillWidth().Padding(12).Gap(8).Background(a.soft()).Radius(8).Children(func() {
		a.label(c, "Connection lost; cleanup completed. Sign in again?")
		ui.Row(c).Gap(8).Children(func() {
			if ui.Button(c.Key("retry-fresh-auth"), a.tr("Sign in again")).Disabled(!a.canConnect(a.selected())).Clicked() {
				a.openConnectForm()
			}
			if ui.Button(c.Key("dismiss-reauth"), a.tr("Dismiss")).Clicked() {
				a.clearReauthentication()
			}
		})
	})
}
