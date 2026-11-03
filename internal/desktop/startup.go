package desktop

import (
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/autostart"
)

func (a *App) initializeStartup() {
	manager, err := autostart.New(autostart.Options{})
	if err != nil {
		a.StartupError = "Startup settings are unavailable"
		return
	}
	a.Startup = manager
	a.StartupStatus, err = manager.Status()
	if err != nil {
		a.StartupError = "Existing startup entry cannot be safely managed"
	}
}
func (a *App) startupSettings(c *ui.Context) {
	ui.Column(c).FillWidth().Padding(16).Gap(10).Background(c.Theme().Surface).Border(1, c.Theme().Border).Radius(12).Children(func() {
		ui.Row(c).FillWidth().AlignItems(ui.Center).Children(func() {
			ui.Text(c, a.tr("Launch at login")).Grow(1)
			label := "Enable"
			if a.StartupStatus.Enabled {
				label = "Disable"
			}
			if ui.Button(c.Key("startup-request"), a.tr(label)).Disabled(a.Startup == nil || !a.StartupStatus.Supported || a.StartupError != "" || a.StartupBusy || a.ShuttingDown).Clicked() {
				a.StartupConfirm = true
			}
		})
		a.label(c, "Starts the application only; never automatically connects")
		if a.StartupError != "" {
			a.label(c, a.StartupError)
		}
		if a.Startup != nil && !a.StartupStatus.Supported {
			a.label(c, "Login startup is available on Linux only")
		}
		if a.StartupConfirm {
			a.label(c, "Confirm changing this user login entry?")
			ui.Text(c, a.StartupStatus.Path).FontSize(11).FillWidth()
			executable := a.StartupStatus.Executable
			if a.StartupStatus.Enabled && a.StartupStatus.RegisteredExecutable != "" {
				executable = a.StartupStatus.RegisteredExecutable
			}
			ui.Text(c, executable).FontSize(11).FillWidth()
			ui.Row(c).Gap(8).Children(func() {
				if ui.Button(c.Key("startup-cancel"), a.tr("Cancel")).Clicked() {
					a.StartupConfirm = false
				}
				if ui.Button(c.Key("startup-confirm"), a.tr("Confirm change")).Disabled(a.StartupBusy || a.ShuttingDown).Clicked() {
					a.changeStartup()
				}
			})
		}
	})
}
func (a *App) changeStartup() {
	if a.Startup == nil || a.StartupBusy || a.ShuttingDown || !a.StartupConfirm {
		return
	}
	a.StartupConfirm = false
	a.StartupBusy = true
	manager := a.Startup
	enabled := a.StartupStatus.Enabled
	go func() {
		var err error
		if enabled {
			err = manager.Disable()
		} else {
			err = manager.Enable()
		}
		status, statusErr := manager.Status()
		mygo.RunOnMain(func() {
			a.StartupBusy = false
			a.StartupStatus = status
			if err != nil || statusErr != nil {
				a.StartupError = "Startup entry change could not be confirmed; check the current status"
			} else {
				a.StartupError = ""
			}
			if a.Window != nil {
				a.Window.Invalidate()
			}
		})
	}()
}
