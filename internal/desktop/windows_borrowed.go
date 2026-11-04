package desktop

import (
	"context"
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
	"time"
)

// NewWindowsBorrowed is selected only by the explicit startup option. Adapter
// creation does not load RAS or query profiles; capability is a platform check.
func NewWindowsBorrowed(path string) *App {
	a := NewWithAdapter(path, core.NewWindowsBorrowedAdapter())
	a.WindowsBorrowedEnabled = true
	return a
}
func (a *App) platformAdapter() core.Adapter {
	if a.WindowsBorrowedEnabled {
		return core.NewWindowsBorrowedAdapter()
	}
	return defaultAdapter()
}
func (a *App) profileProtocols() []string {
	if a.WindowsBorrowedEnabled {
		return []string{core.WindowsBorrowedProtocol}
	}
	return core.Protocols
}
func (a *App) windowsBorrowedFields(c *ui.Context) {
	if a.Draft.WindowsBorrowed == nil {
		a.Draft.WindowsBorrowed = &core.WindowsBorrowedOptions{}
	}
	p := a.Draft.WindowsBorrowed
	a.windowsNotice(c, "Existing L2TP/IPsec Windows profile only; Meridian will not edit or delete it")
	a.windowsNotice(c, "Exact local phonebook path (.pbk)")
	ui.TextInput(c.Key("windows-phonebook"), &p.PhonebookPath).FillWidth()
	a.windowsNotice(c, "Exact Windows entry name")
	ui.TextInput(c.Key("windows-entry"), &p.EntryName).FillWidth()
	a.windowsNotice(c, "Account domain (optional)")
	ui.TextInput(c.Key("windows-domain"), &p.Domain).FillWidth()
	a.windowsNotice(c, "Enter the gateway supplied by your administrator; do not infer it from an unknown profile")
	a.windowsNotice(c, "No exclusive ownership, kill switch or full route/DNS leak protection; gateway compatibility is not yet validated")
}
func (a *App) windowsBorrowedConsent(c *ui.Context) {
	a.windowsNotice(c, "No exclusive ownership, kill switch or full route/DNS leak protection.")
	a.windowsNotice(c, "Experimental limited mode: Windows may cache credentials; other applications may share this connection")
	a.windowsNotice(c, "Cleanup uncertainty can retain password buffers and keep Meridian open until verified; no extra disconnect will target another reference")
	ui.Checkbox(c.Key("windows-persistence-consent"), &a.WindowsPersistenceConsent, "Allow Windows credential caching for this attempt")
	ui.Checkbox(c.Key("windows-shared-consent"), &a.WindowsSharedConsent, "Accept shared connections and limited verification")
}
func (a *App) windowsConsentReady(p *core.Profile) bool {
	return p == nil || p.Protocol != core.WindowsBorrowedProtocol || a.WindowsBorrowedEnabled && a.WindowsPersistenceConsent && a.WindowsSharedConsent
}
func (a *App) retryScopedCleanup() {
	if a.CleanupRetrying {
		return
	}
	a.CleanupRetrying = true
	a.clearCredentials()
	engine := a.Engine
	windowsAttempt := a.windowsOwnsAttempt(engine.Snapshot())
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err := engine.RetryCleanup(ctx)
		mygo.RunOnMain(func() {
			a.CleanupRetrying = false
			if err != nil {
				if windowsAttempt {
					a.Notice = "Cleanup remains unconfirmed. Inspect the connection in Windows; Meridian will not release another application's reference."
				} else {
					a.Notice = "Selected system service cleanup remains unconfirmed; keep Meridian open and inspect that service."
				}
			} else {
				a.Notice = engine.Snapshot().Message
			}
			if a.Window != nil {
				a.Window.Invalidate()
			}
		})
	}()
}

func (a *App) windowsNotice(c *ui.Context, text string) {
	ui.Text(c, text).FontSize(12).TextColor(c.Theme().TextMuted).FillWidth().Wrap()
}

func (a *App) windowsOwnsAttempt(s core.Snapshot) bool {
	return a.windowsActiveProfile != nil && a.windowsActiveAttemptID != 0 && a.windowsActiveAttemptID == s.AttemptID
}
