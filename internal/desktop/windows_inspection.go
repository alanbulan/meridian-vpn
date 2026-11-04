package desktop

import (
	"fmt"
	"runtime"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"
	"mygo-vpn/internal/core"
	"mygo-vpn/internal/windowsvpn"
)

// Inspection is an optional metadata observation, never a readiness or consent
// token. Only the UI thread owns this state. A native read cannot be canceled by
// closing the form, so running stays set until the original worker returns.
type windowsInspectionUI struct {
	acknowledged bool
	running      bool
	generation   uint64
	message      string
}

func (s *windowsInspectionUI) reset() {
	s.acknowledged = false
	s.message = ""
	s.generation++
}

func (a *App) windowsInspectionForm(c *ui.Context) {
	a.windowsNotice(c, "Optional profile check before entering a password. This reads the selected Windows VPN configuration and matching connections. Loading RAS may start its Windows service. It does not dial, disconnect or read credentials.")
	ui.Checkbox(c.Key("windows-inspection-consent"), &a.windowsInspection.acknowledged, "Allow RAS service startup for this check").Disabled(a.windowsInspection.running)
	if ui.Button(c.Key("windows-inspect-profile"), "Check existing Windows profile").Disabled(!a.windowsInspection.acknowledged || a.windowsInspection.running || a.LoadBlocked || a.ShuttingDown || a.Checking || a.busy() || a.Engine.Snapshot().State == core.CleanupFailed).Clicked() {
		a.beginWindowsInspection()
	}
	if a.windowsInspection.running {
		a.windowsNotice(c, "Waiting for the Windows read-only query. Closing this form discards its result, but cannot cancel the native query. Connecting is disabled until it returns.")
	} else if a.windowsInspection.message != "" {
		a.windowsNotice(c, a.windowsInspection.message)
	}
}

func (a *App) beginWindowsInspection() {
	p := a.selected()
	if !a.WindowsBorrowedEnabled || !a.ConnectPanel || p == nil || p.Protocol != core.WindowsBorrowedProtocol || core.ValidateProfile(*p) != nil || !a.windowsInspection.acknowledged || a.windowsInspection.running || a.LoadBlocked || a.ShuttingDown || a.Checking || a.busy() || a.Engine.Snapshot().State == core.CleanupFailed {
		return
	}
	a.windowsInspection.acknowledged = false // This click consumes this read's consent.
	a.windowsInspection.message = ""
	if runtime.GOOS != "windows" {
		a.windowsInspection.message = "This profile check is available only on Windows."
		return
	}
	selection := windowsvpn.PhonebookEntry{PhonebookPath: p.WindowsBorrowed.PhonebookPath, Name: p.WindowsBorrowed.EntryName}
	gateway, profileID := p.Gateway, p.ID
	generation := a.windowsInspection.generation
	a.windowsInspection.running = true
	go func() {
		message := inspectWindowsProfile(selection, gateway)
		mygo.RunOnMain(func() {
			a.windowsInspection.running = false
			current := a.selected()
			if !a.ShuttingDown && a.ConnectPanel && generation == a.windowsInspection.generation && current != nil && current.Protocol == core.WindowsBorrowedProtocol && current.WindowsBorrowed != nil && current.ID == profileID && current.Gateway == gateway && current.WindowsBorrowed.PhonebookPath == selection.PhonebookPath && current.WindowsBorrowed.EntryName == selection.Name {
				a.windowsInspection.message = message
			}
			if a.Window != nil {
				a.Window.Invalidate()
			}
		})
	}()
}

func inspectWindowsProfile(selection windowsvpn.PhonebookEntry, gateway string) (message string) {
	// No raw native error, private path, entry name, account or handle enters UI
	// messages or logs. Native ownership remains with the synchronous call.
	message = "Windows profile inspection did not complete. No connection was attempted."
	defer func() {
		if recover() != nil {
			message = "Windows profile inspection did not complete. No connection was attempted."
		}
	}()
	evidence, err := windowsvpn.InspectSystemEntry(selection, gateway)
	if err != nil {
		return "Profile metadata could not be verified. Check the local phonebook path, exact entry, independent gateway and supported L2TP/IPsec settings. No connection was attempted."
	}
	snapshot, err := windowsvpn.ObserveSystemConnections(evidence)
	if err != nil {
		return "Profile metadata matched, but existing connections could not be verified. No connection was attempted."
	}
	if count := snapshot.ObservedConnections(); count != 0 {
		return fmt.Sprintf("Profile metadata matched; %d matching connection(s) were observed. Meridian will not adopt or disconnect them. Resolve existing connections in Windows before connecting. This was not a tunnel or route/DNS test.", count)
	}
	return "Profile metadata matched and no matching connections were observed at this moment. This is not proof of exclusive ownership, connectivity or route/DNS protection. Connecting still requires fresh consent and repeats validation."
}
