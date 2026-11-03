package desktop

import (
	"fmt"
	"github.com/egoist/mygo"
	"mygo-vpn/internal/core"
)

func (a *App) chooseINIPreview() {
	if a.FileBusy || a.ShuttingDown {
		return
	}
	a.FileBusy = true
	title := a.tr("Inspect INI (read only)")
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: a.Window, Title: title, Filters: []mygo.FileFilter{{Name: "INI", Extensions: []string{"ini"}}}})
		var result core.INIPreview
		selected := err == nil && len(paths) > 0
		if selected {
			result, err = core.PreviewINIFile(paths[0])
		}
		mygo.RunOnMain(func() {
			a.FileBusy = false
			if a.ShuttingDown {
				return
			}
			if err != nil {
				a.Notice = a.tr("INI file cannot be safely read or parsed; nothing was changed")
			} else if selected {
				a.Notice = fmt.Sprintf(a.tr("Read-only INI: %d sections, %d entries. All names and values hidden. Vendor compatibility unverified; nothing imported."), result.Sections, result.Entries)
			}
			if a.Window != nil {
				a.Window.Invalidate()
			}
		})
	}()
}
