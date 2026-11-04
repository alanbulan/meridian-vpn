package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/egoist/mygo"
	"mygo-vpn/internal/core"
	"os"
	"path/filepath"
	"reflect"
)

// ImportProfiles accepts only the versioned Meridian schema, never shell hooks or
// proprietary UniVPN configuration. Existing profiles/settings are preserved.
func (a *App) ImportProfiles(path string) error {
	if a.busy() || a.ShuttingDown {
		return errors.New("configuration changes are unavailable while a connection is active")
	}
	if info, err := os.Lstat(path); err != nil {
		return err
	} else if !info.Mode().IsRegular() {
		return errors.New("import requires a regular JSON file")
	}
	imported, err := (core.Store{Path: path}).Load()
	if err != nil {
		return err
	}
	cfg := a.copyConfig()
	added := 0
	for _, p := range imported.Profiles {
		p.AllowProxySystemAuth = false
		duplicate := false
		for _, existing := range cfg.Profiles {
			x, y := p, existing
			x.ID = ""
			y.ID = ""
			x.AllowProxySystemAuth = false
			y.AllowProxySystemAuth = false
			if reflect.DeepEqual(x, y) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		p.ID = core.NewID()
		if err := cfg.Upsert(p); err != nil {
			return err
		}
		added++
	}
	if added == 0 {
		a.Notice = a.tr("No new profiles to import")
		return nil
	}
	if !a.commit(cfg) {
		return errors.New(a.Notice)
	}
	a.Notice = fmt.Sprintf(a.tr("Imported %d connections"), added)
	return nil
}
func (a *App) ExportProfiles(path string, selected *core.Profile) error {
	if sameFilePath(path, a.Store.Path) {
		return errors.New("export cannot replace the active configuration file")
	}
	cfg := a.copyConfig()
	if selected != nil {
		cfg.Profiles = []core.Profile{*selected}
		cfg.SelectedID = selected.ID
	}
	for i := range cfg.Profiles {
		cfg.Profiles[i].AllowProxySystemAuth = false
	}
	cfg.Settings = core.Settings{}
	// Device-local remembered service expectations are not portable profiles.
	cfg.MacServiceSelection = nil
	return (core.Store{Path: path}).Save(cfg)
}
func sameFilePath(a, b string) bool {
	aa, e := filepath.Abs(a)
	bb, f := filepath.Abs(b)
	if e != nil || f != nil {
		return true
	}
	if aa == bb {
		return true
	}
	sa, e := os.Stat(a)
	sb, f := os.Stat(b)
	return e == nil && f == nil && os.SameFile(sa, sb)
}
func (a *App) ExportActivity(path string) error {
	if sameFilePath(path, a.Store.Path) {
		return errors.New("export cannot replace the active configuration file")
	}
	data, err := json.MarshalIndent(struct {
		Version int             `json:"version"`
		Events  []core.LogEntry `json:"events"`
	}{1, a.Engine.Snapshot().Logs}, "", "  ")
	if err != nil {
		return err
	}
	return atomicExport(path, data)
}
func atomicExport(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".meridian-export-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
func (a *App) fileResult(err error) {
	a.FileBusy = false
	if err != nil {
		a.Notice = err.Error()
	} else {
		a.Notice = ""
	}
	if a.Window != nil {
		a.Window.Invalidate()
	}
}
func (a *App) chooseImport() {
	if a.FileBusy || a.busy() || a.ShuttingDown {
		return
	}
	a.FileBusy = true
	title := a.tr("Import Meridian profiles")
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: a.Window, Title: title, Filters: []mygo.FileFilter{{Name: "Meridian JSON", Extensions: []string{"json"}}}})
		mygo.RunOnMain(func() {
			a.FileBusy = false
			if err != nil {
				a.fileResult(err)
				return
			}
			if len(paths) > 0 {
				if e := a.ImportProfiles(paths[0]); e != nil {
					a.Notice = e.Error()
				}
			}
			if a.Window != nil {
				a.Window.Invalidate()
			}
		})
	}()
}
func (a *App) chooseExport(p *core.Profile) {
	if a.FileBusy || a.ShuttingDown {
		return
	}
	var selected *core.Profile
	if p != nil {
		copy := *p
		selected = &copy
	}
	a.FileBusy = true
	title := a.tr("Export profiles")
	go func() {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: a.Window, Title: title, DefaultPath: "meridian-profiles.json"})
		mygo.RunOnMain(func() {
			if err == nil && path != "" && !a.ShuttingDown {
				err = a.ExportProfiles(path, selected)
			}
			a.fileResult(err)
		})
	}()
}
func (a *App) chooseLogExport() {
	if a.FileBusy || a.ShuttingDown {
		return
	}
	a.FileBusy = true
	title := a.tr("Export activity")
	go func() {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: a.Window, Title: title, DefaultPath: "meridian-activity.json"})
		mygo.RunOnMain(func() {
			if err == nil && path != "" && !a.ShuttingDown {
				err = a.ExportActivity(path)
			}
			a.fileResult(err)
		})
	}()
}
func (a *App) chooseCA() {
	if a.FileBusy || a.ShuttingDown {
		return
	}
	a.FileBusy = true
	generation := a.editorGeneration
	title := a.tr("Choose CA certificate")
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{Parent: a.Window, Title: title, Filters: []mygo.FileFilter{{Name: "PEM certificate", Extensions: []string{"pem", "crt", "cer"}}}})
		mygo.RunOnMain(func() {
			if err == nil && len(paths) > 0 && !a.ShuttingDown && a.Editing && a.editorGeneration == generation {
				a.Draft.CAFile = paths[0]
			}
			a.fileResult(err)
		})
	}()
}
