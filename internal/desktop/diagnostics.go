package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/egoist/mygo"
	"mygo-vpn/internal/diagnostics"
	"time"
)

func (a *App) ExportDiagnostics(ctx context.Context, path string) error {
	if sameFilePath(path, a.Store.Path) {
		return errors.New("cannot overwrite the active configuration")
	}
	report := diagnostics.Collect(ctx, "0.1")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return atomicExport(path, data)
}
func (a *App) chooseDiagnosticsExport() {
	if a.FileBusy || a.ShuttingDown {
		return
	}
	a.FileBusy = true
	title := a.tr("Export diagnostics")
	// Capture storage identity, not mutable UI fields, before background work.
	storePath := a.Store.Path
	go func() {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{Parent: a.Window, Title: title, DefaultPath: "meridian-diagnostics.json"})
		mygo.RunOnMain(func() {
			if err != nil || path == "" || a.ShuttingDown {
				a.fileResult(err)
				return
			}
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				snapshot := &App{}
				snapshot.Store.Path = storePath
				err := snapshot.ExportDiagnostics(ctx, path)
				mygo.RunOnMain(func() { a.fileResult(err) })
			}()
		})
	}()
}
