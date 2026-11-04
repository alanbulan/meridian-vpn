package desktop

import (
	"github.com/egoist/mygo/ui"
	"image/png"
	"mygo-vpn/internal/core"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsLimitedRenderEvidence(t *testing.T) {
	directory := os.Getenv("MERIDIAN_WINDOWS_UI_EVIDENCE")
	if directory == "" {
		t.Skip("optional synthetic UI render output")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	a := NewWithAdapter(filepath.Join(t.TempDir(), "profiles.json"), &fakeWindowsAdapter{})
	a.WindowsBorrowedEnabled = true
	a.Config.Settings.Language = "en"
	profile := desktopWindowsProfile()
	a.Config.Profiles = []core.Profile{profile}
	a.Config.SelectedID = profile.ID
	a.startEdit(&profile)
	for _, name := range []string{"profile", "consent"} {
		var view func(*ui.Context)
		if name == "profile" {
			view = a.editor
		} else {
			a.openConnectForm()
			view = a.connectForm
		}
		pixels := ui.Render(view, 660, 1300, 1)
		file, err := os.Create(filepath.Join(directory, name+".png"))
		if err != nil {
			t.Fatal(err)
		}
		err = png.Encode(file, pixels)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
}
