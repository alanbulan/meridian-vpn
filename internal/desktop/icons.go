package desktop

import (
	"embed"
	"fmt"

	"github.com/egoist/mygo/ui"
)

// lucideAssets contains unchanged official Lucide 0.468.0 SVGs. See the
// adjacent assets/lucide/README.md, SHA256SUMS, and LICENSE for provenance.
//
//go:embed assets/lucide/*.svg
var lucideAssets embed.FS

// iconFiles maps UI roles to the official icon names. Keep asset geometry in
// the upstream files unchanged; colors and display sizes belong to the UI.
var iconFiles = map[string]string{
	"import":   "download.svg",
	"export":   "upload.svg",
	"arrows":   "arrow-left-right.svg",
	"computer": "monitor.svg",
	"vpn":      "shield-check.svg",
	"closed":   "circle-x.svg",
	"back":     "arrow-left.svg",
	"search":   "search.svg",
	"proxy":    "network.svg",
	"brand":    "waypoints.svg",
	"Overview": "layout-grid.svg",
	"Profiles": "server.svg",
	"Activity": "chart-no-axes-combined.svg",
	"Settings": "sliders-horizontal.svg",
	"power":    "power.svg",
	"sun":      "sun.svg",
	"moon":     "moon.svg",
	"plus":     "plus.svg",
	"check":    "check.svg",
	"edit":     "pencil.svg",
	"trash":    "trash-2.svg",
	"info":     "info.svg",
	"arrow":    "chevron-right.svg",
	"refresh":  "refresh-cw.svg",
	"lock":     "lock.svg",
}

var icons = loadIcons()

func loadIcons() map[string]*ui.SVG {
	result := make(map[string]*ui.SVG, len(iconFiles))
	for key, filename := range iconFiles {
		data, err := lucideAssets.ReadFile("assets/lucide/" + filename)
		if err != nil {
			panic(fmt.Sprintf("desktop: missing Lucide icon %q: %v", key, err))
		}
		result[key] = ui.MustParseSVG(data)
	}
	return result
}

func iconButton(c *ui.Context, key, label string, ic *ui.SVG) ui.Element {
	return ui.ButtonBase(c.Key(key)).Label(label).Tooltip(label).Size(34, 34).Padding(8).Radius(8).Children(func() { ui.Icon(c, ic).Size(18, 18) })
}

// trayPNG is rasterized from the unchanged official Lucide network.svg.
// The librsvg/Cairo conversion is documented with the assets.
//
//go:embed assets/lucide/tray-network.png
var trayPNG []byte

// TrayIcon returns an independent copy of the official icon's PNG rendering.
func TrayIcon() []byte {
	return append([]byte(nil), trayPNG...)
}
