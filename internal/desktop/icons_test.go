package desktop

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/egoist/mygo/ui"
)

func TestLucideMappings(t *testing.T) {
	// Include the dynamically selected roles as well as literal references.
	roles := []string{
		"import", "export", "arrows", "computer", "vpn", "closed", "back", "search", "proxy",
		"brand", "Overview", "Profiles", "Activity", "Settings", "power", "sun", "moon",
		"plus", "check", "edit", "trash", "info", "arrow", "refresh", "lock",
	}
	if len(icons) != len(roles) || len(iconFiles) != len(roles) {
		t.Fatalf("want %d mapped icons, got %d icons and %d filenames", len(roles), len(icons), len(iconFiles))
	}
	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			filename, ok := iconFiles[role]
			if !ok || filename == "" || filepath.Base(filename) != filename {
				t.Fatalf("missing or invalid official filename for %q: %q", role, filename)
			}
			data, err := lucideAssets.ReadFile("assets/lucide/" + filename)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ui.ParseSVG(data)
			if err != nil {
				t.Fatal(err)
			}
			if w, h := parsed.Size(); w != 24 || h != 24 {
				t.Fatalf("official Lucide asset must retain its 24px viewBox, got %gx%g", w, h)
			}
			if icons[role] == nil {
				t.Fatalf("%q has no parsed icon", role)
			}
		})
	}
}

func TestLucideAssetIntegrity(t *testing.T) {
	manifest, err := os.ReadFile("assets/lucide/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 || !strings.HasSuffix(fields[1], ".svg") || seen[fields[1]] {
			t.Fatalf("invalid or duplicate asset checksum: %q", line)
		}
		seen[fields[1]] = true
		data, err := lucideAssets.ReadFile("assets/lucide/" + fields[1])
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != fields[0] {
			t.Errorf("%s differs from the unchanged official asset: got %s, want %s", fields[1], got, fields[0])
		}
	}
	files, err := lucideAssets.ReadDir("assets/lucide")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(seen) {
		t.Fatalf("%d embedded assets but %d checksum entries", len(files), len(seen))
	}
	used := make(map[string]bool)
	for _, filename := range iconFiles {
		if !seen[filename] {
			t.Errorf("mapped icon %s has no provenance checksum", filename)
		}
		used[filename] = true
	}
	for filename := range seen {
		if !used[filename] {
			t.Errorf("unused embedded icon %s", filename)
		}
	}
}

func TestEveryLiteralIconReferenceIsMapped(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, filename := range files {
		if strings.HasSuffix(filename, "_test.go") {
			continue
		}
		source, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(source), "<svg") || strings.Contains(string(source), "<path") {
			t.Errorf("%s contains inline SVG geometry; use official embedded assets", filename)
		}
		f, err := parser.ParseFile(token.NewFileSet(), filename, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			index, ok := n.(*ast.IndexExpr)
			if !ok {
				return true
			}
			name, ok := index.X.(*ast.Ident)
			if !ok || name.Name != "icons" {
				return true
			}
			literal, ok := index.Index.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			role, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			if icons[role] == nil {
				t.Errorf("%s references unmapped icon %q", filename, role)
			}
			return true
		})
	}
}

func TestLucideNativeRendering(t *testing.T) {
	for role, icon := range icons {
		t.Run(role, func(t *testing.T) {
			img := ui.Render(func(c *ui.Context) {
				ui.Column(c).Fill().Padding(12).Background(ui.RGB(255, 255, 255)).Children(func() {
					ui.Icon(c, icon).Size(24, 24).TextColor(ui.RGB(0, 0, 255))
				})
			}, 48, 48, 1)
			bounds := bluePixelBounds(img)
			if bounds.Empty() || bounds.Dx() < 8 || bounds.Dy() < 8 {
				t.Fatalf("official %s icon rendered empty or incomplete: %v", role, bounds)
			}
		})
	}
}

func TestTopologyArrowKeepsOfficialAspectRatio(t *testing.T) {
	render := func(width, height float32) image.Rectangle {
		img := ui.Render(func(c *ui.Context) {
			ui.Column(c).Fill().Padding(10).Background(ui.RGB(255, 255, 255)).Children(func() {
				ui.Icon(c, icons["arrows"]).Size(width, height).TextColor(ui.RGB(0, 0, 255))
			})
		}, 110, 60, 1)
		return bluePixelBounds(img)
	}
	square, oldWideSlot := render(28, 28), render(82, 12)
	if square.Empty() || oldWideSlot.Empty() {
		t.Fatalf("topology arrows did not render: square=%v old slot=%v", square, oldWideSlot)
	}
	// MyGo preserves aspect ratio rather than stretching the official SVG.
	// An 82x12 slot therefore shrinks the artwork to roughly 12x12.
	if square.Dx() <= oldWideSlot.Dx() || square.Dy() <= oldWideSlot.Dy() || oldWideSlot.Dx() > 12 {
		t.Fatalf("unexpected aspect fit: square=%v old slot=%v", square, oldWideSlot)
	}
}

func bluePixelBounds(img *image.RGBA) image.Rectangle {
	var result image.Rectangle
	for y := img.Bounds().Min.Y; y < img.Bounds().Max.Y; y++ {
		for x := img.Bounds().Min.X; x < img.Bounds().Max.X; x++ {
			p := img.RGBAAt(x, y)
			if p.B > 180 && p.R < 160 && p.G < 160 && p.A > 180 {
				result = result.Union(image.Rect(x, y, x+1, y+1))
			}
		}
	}
	return result
}

func TestTrayIconPNG(t *testing.T) {
	data := TrayIcon()
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds() != image.Rect(0, 0, 32, 32) {
		t.Fatalf("tray bitmap has unexpected bounds: %v", img.Bounds())
	}
	transparent, painted := 0, 0
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			r, g, b, a := img.At(x, y).RGBA()
			if a == 0 {
				transparent++
			} else if a == 65535 {
				painted++
				if r>>8 != 169 || g>>8 != 149 || b>>8 != 255 {
					t.Fatalf("tray asset lost its theme color at %d,%d: %d %d %d", x, y, r>>8, g>>8, b>>8)
				}
			}
		}
	}
	if transparent < 300 || painted < 40 {
		t.Fatalf("tray image is empty or has lost transparency: %d transparent, %d painted pixels", transparent, painted)
	}
	data[0] = 0
	if bytes.Equal(data, TrayIcon()) {
		t.Fatal("caller mutation changed the embedded tray asset")
	}
}
