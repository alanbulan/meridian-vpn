# Official Lucide icons

These SVG files are copied **byte for byte, without modification**, from the
official [Lucide repository](https://github.com/lucide-icons/lucide), tag
[`0.468.0`](https://github.com/lucide-icons/lucide/tree/0.468.0/icons).

- Source archive: https://github.com/lucide-icons/lucide/archive/refs/tags/0.468.0.tar.gz
- Archive SHA-256: `91cda05023eae90e2cb8a52c0b1abedd5ebad1bdbbadcde76f01aab652828691`
- Upstream source paths: `icons/<filename>.svg`
- Per-file SHA-256 hashes: [`SHA256SUMS`](SHA256SUMS)
- License: upstream [`LICENSE`](LICENSE), copied unchanged (ISC, with Feather attribution)

The application embeds these static assets with Go `embed.FS`, parses them once
with MyGo's `ui.MustParseSVG`, and displays them using MyGo's native `ui.Icon`.
No web runtime, JavaScript package, network fetch, custom SVG path, or SVG
rewriting is used. See MyGo's [icon documentation](https://mygo.egoist.dev/docs/ui/icon).

`internal/desktop/icons.go` maps application names to the official filenames.
The brand mark uses Lucide `waypoints`, not a custom-drawn logo. Topology arrows
use the official square `arrow-left-right` asset. Render square assets in square
bounds; reusing the previous custom arrow's 82 × 12 bounds would make this icon
tiny (MyGo fits the SVG without stretching).

To update, copy the selected SVGs and license from another official, pinned
Lucide release without editing the files; update this provenance and the hash
manifest, then run the icon tests. `TestLucideAssetIntegrity` checks each hash.

## System tray bitmap

`tray-network.png` is the official unchanged `network.svg` rasterized to 32 × 32
with a transparent background and the application's lavender color. The tray
API requires a PNG. No pixels or geometry are hand-drawn. The original SVG
remains unchanged; the renderer receives the presentation color as a separate
stylesheet. Conversion uses installed librsvg 2.60.0 and Cairo 1.18.4:

```sh
python3 internal/desktop/assets/lucide/generate_tray.py
```

The script loads system libraries with Python's standard-library `ctypes`.
It is a reproducibility tool only; the app embeds the finished PNG and needs
neither Python nor librsvg to display it. PNG output may vary across renderer
versions even when the rendered pixels match.

PNG SHA-256: `7ad25b7a6e244d9ace9b1fac22c404ff3680a9bacde170c8b7d81b2fe7da3fdb`
