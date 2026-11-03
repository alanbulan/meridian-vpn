# Modified-source provenance

Upstream OpenConnect commit and archive digest are pinned in `upstream.json`.
The original upstream archive is retained byte-for-byte.

- Patches 0001–0004 retain their original authorship and 2026-10-09 patch dates.
- Patches 0005–0009 were present in the restored Meridian v19 source checkpoint
  reviewed on 2026-11-03. Their original raw diffs contain no reliable creation
  dates or author headers; none have been invented.
- Patch 0010 was prepared on 2026-11-03 for publication. It adds prominent
  modified-version notices to every file changed by the preceding series,
  retaining original copyright and license text. It changes comments only.

The notice date records this publication modification, not an assertion about
when earlier code was first written. Reproduce the complete tree by passing the
retained archive to `scripts/prepare_native.py`; the ordered pin includes all
ten patches. Snapshot files under `source/` and `tests/` mirror that result.

Keep the LGPL-2.1 text and all applicable original notices. This provenance record
is not a legal opinion or a claim that future binary distributions satisfy every
license obligation. Review those obligations for each actual distribution.
