# Linux versioned candidate

This package contains the real Meridian Linux GUI and foreground CLI. It is an
**unsigned candidate**, not a signed installer or evidence of a validated
corporate VPN connection. It does not contain the experimental UniVPN worker,
install a system service, or change your network during extraction.

## Run

Supported packaging target: Linux amd64. Extract into a directory owned by you
that is not group/world-writable, with trusted ancestors (not `/tmp`). Verify
`sha256sum -c SHA256SUMS` before running. The archive's hash must also match the
build's separately delivered checksum. Checksums are not publisher signatures.

- `./meridian --version` and `./meridianctl version` show the packaged version.
- `./meridianctl help` is offline and does not read configuration.
- `./meridianctl diagnostics --json` checks dependencies and NM readiness only;
  it does not contact a gateway. Missing dependencies produce exit code 1.
- `./meridian` opens the native desktop. Do not run the GUI as root.

The GUI requires system GTK3/Pango/Fontconfig and the desktop libraries required
by MyGo. A working desktop D-Bus/Polkit authorization environment, NetworkManager,
OpenConnect and NetworkManager-openconnect are external dependencies for
AnyConnect. L2TP additionally requires NetworkManager-l2tp and its distribution
IPsec/PPP dependencies. Your administrator must install and maintain them using
the distribution's official packages. The candidate does not install them.

If `build-manifest.json` says `mfa_helper: true`, the adjacent separate C helper
was built with system libopenconnect and passed its authentication-only protocol
handshake. System libopenconnect 9.12+/API 5.9+ and its dynamic dependencies must
be available on the target. No libraries or credentials are bundled. A successful
build-host handshake does not prove the target's runtime ABI. Run diagnostics on
the target; absent/incompatible runtime or unsafe placement disables interactive
authentication. Keep the helper beside both binaries. Without it, ordinary
non-interactive authentication remains available; structured MFA is unavailable.
The exact build's CLI documentation in `source.tar` defines whether terminal MFA
is implemented. SSO/browser auth/Host Checker are not implied by MFA support.

Actual connection requires a configured authorized gateway, fresh credentials,
and explicit network authorization. Ctrl+C/SIGTERM stops the foreground CLI's
own connection; GUI shutdown waits for cleanup. Never use forced termination as
a substitute for disconnecting. Do not assume internal access, route/DNS
restoration, IPv6 leak protection, kill switch, reconnect or crash recovery from
an activated-interface indication. L2TP IKE/PPP and corporate gateway behavior
still need protocol-specific real acceptance.

## Build and verify

Use the repository's official pinned Go toolchain and clean exact source commit:

```
go mod download
go mod verify
go test -count=1 ./...
go vet ./...
python3 -m unittest discover -s scripts -v
python3 scripts/package-linux.py --version 0.1.0-alpha.1 --output /path/out/meridian-linux-amd64.tar.gz
```

The version above is an example, not an existing release or a version decision.
Add `--with-helper` only when official system `libopenconnect-dev` 9.12+,
`pkg-config` and a C11 compiler are installed. The script never installs them.
Its Go builds use `CGO_ENABLED=0`; the helper is an explicitly separate C build.
`--go /absolute/path/to/go` selects an installed official compiler.

The output is exclusively created (never overwritten), with deterministic member
ordering, modes, owner fields and commit-time timestamps. Identical inputs give
identical archive bytes; different compiler/system dependencies may change
binaries, so cross-machine reproducibility is not claimed. The manifest records
version, exact commit, toolchain, helper build version, input hashes and honest
verification limits. `source.tar` is the exact git source tree and contains the
helper source/build instructions, project documentation and dependency notices.
No runtime library is embedded; preserve its distribution's notices and obtain
corresponding source through that distribution when redistributing those libraries.

`.github/workflows/linux-candidate.yml` builds/tests/uploads a candidate only.
It runs manually or on the exact `candidate/linux-minimal-20261104` branch;
that branch uses provisional version `0.1.0-alpha.1` with the helper enabled.
It cannot publish a GitHub Release and has read-only repository permissions.
Before public distribution the maintainer must decide the license for Meridian's
own code, review exact linkage/source obligations and authorize the release.
This packaging does not choose or grant any new license. Keep `THIRD_PARTY.md`,
all notices and corresponding source with the candidate.

Before describing it as production-ready, record clean-desktop GUI/runtime tests
and authorized real VPN acceptance: gateway identity/authentication, intended
internal reachability, routes and DNS before/during/after, cancel/auth failure,
normal disconnect, connection loss, NM restart, and effects on existing VPNs.
Private/local fixtures and CI skips are not substitutes for these results.
