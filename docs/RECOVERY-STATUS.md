# Recovery status, 2026-11-03

The recoverable starting artifact is `meridian-0.1-source.zip`, persisted version 3, last modified 2026-11-03 03:55:22 UTC. A fresh working tree was extracted from those bytes. Later previously reported development changes were not present in this archive; they must not be described as recovered.

## Reimplemented in this working tree

- Bounded structural UTF-8 INI inspection, CLI `profiles preview-ini` and native settings file picker. All names and values are hidden. Duplicate keys/sections and unsafe or oversized files fail closed. This is not vendor-format conversion/import.
- Native certificate format selector for PEM, PKCS#12 and PKCS#11, appropriate bundle picker / URI inputs, per-session passphrase/PIN. Changing format clears incompatible references and invalidates outstanding old-format file pickers.
- Native L2TP/IPsec parameter controls and per-session PSK, routed through the protocol-aware backend capability. Switching protocol clears incompatible transport fields and credentials. Draft/copy operations deep-copy L2TP options.
- Regression tests for INI boundaries/redaction, no configuration reads/writes during CLI preview, certificate format safety, protocol switching, PSK clearing and L2TP draft isolation.

## Verification by recovery worker

- `go test ./cmd/meridianctl ./internal/core`: passed at 05:53 UTC.
- `go test ./internal/desktop`: passed, including rerun after capability text updates.
- `go test -race ./cmd/meridianctl ./internal/desktop`: passed.
- `go vet ./cmd/meridianctl ./internal/desktop`: passed.

Other workers may have changed core behavior concurrently. Final aggregate verification is still required after all integration. None of these checks establishes successful real VPN connection, routing/DNS restoration, token-hardware compatibility, or enterprise gateway compatibility. This worker did not run a real tunnel or change host network settings.

## Final disabled experimental checkpoint, 06:12 UTC

Final current-tree default tests: 202 top-level PASS, 20 explicit SKIP. Full project race, vet, module verification, Linux GUI/CLI and Windows AMD64/macOS ARM64 GUI/CLI builds passed. See VALIDATION.md and RECOVERY-TEST-RESULTS.jsonl. Real authentication-only OpenConnect suite separately passed all 10 tests, including PFX; native UniVPN mock TLS suite passed all 9. No privileged tunnel or route/DNS tests occurred.

The UniVPN controller and broker are implemented and mock-tested but unavailable for deployment without descendant containment, exclusive namespace lease, service deployment, and authorized integration validation. An opt-in authenticated native inherited-pipe session source is implemented in the subsequent session-channel work; it is not activated. Default GUI UniVPN remains disabled.

## Native session-channel checkpoint, 06:27 UTC

The subsequent source update adds an opt-in private inherited-pipe native session
channel, the matching Go process-bound configuration source, and stricter
fail-closed kernel JSON parsing. It includes seven pinned native patches and
actual C-emitter wire fixtures. The channel does not activate a service or GUI
connection capability.

Verification for this update: full core race tests and core vet passed after the
final changes. A fresh official native archive plus all seven patches completed
the packaged build, nine loopback TLS regressions, actual inherited-pipe CLI
authentication success/rejection tests, and wrapped TUN/netlink emitter tests.
Native source/package checksums verified. Independent review found no additional
critical source issue in this disabled experimental scope.

A graceful no-network attestation still requires EOF, whole-process-tree
containment, and independent kernel absence proof. Partial acquisition or missing
proof quarantines the broker. Real containment and exclusive namespace lease
providers remain unavailable; a broker lock cannot exclude competing privileged
host writers, and a private namespace needs correct user-traffic forwarding and
DNS integration. Production activation and real privileged networking remain
unimplemented/unverified, not implicitly approved by passing isolated tests.
