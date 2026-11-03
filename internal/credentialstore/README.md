# Opt-in Secret Service foundation (not enabled)

This package is **not connected to the desktop or CLI**. It is not a completed
remember-password feature or a claim of production readiness. No real keyring
operation has been run during its development.

## Design

- Linux only; other platforms fail with `ErrUnsupported`.
- Explicit per-operation `SavePassword`, `UsePassword` or `DeletePassword`
  consent. Connecting is not saving consent. Save replaces an existing matching
  password, so the UI must explicitly describe that consequence. The enum is a
  caller contract, not cryptographic evidence of a user's click.
- SHA-256 of structured, exact profile ID, HTTPS gateway, protocol and account
  binds a login password to one connection. Path, host spelling and port changes
  intentionally invalidate reuse. Hashes are identifiers, not confidential
  metadata or authentication. Never accept an imported keyring key.
- Password bytes never enter argv, environment, logs or profile configuration.
  No OTP, session cookie, API key, recovery code or private-key storage API.
- No file fallback. No system installation, collection creation, automatic
  unlock, prompts, service startup, shell, or system configuration change.
- SearchItems distinguishes locked/unlocked matches. Missing and duplicate
  records fail closed; locked records are never silently replaced. `SetSecret`
  updates one existing record. New records use `CreateItem(replace=false)`;
  in-process operations are serialized. Cross-process racing saves can still
  create duplicates: a post-create search checks the observed result and future
  operations refuse duplicates rather than guessing. There is no cross-process
  atomic compare-and-create guarantee; no automatic cleanup is attempted. A
  post-create error (including locked/ambiguous) can occur **after an item was
  saved**. It is not proof of no side effect and must not cause automatic retry
  or deletion.
- Only `/run/user/<uid>/bus` is accepted. The connection checks the runtime-directory owner/mode and Unix peer UID, uses
  SASL EXTERNAL, verifies the Secret Service owner UID, and
  pins the current unique Secret Service owner. Nonstandard session buses are
  unsupported. An existing running desktop Secret Service is required.
- Every operation has a 30-second deadline; cancellation closes the private
  connection, including SASL/Hello. Save/Delete timeout can mean an uncertain
  outcome; callers must not automatically retry writes or report success.
- Errors are fixed messages with no backend details. `ErrPromptRequired` means
  no prompt was executed; the user must manage the keyring themselves.
- Values are limited to 4096 bytes. Owned input/output slices are cleared on
  failure or after use. Go/D-Bus serialization copies cannot be guaranteed wiped.

## Transport and trust boundary

The standard `plain` Secret Service session algorithm runs over the local Unix
session bus. It is **not end-to-end encryption against the bus daemon**, root,
malware running as the user, a malicious Secret Service, or memory inspection.
The system provider owns encryption at rest; this code cannot attest its storage
policy. Do not claim secure-element protection or automatic encrypted-at-rest
verification. No private encryption protocol is implemented.

The application checks the 4096-byte value limit after D-Bus decoding. It does
not lower godbus's protocol message allocation limit. A hostile same-session
service can therefore cause larger transient allocations; a reviewed bounded
transport/decoder is a gate if hostile-provider resilience is required.

## Dependencies and selection

`github.com/godbus/dbus/v5` is pinned to v5.2.2 (BSD-2-Clause), whose minimum dependency is
`golang.org/x/sys v0.27.0`. The repository module graph selects `golang.org/x/sys v0.48.0` (Go project's BSD-style license). Include exact upstream
notices when distributing. This is a new Go dependency, not a bundled daemon.
The package does not invoke libsecret or vendor its code.

Sources checked on 2026-11-03:

- [Secret Service specification](https://specifications.freedesktop.org/secret-service/latest-single/)
- [godbus v5.2.2 module](https://github.com/godbus/dbus/blob/v5.2.2/go.mod)
- [godbus license](https://github.com/godbus/dbus/blob/v5.2.2/LICENSE)
- [Go x/sys license](https://cs.opensource.google/go/x/sys/+/refs/tags/v0.48.0:LICENSE)

Rejected shortcuts: libsecret secret-tool returns exit 1 for both missing and
failed lookup, so cannot expose reliable missing/locked/error semantics.
Zalando go-keyring is MIT but its high-level API lacks context cancellation and
performs automatic unlock; direct godbus gives explicit control of these steps.

## Validation status and release gates

The environment's `/usr/bin/go` is not a Go toolchain; no Go compiler or gofmt
was available. Tests and cross-compilation have **not run**. Dependency checksum
verification and `go mod tidy` must run in an authorized Go/CI environment before
review approval; do not claim this checkpoint is build-verified.

Unit fixtures are injected, in-memory buses only. They cover consent before I/O,
exact endpoint binding, input ownership/wiping, error redaction, cancellation,
value limits, missing/locked/duplicate states, save/load/delete and prompt refusal.
They never open `/run/user` or read, store or delete real secrets.

Before enabling this feature:

1. Run gofmt; go mod tidy; go mod verify; focused tests and full repository tests,
   race checks and Windows/macOS cross-builds. Audit dependency changes/notices.
2. Add adversarial local mock D-Bus wire tests (not a user's real bus), including
   malformed messages, owner loss, partial replies and cancellation during auth.
3. With explicit authorization and synthetic credentials in an isolated test
   account, verify GNOME Keyring and compatible Secret Service providers: default
   alias, locked item/collection, missing service, duplicate record, canceled
   save/delete, restart persistence and actual deletion. Never reuse user secrets.
4. Integrate explicit unchecked-by-default UI Save/Replace, Use and Delete
   actions; bind decisions to the exact visible profile/gateway/account and
   invalidate them on edits. Keep work off the UI thread, handle cancellation,
   clear displayed password state and distinguish operation outcomes.
5. Get a threat-model/security review of plain sessions, provider trust, memory
   copies, D-Bus allocation bounds, duplicate races, and uncertain write outcomes.

Until these gates pass, the existing application remains memory-only.


## Versioned text envelope and GNOME compatibility

GNOME Keyring's upstream `gkd_secret_secret_parse` reads but does not retain the
incoming MIME label, and `gkd_secret_secret_append` emits `text/plain` for replies.
The original binary `application/octet-stream` design therefore failed closed on
its first real-provider read. We do not accept arbitrary MIME types to hide that
mismatch. The provider now writes and requires exactly `text/plain`, containing
`meridian-password-v2:<exact-reference-digest>:<canonical-padded-base64>`.
The reference in the payload must match the query reference; malformed versions,
noncanonical padding, whitespace, invalid base64 and oversized decoded values
are rejected. Binary password bytes still round-trip without text conversion.
Base64 is encoding, not encryption. The OS provider retains responsibility for
storage protection, and a malicious same-UID provider can rewrite this envelope.

The distinct `login-password-base64-v2` attribute namespace does not read, migrate
or delete old `login-password-v1` records. This package remains unconnected to the
application, so no live-user migration is authorized or performed. The 4096-byte
password limit is unchanged; only the bounded stored encoding has additional
space for its version, digest and base64 expansion.

Source: [GNOME secret serialization implementation](https://github.com/GNOME/gnome-keyring/blob/master/daemon/dbus/gkd-secret-secret.c).
