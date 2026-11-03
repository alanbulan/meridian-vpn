# Explicit desktop password operations (development integration)

The session authentication form now exposes optional system-password operations.
This connects the existing provider to the desktop; it does not make startup,
connection, reconnect, profile import, or profile selection read/save credentials.
The CLI remains unchanged. There is no remembered opt-in or new config field.

## User flow

1. A Linux user opens the normal session-authentication form for an existing
   standard HTTPS password profile with a username. The provider is constructed
   without I/O. No availability probe or lookup runs automatically.
2. Save/replace, load, and delete are three separate requests. Each opens a
   confirmation naming the profile/name/ID, exact gateway, protocol and account.
3. Save additionally requires affirming this is a reusable password, not an OTP.
   Its confirmation explicitly authorizes persistence across logins and replacing
   the prior value. Delete explicitly includes clearing the input field.
4. A confirmed operation runs on a background goroutine with a bounded context.
   No UI widget or mutable App field is accessed from that goroutine.
5. Load only fills the same password field and resets network/proxy permission.
   The user must separately authorize network changes and press Connect. Save
   does not connect; deleting a profile does not delete its stored password.

Windows/macOS show an unavailable message and have no store instance. The first
integration excludes interactive authentication, L2TP, experimental UniVPN,
certificate/private-key profiles, missing usernames and authentication groups.
It never stores OTP prompts, key passphrases, token PINs or IPsec PSKs. Desktop
password inputs must be nonempty valid UTF-8, at most 4096 bytes, with no CR/LF/NUL;
the lower-level provider continues to support arbitrary bounded binary values.

## Binding, cancellation and errors

A confirmation and its worker are bound to the exact reference, a hash of the
whole profile snapshot and a fingerprint of the existing input. Confirmation is
invalidated by edits. A newly typed value cannot be overwritten by an older
load. A loaded password is cleared if its profile or gateway changes. Save and
delete use the captured reference, never a later selected profile.

Navigation, cancellation, hiding the window to the tray and shutdown cancel the context.
The hide hook clears session input without changing the VPN session. The worker returns
through an unbuffered result channel; if canceled or abandoned, it clears output
bytes instead of leaving them in a buffered result. Owned input copies and
consumed/rejected outputs are cleared. The UI password is a Go string: complete
memory erasure of UI/runtime copies cannot be guaranteed.

Ordinary completion notices are bound to the original reference/profile and are
cleared when it changes. An uncertain write is a separate dismissible warning
that names its original profile/gateway/account and survives navigation/config
changes; it blocks another keyring request until dismissed. Raw provider errors,
secret bytes and fingerprints are never logged or displayed.

Cancellation does not undo a write. A daemon may have saved/deleted an item before
its reply was canceled. Shutdown cancels but does not block the UI waiting for the
keyring worker or persist its warning across process exits. An interrupted write
therefore needs manual inspection before retrying; no automatic retry/rollback
is implemented. The current UI does not promise transactional cancel semantics.

## Automated evidence and limits

`credentials_test.go` uses only an injected in-memory mock and a counting VPN
adapter that refuses network use. It covers explicit confirmation/no startup I/O,
OTP-save acknowledgment, exact reference capture, repeated confirmation, late
results and fresh typing, cancellation/navigation/shutdown, known lock errors,
error redaction, config non-persistence, unsupported modes, loaded-value binding,
notice/warning ownership, and narrow-view layout checks. These tests do not call
NewSystem or a real keyring operation.

The earlier separate integration suite exercised a real GNOME Keyring daemon
with synthetic secrets in a disposable container. That does not validate this
native GUI workflow end-to-end, a user's desktop keyring permissions, other
Linux providers, or Windows/macOS stores. No real user credentials were used.

The editing environment cannot compile/run Go or render native GUI screenshots.
This integration still needs the exact development commit's full/race/UI tests,
manual native rendering and cancel/close/scroll checks, and an authorized
synthetic desktop end-to-end test before claiming release readiness. Source-level
UI tester coverage is not a visual acceptance pass. See the provider README for
plain-session, memory-copy, hostile-decoder and cross-process-race limitations.

Password confirmations temporarily replace unrelated session input controls,
rather than being stacked below them. Cancel restores the existing input without
contacting the provider. Exact target fields remain visible in the scrollable
form; they are not abbreviated. Minimum-window tests retain the original bounds,
include English and Chinese, and exercise scrolling to confirm/cancel controls
with a valid long synthetic target. Native font/rendering acceptance is still
required; headless geometry tests are not a pixel-level UI review.
