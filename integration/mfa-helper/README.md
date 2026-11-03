# Optional structured authentication helper

Meridian's MyGo GUI and Go bridge remain pure Go (`CGO_ENABLED=0`). Linux users who require interactive AnyConnect authentication can optionally build the small **separate C executable** `meridian-auth-helper`. It uses the official libopenconnect `process_auth_form` callback, rather than guessing prompts from CLI stderr. The existing password/certificate-only CLI path remains available when interactive authentication is disabled.

The helper only calls `openconnect_obtain_cookie`. It **never creates a tunnel, invokes NetworkManager, opens TUN, installs routes/DNS, installs a CA, or changes the host's security settings**. After authentication the existing Go NetworkManager backend handles the separately authorized tunnel operation. Authentication success is not tunnel readiness.

## Supported and unsupported

- Typed text/password fields (including server-requested one-time codes), select lists, retry forms, exact configured authentication-group selection, and PEM client certificate/private-key authentication.
- Initial username/password are reused only for the first form when that form contains exclusively recognized username/password fields. Additional fields or later challenges require the native GUI prompt. A saved group is matched exactly to a server-provided ID or label; it is never invented.
- Normal system trust and an optional validated private CA file. TLS errors **always reject**. There is no certificate-exception button or callback path.
- External-browser/webview SSO and SSO form fields **reject**. The isolated helper exits immediately on SSO fields because libopenconnect v9.12 can continue into SSO handling even after a form callback returns an error; browser callbacks also terminate the helper rather than launch anything. CSD/Host Checker remains disabled: the helper never calls `openconnect_setup_csd`, configures a wrapper, or enables a user for scripts. No software-token seed, PKCS#11/USB key, push-notification poller, or endpoint-compliance flow is implemented.
- Tested against an ephemeral localhost TLS AnyConnect fixture, not a corporate gateway. The tests cover actual official libopenconnect callbacks, password → OTP + method selection → wrong-code retry → success, rejection, cancellation, bounded forms, and client certificates. This does not claim universal MFA, UniVPN compatibility, or a real VPN end-to-end test.

## Build with system development dependencies

Requirements: Linux, a C11 compiler, pkg-config, and official libopenconnect **9.12 or later / API 5.9 or later** headers and runtime library. Install/maintain these separately through the operating system's package manager; this project never installs packages automatically. Typical Debian development package name: `libopenconnect-dev`.

From the repository root:

```sh
./integration/mfa-helper/build.sh ./build/meridian-auth-helper
CGO_ENABLED=0 go build -o ./build/meridian ./cmd/meridian
```

The helper build uses dynamic linking and hardening flags, without a workspace RPATH. Put it **next to the GUI executable** or in a normal trusted executable directory on `PATH`. The GUI prefers a sibling, then PATH, and probes the fixed `--protocol-version` handshake. Discovery rejects symlink executables, non-regular files, missing execute bits, owners other than root/current user, and group/world-writable files or ancestors. Do not install it under `/tmp`, shared writable directories, or run it as root. These checks are path hygiene, not a digital signature; the current user's account and system administrator remain trusted.

The helper must find its system libopenconnect runtime normally. If the helper or runtime is absent, incompatible, insecurely located, or cannot start, the GUI explicitly disables interactive authentication. A shipped helper binary does not bundle the runtime library and is not a signed installer. The Linux binary is not a macOS/Windows backend.

## Reproducible private Debian staging

For compatible Linux amd64 test hosts, this opt-in script downloads pinned official Debian packages, verifies recorded SHA-256 hashes, and extracts them under the chosen workspace only. It does not run package maintainer scripts, install packages, start services, or modify system files. Ordinary system dependency ABIs must already be compatible.

```sh
./integration/mfa-helper/stage-debian-helper.sh /absolute/private/workspace/mfa-stage

MERIDIAN_MFA_HELPER_TEST_BINARY=/absolute/private/workspace/mfa-stage/meridian-auth-helper \
LD_LIBRARY_PATH=/absolute/private/workspace/mfa-stage/root/usr/lib/x86_64-linux-gnu \
  ./integration/mfa-helper/run-auth-only.sh
```

The runtime packages and hashes come from [`../authfixture/debian-packages.sha256-urls`](../authfixture/debian-packages.sha256-urls). The extra development-header package is Debian `libopenconnect-dev_9.12-3+deb13u2_amd64.deb`, SHA-256 `c38741a011ce2840bf792c3727bfa14d0b661dc02f58f500af5f907641caafd8`. Package URLs are the official `https://deb.debian.org/debian/pool/main/` archive. These hashes pin fetched artifacts; the script does not claim an additional Debian release-signature verification.

Do not use `LD_LIBRARY_PATH` pointing at an untrusted directory. It is only necessary for this private staging example, not normal runtime installs. Downloaded dependencies are excluded from this repository and source deliverable.

Tests are opt-in: ordinary `go test ./...` skips `TestRealMFA*` without the environment variable. A skipped test is not a passed integration test. `RESULTS.txt` records a sanitized run with Go 1.27.3, Debian libopenconnect 9.12-3+deb13u2, and GnuTLS 3.8.9. Test secrets are fixed synthetic values. Test CA private keys stay in memory; only public CA certificates and ephemeral test client-identity fixture files are written in private test directories.

## Private IPC protocol v1

Only the child's inherited stdin and stdout pipes carry protocol messages. There is no socket listener, temporary credential file, shell evaluation, secret command argument, secret environment variable, or credential logging. Stderr/progress output is discarded. Helper core dumps are disabled for that process, and it exits after authentication. Memory buffers are cleared where owned; Go strings, widget strings, and libopenconnect allocations cannot provide a guarantee against memory forensics.

Every frame starts with a 4-byte big-endian payload length, **36–65,536 bytes**. Payload:

1. Protocol version `u8 = 1`.
2. Message type `u8`: `1` initialize, `2` challenge, `3` answer, `4` authenticated result. Anything else fails closed.
3. Session ID: 32 ASCII lowercase hexadecimal characters generated from 16 random bytes by Go for each attempt.
4. Round: big-endian `u16`. Init is zero. Challenges strictly increase from one. Answers must echo the current session/round. Result echoes the last round, or zero for certificate-only auth.
5. Type-specific data, with no trailing bytes accepted.

A string/byte value is `u16` big-endian byte length followed by exactly that many bytes. It is not NUL-terminated on the wire. Strings must be valid UTF-8 at the Go boundary. Embedded NUL/unsupported controls fail; metadata can contain newline/tab as inert text. IDs, choices, answers, and authenticated fields do not accept line breaks or control delimiters.

- **Init:** gateway, retained CA fd path or empty, explicitly authorized proxy or empty, retained client certificate fd path or empty, retained key fd path or empty, one-attempt key passphrase or empty, configured authentication group or empty. Only checked retained file descriptors are passed via `ExtraFiles`; `/proc/self/fd/N` is sent privately. No server-provided file paths are used.
- **Challenge:** title, message, field count `u16`; then each field's ID, label, kind `u8` (`1=text`, `2=password/token`, `3=select`), choice count `u16`, and each choice's ID and label. Hidden backend state stays inside libopenconnect. Unsupported field types fail. Duplicate field/choice IDs fail.
- **Answer:** field count `u16`, then ID and value for each field in challenge order. Exactly the current field set is required; select values must match a supplied choice ID. The bridge clears answer byte slices after consumption.
- **Authenticated result:** cookie, HTTPS connect URL, verified peer-certificate fingerprint, and optional `DNSNAME:IP` resolver hint. DNS load-balancing preserves both the authenticated address and the original hostname/SNI. Go validates the returned URL and numeric resolver mapping before handing the tuple to NetworkManager.

Limits on both sides: **180 seconds per authentication attempt, eight visible forms, sixteen visible fields per form, thirty-two choices per select**. The helper also caps all form options (including hidden ones) at 64. IDs are at most 128 bytes, title/labels 2,048, combined banner/message/retry text 4,096, answers 4,096, returned cookie/URL/fingerprint 16,384. Oversized, malformed, stale, repeated, incomplete, or mismatched frames fail closed. The GUI callback must respect cancellation. Cancellation kills the helper and closes its pipes, including an inherited-output defense, so there is no residual authentication process to answer an old session.

## Source and licensing

The new helper source is MIT-licensed (SPDX in `main.c`); it dynamically uses the separately installed **libopenconnect LGPL-2.1 library**. OpenConnect's command-line application and related components may have different license obligations. Packaging/distributing the external library is not covered by merely including this helper; retain the distributor's notices/source and applicable license requirements. This project does not copy or bundle the library implementation.

Primary references, checked against the official v9.12 source:

- [Public callback and lifecycle API, openconnect.h](https://gitlab.com/openconnect/openconnect/-/blob/v9.12/openconnect.h).
- [Authentication form handling and library lifetime, library.c](https://gitlab.com/openconnect/openconnect/-/blob/v9.12/library.c).
- [AnyConnect forms and default-disabled CSD, auth.c](https://gitlab.com/openconnect/openconnect/-/blob/v9.12/auth.c).
- [Official CLI auth-only result and RESOLVE handling, main.c](https://gitlab.com/openconnect/openconnect/-/blob/v9.12/main.c).
- [OpenConnect non-root authentication architecture](https://www.infradead.org/openconnect/nonroot.html).
