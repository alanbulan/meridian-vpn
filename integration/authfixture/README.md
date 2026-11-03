# Real OpenConnect authentication-only integration

These opt-in tests launch an **actual OpenConnect client**, not a mock runner, against a loopback HTTPS AnyConnect XML authentication fixture. The test code lives in `internal/core/authfixture_integration_test.go`, so real-client arguments come from production `OpenConnectArgs` (including custom-CA validation and direct-mode `--no-proxy`), child environment uses production proxy sanitization, and successful output is passed directly to production `parseAuthentication`.

## Scope

Verified with Debian OpenConnect **9.12-3+deb13u2**, GnuTLS **3.8.9**, Linux amd64:

1. Trusted fixture TLS certificate → username/password challenge/reply → authenticated cookie, gateway and certificate fingerprint parsed by production code.
2. Invalid synthetic password rejected after a real challenge/reply; no cookie.
3. Untrusted fixture certificate rejected before HTTP credentials reached the server; error identifies certificate validation.
4. Cancelled pending authentication terminates the real child process; no cookie.
5. Real mTLS certificate-only authentication with no username/password, using both an unencrypted EC PEM key and an encrypted OpenSSL-compatible EC PEM key.
6. A client certificate not trusted by the local gateway is rejected at TLS, before HTTP authentication.
7. Missing/wrong encrypted-key passphrases fail closed without an HTTP credential request.
8. Cancellation during pending client-certificate authentication terminates the real child.
9. Encrypted PKCS#8 (PBES2, AES-256-CBC, PBKDF2-HMAC-SHA256) authenticates with a private-FD passphrase; missing/wrong passphrases and a mismatched certificate fail closed.

Client-certificate tests use production `authenticateOpenConnect` and `execRunner`, including their no-follow file validation, retained descriptors, strict result parser, and cancellation. A separate real subprocess test checks that the password and key passphrase never appear in argv or environment, and arrive only over stdin and inherited descriptor 3. Certificate and private key use inherited descriptors 4 and 5; only the authenticated cookie tuple reaches the NetworkManager stage (which remains mocked).

Every client invocation uses **`--authenticate`**. The fixture counts and rejects HTTP `CONNECT`; the successful runs recorded **zero tunnel CONNECT requests**. The tests never run `nmcli`, touch `/dev/net/tun`, create a network interface, set routes/DNS, contact a corporate gateway or establish a VPN. These results **do not constitute Linux VPN end-to-end verification or UniVPN compatibility**.

Credentials are fixed synthetic test values; passwords are delivered through stdin. Real generated cookies (which can include an HPKE private-key prefix) are held in memory, never printed or written to files. The test CA and synthetic client identity files are written to private temporary mode-0600 files and deleted by the test harness. No real credential is used. The TLS server key stays in Go test server memory; the test CA is not installed in the OS trust store. Key passphrases are passed as a generated config through an anonymous pipe, never as process arguments, environment variables, or config files. The fixture uses `--cafile` solely for that temporary test CA and `--no-proxy` to keep requests on loopback. TLS verification is not disabled.

## Run against an installed trusted client

From the repository root:

```sh
MERIDIAN_OPENCONNECT_TEST_BINARY=/usr/sbin/openconnect \
  ./integration/authfixture/run-auth-only.sh
```

Normal `go test ./...` **skips** these nine opt-in test functions when the variable is unset. Skipped does not mean passed. The client `--version` prerequisite is verified in every test; failure to launch a real client cannot falsely pass a negative test.

## Workspace-only Debian staging

No root or package installation is used. On a compatible Linux amd64 system, the script downloads pinned packages from `https://deb.debian.org/debian/pool/main/`, checks the recorded SHA-256 for each archive, and extracts them beneath the requested private staging directory:

```sh
./integration/authfixture/stage-debian-client.sh /absolute/workspace/openconnect-fixture

MERIDIAN_OPENCONNECT_TEST_BINARY=/absolute/workspace/openconnect-fixture/root/usr/sbin/openconnect \
LD_LIBRARY_PATH=/absolute/workspace/openconnect-fixture/root/usr/lib/x86_64-linux-gnu \
  ./integration/authfixture/run-auth-only.sh
```

The script does **not** install packages, run package maintainer scripts, start services, change security policy or modify system files. Additional ordinary system libraries (glibc, GnuTLS, libxml2, etc.) must already be ABI compatible. The package hashes pin the HTTPS-fetched artifacts; this fixture does not claim a separate Debian release-signature verification. Do not substitute an untrusted executable.

In the cloud execution workspace, the actual command used Go 1.27.3 and these explicit paths:

```sh
GO=/workspace/shared/toolchains/go/bin/go \
GOCACHE=/workspace/shared/go-build GOPATH=/workspace/shared/go-path \
LD_LIBRARY_PATH=/workspace/shared/openconnect-fixture/root/usr/lib/x86_64-linux-gnu \
MERIDIAN_OPENCONNECT_TEST_BINARY=/workspace/shared/openconnect-fixture/root/usr/sbin/openconnect \
  ./integration/authfixture/run-auth-only.sh
```

A clean staging reproduction at `/workspace/shared/openconnect-fixture-repro` also completed: all 12 archive SHA-256 checks passed, the staged client ran, and the original four authentication tests passed again (historical baseline; the current expanded result is in `RESULTS.txt`). Shell syntax validation and core vet passed.

`RESULTS.txt` contains the sanitized final test output. Downloaded executables and libraries are not included in the source archive.

## Primary references

- [OpenConnect: authenticate separately as an unprivileged user](https://www.infradead.org/openconnect/nonroot.html).
- [OpenConnect: AnyConnect protocol overview](https://www.infradead.org/openconnect/anyconnect.html).
- Official upstream source checked out at commit `70d1e79d1e55849dfc71dcc199b1edb535b547e4`: [`auth.c`](https://gitlab.com/openconnect/openconnect/-/blob/70d1e79d1e55849dfc71dcc199b1edb535b547e4/auth.c), [`main.c`](https://gitlab.com/openconnect/openconnect/-/blob/70d1e79d1e55849dfc71dcc199b1edb535b547e4/main.c), and [`tests/fake-cisco-server.py`](https://gitlab.com/openconnect/openconnect/-/blob/70d1e79d1e55849dfc71dcc199b1edb535b547e4/tests/fake-cisco-server.py). The fixture uses its own minimal authentication handler; it is not a complete gateway or copied server implementation.
- Official Debian package URLs and pinned archive hashes: `debian-packages.sha256-urls`.

## Client identity format and validation

Profiles store certificate and private-key absolute path references only. Use a PEM certificate chain whose first certificate is the currently valid client leaf, and a separate RSA/EC/PKCS#8 PEM private key. Private keys must have owner-only POSIX permissions (for example `0600`); certificates may not be group/world writable. Symlinks, FIFOs, directories, oversized files, malformed PEM, expired/non-client certificates and mismatched unencrypted keys are rejected locally. The native TLS implementation decrypts and matches encrypted keys. PKCS#12 bundles and hardware/USB tokens are not implemented.

The traditional encrypted-PEM test uses OpenSSL-compatible uppercase IV hex in its DEK-Info header. OpenConnect 9.12 rejects lowercase IV hex produced by Go's deprecated legacy PEM encryption function; the test fixture normalizes only its own synthetic header. Encrypted PKCS#8 avoids that legacy format constraint. Do not infer support for every cipher/provider from the tested formats.

OpenConnect config values are not shell quoted. The generated key-password line preserves literal quotes, `#`, and `=`. Empty passphrases omit that line. CR/LF/NUL, leading space/tab and passphrases over 4096 bytes are rejected before starting any process.
