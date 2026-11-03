# Client certificate formats

Meridian profiles support three explicit identity formats. These are OpenConnect
client authentication inputs, not a claim of compatibility with any commercial
gateway. No server-certificate verification bypass is added.

| `certificate_format` | `client_certificate` | `client_key` |
| --- | --- | --- |
| absent / `pem` | Absolute PEM certificate path | Absolute PEM private-key path |
| `pkcs12` | Absolute DER PKCS#12/PFX bundle path | Must be empty |
| `pkcs11` | PKCS#11 certificate object URI | Optional PKCS#11 private-key URI |

The GUI exposes the format and identity references. Only references persist.
Bundle passwords and token PINs are per-attempt `Credentials.KeyPassword` bytes,
never profile properties, process arguments, environment variables or files.
Clearing managed buffers is best-effort: Go/runtime/UI string copies cannot be
promised to be erased from memory.

## Files and secrets

PEM keys and PKCS#12 bundles must be owner-only regular files, at most 4 MiB.
Linux opens reject symbolic links and hold the validated file descriptors open
through authentication. PEM public certificates must not be group/world writable.
The command backend receives identity files through inherited descriptors and a
private config pipe; the interactive helper receives references and secrets in
its bounded private protocol. Neither path passes identity material to nmcli.

PKCS#12 local validation checks only the ASN.1 PFX version/content envelope, not
its cryptographic validity. A structurally valid password-integrity MAC is required;
MAC-less containers are rejected. It accepts version-3 data-content PFX, not signed-data
PFX. OpenConnect's TLS backend performs MAC verification, decryption, chain
loading, certificate checks and private-key matching. A successful profile save
therefore does not establish that a bundle password or identity is valid.

## Tokens

PKCS#11 requires the user's existing correctly configured provider and an
OpenConnect TLS build with token support. Meridian does not install providers,
load a user-selected module, enumerate tokens, change PINs, or alter system
keyrings. The URI must select an `id` or `object`. Optional type selectors must
match `cert` for the certificate and `private` for the private key. RFC 7512 `type`
and the older OpenConnect documentation's `object-type` are accepted, but not both.
Non-URI-safe bytes must be percent-encoded.

Only known non-secret identity attributes are allowed. URI queries/fragments,
`pin-value`, `pin-source`, module selectors, duplicate/unknown attributes and
control characters in text selectors are rejected before persistence or launch.
Binary object IDs are supported. For example:

```
pkcs11:token=Synthetic%20Token;id=%01;type=cert
```

Use interactive authentication for provider-generated PIN challenges when the
provider does not consume `key-password`. Provider support for supplied PINs is
TLS-backend dependent. The helper's existing bounded password-form callback can
surface challenges, but real hardware/provider interoperability has not been
verified by this recovery. No production token has been accessed in testing.

## Verification scope

`go test ./internal/core` includes simulated descriptor transport, anti-injection
and URI persistence checks. If OpenSSL is available, a fresh synthetic encrypted
PFX is generated locally to validate the envelope. This does not exercise a
remote gateway or a hardware token. The envelope-only fixture deliberately is
not a real identity and is used only for transport tests.

`TestRealOpenConnectPKCS12` is opt-in via `MERIDIAN_OPENCONNECT_TEST_BINARY`, following
the existing fixture harness. It uses fresh synthetic credentials and loopback
TLS with `--authenticate`, validates a returned authentication tuple and rejects
wrong/missing passwords. It never requests a tunnel, nmcli, host routes or DNS.
If the explicit real binary is unavailable, this test is skipped, not passed.

### Recovery verification result (2026-11-03)

The full authentication-only script passed all ten named real OpenConnect tests
against the retained OpenConnect 9.21 + UniVPN-patched, OpenSSL-backed executable.
The wrapper used was `recovery/native-univpn-linux-amd64/openconnect`; it loads
its isolated sibling libraries, without installing system software.

PKCS#12 completed real loopback mTLS using freshly generated synthetic credentials
and a private descriptor-delivered bundle/passphrase. Missing and wrong bundle
passwords were rejected. PEM, encrypted PEM, encrypted PKCS#8, server/client trust
rejection and cancellation tests also passed. The fixture asserts zero tunnel
CONNECT requests. No production gateway or hardware PKCS#11 test was performed.

The invocation was `sh integration/authfixture/run-auth-only.sh` with
`MERIDIAN_OPENCONNECT_TEST_BINARY` set to the absolute wrapper path. Captured
output is retained as `recovery/meridian-auth-only-validation.log` in the recovery
workspace. This demonstrates the tested OpenSSL fork build only, not all TLS
backend/provider combinations.

## Primary references

- https://www.infradead.org/openconnect/connecting.html
- https://www.infradead.org/openconnect/pkcs11.html
- https://www.infradead.org/openconnect/manual.html

The existing helper uses `openconnect_set_client_cert` and
`openconnect_set_key_password`; format selection does not require a new helper
wire protocol. Bundle keys use the same file as the certificate by omitting a
separate key reference, as OpenConnect specifies.
