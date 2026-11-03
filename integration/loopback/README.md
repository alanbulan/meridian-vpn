# Opt-in loopback integration runner

These Linux fixtures exercise real authentication and experimental native code
against synthetic localhost TLS servers. They are **not** enterprise gateway,
real TUN, route/DNS recovery, privileged deployment, or sandbox acceptance tests.
Run as an ordinary user in a private workspace. The runner refuses root, does
not install dependencies, does not run NetworkManager, and does not enable the
experimental application backend. Synthetic fixture credentials are not real
accounts. Never supply corporate credentials or a corporate gateway.

## Authentication (official OpenConnect and optional MFA helper)

Prerequisites: the project's Go toolchain; C compiler; pkg-config; official
OpenConnect/libopenconnect development package **9.12+**; Python 3 and OpenSSL.
For example, a separately prepared Debian trixie CI environment supplies
`build-essential pkg-config libopenconnect-dev openconnect openssl ca-certificates
python3 git`. Dependency installation is a separate CI-administrator step, not
something this runner performs. Log package versions when recording evidence.
Ubuntu 24.04's older libopenconnect must not be mistaken for a compatible helper.

From the repository root, with dependencies already present:

```sh
sh integration/mfa-helper/build.sh "$PWD/build/meridian-auth-helper"
MERIDIAN_OPENCONNECT_TEST_BINARY=/usr/sbin/openconnect \
MERIDIAN_MFA_HELPER_TEST_BINARY="$PWD/build/meridian-auth-helper" \
  python3 integration/loopback/run.py auth --reports reports/loopback-auth
```

Use the actual absolute system OpenConnect path if different. The helper must
be in a private/trusted directory, including its ancestors; do not put it under
world-writable `/tmp`. No production credentials are accepted by this command.
`auth.jsonl` is the original `go test -json` evidence; stderr has its own log.
The runner requires all 18 named top-level real-authentication tests plus the
package pass. Any skip (including a subtest), failure, malformed output, or
missing expected test makes this suite fail, rather than reporting integration
success from ordinary unit-test success.

## Experimental native regression

Additional prerequisites: `autoconf automake libtool libtool-bin gettext
libssl-dev libxml2-dev zlib1g-dev` and make. On a prepared Linux host:

```sh
python3 integration/loopback/run.py native \
  --native-build "$PWD/build/loopback-native" --reports reports/loopback-native
```

The native destination must not already exist. Preparation verifies the bundled
upstream archive and applies the entire recorded patch chain. This entry point
requires the bundled archive and never downloads a missing one. Required test
sources must exist after patching, so the legacy build script's conditional
checks cannot silently omit the UniVPN fixtures. It then runs the existing
native build/regression script with script-TUN sockets, local TLS, inherited
packet sockets and syscall-wrapped TUN/netlink tests, not a kernel TUN. Logs
and an explicit `live_vpn_acceptance: false` summary are written under reports.
These tests are regression checks, not an OS-enforced malicious-code sandbox.
Do not run the production worker bootstrap or install a privileged service.

## Runner regressions and evidence limits

```sh
python3 -m unittest discover -s integration/loopback -v
```

The tests cover fail-closed evidence parsing and real patch application inside
a nested Git checkout, including inherited Git directory overrides. Preparation
must isolate Git discovery: otherwise `git apply` can find the parent repository
and return success while silently skipping all extracted-tree paths.

Six runner/preparation tests passed during this change. The current editing
host lacks the required Go/C development dependencies, so it did **not** execute
real authentication or compile/run native fixtures. The new CI results, not
this local parser result or old archived fixture logs, establish whether those
suites pass for a specific commit. Retain `reports/loopback-*` even on failure.
