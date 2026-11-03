# Isolated Secret Service wire tests

These are opt-in **real D-Bus transport tests with an in-memory Secret Service
fixture**, not GNOME Keyring/KWallet acceptance and not real VPN authentication.
Only synthetic hard-coded passwords exist. No installed keyring daemon is used.

Run in an authorized disposable Linux CI container with Go and the distribution's
`dbus-daemon` package installed:

```
bash integration/credentialstore/run-wire-tests.sh
```

No production code/test hooks or system settings change. The normal `go test
./...` suite does not compile these tests. Explicit build tag
`credentialintegration` and runner variable `MERIDIAN_CREDENTIAL_WIRE_TESTS=1`
are both required. A missing daemon is a failure, never a skipped acceptance.

## Isolation and cleanup

- Every test creates its own 0700 directory under `/tmp`, a 0600 bus config and
  Unix socket. The daemon runs `--nofork --nopidfile --nosyslog` with a minimal
  environment and a custom config with no includes, service directories,
  activation helper, standard session services or TCP listener.
- Neither client nor fixture reads caller D-Bus addresses. The shell also unsets
  session/system/starter bus selectors. The production fixed `/run/user` path is
  never opened by these tests.
- Normal test cleanup kills/reaps only the child daemon PID and removes its
  temporary directory. The dedicated disposable CI job adds an always-run
  fallback that kills processes belonging only to its newly created fixture UID
  and removes that UID's matching temporary directories. Container teardown is
  the final fallback after forced job termination; no host user or global
  process-name kills or system service controls are used.
- All connections have bounded contexts; daemon readiness and blocked-reply tests
  have deadlines. Go's overall test timeout is 60 seconds. Use a disposable CI
  container so even forced runner termination cannot leave persistent processes
  or files on a user's desktop.
- The fixture keeps synthetic records in memory and clears owned slices during
  update/deletion/cleanup. Outputs contain test results and dependency versions,
  not password contents or raw D-Bus payloads. Do not enable D-Bus monitoring,
  shell tracing, or upload temporary directories/HOME.

## Coverage

Actual D-Bus encoding, method dispatch, reply decoding and named errors exercise
`systemBus`, `execute` and the Store consent/error layer:

- Create, load, replacement and delete; missing record before and after deletion.
- Locked item and collection; no silent overwrite.
- Duplicate search results fail closed; deleted item's explicit NoSuchObject
  error maps to ErrNotFound.
- Blocked GetSecret reply respects context timeout and returns no secret.
- Replacing the well-known service owner never redirects a pinned operation.
  A live original owner stays pinned; a disconnected original fails closed.

The test bus limits messages to 64 KiB. This **does not add an equivalent cap to
production godbus decoding**, nor validate malformed hostile D-Bus frames.
Tests do not exercise NewSystem's fixed runtime-directory/peer-UID checks or
SASL deadline edge cases. Those remain separate release gates.

## CI integration snippet

Add a dedicated job to the independent credential-development PR, not main or
platform-preview PRs. Use a disposable official Debian container, install only
official archive packages, then run tests as an unprivileged fixture user:

```
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates git dbus-daemon
# Use the repository's pinned checkout/setup-go actions and Go version.
useradd --create-home --shell /bin/bash meridian-wire-ci
chown -R meridian-wire-ci:meridian-wire-ci "$GITHUB_WORKSPACE"
runuser -u meridian-wire-ci -- env PATH="$PATH" GOTOOLCHAIN=local \
  GOPATH=/home/meridian-wire-ci/go GOCACHE=/home/meridian-wire-ci/.cache/go-build \
  bash integration/credentialstore/run-wire-tests.sh
```

Use a job timeout and upload only `reports/credential-wire/`. Installing these
packages is scoped to the ephemeral CI container, not the user's machine.
No extra Go module dependency is required beyond the existing godbus module.
D-Bus daemon is an external GPL-2.0-or-later/AFL-2.1 dual-licensed test tool;
this change does not bundle it in Meridian artifacts. Verify the exact distro
package copyright file if distributing a test image.

Source: [official dbus-daemon manual](https://dbus.freedesktop.org/doc/dbus-daemon.1.html).
The manual explicitly supports special-purpose buses via custom configuration.

## Still required before enabling password persistence

1. Run this suite on the exact development commit; retain its JSON/exit status.
2. Test a real provider in a separate disposable user/container with an entirely
   temporary HOME, XDG_DATA_HOME and private bus. Launch the provider explicitly,
   never through the host session, and use synthetic secrets. Provider-specific
   unlock/lock fixtures and cancellation must be reviewed before execution.
3. Exercise the production entry point in that container's private `/run/user`
   namespace, including wrong socket UID/permissions, service disappearance and
   blocked SASL. Never repoint the host user's runtime directory to a test bus.
4. Continue UI per-operation consent, thread/cancellation and security review.

Until actual CI execution, this file and the tests are a plan and implementation,
not passing integration evidence.

## Real-provider follow-on feasibility (not executed)

The upstream GNOME daemon supports `--foreground`, `--components=secrets`, a
private `--control-directory`, and `--unlock` reading a password from stdin.
This permits a separate container-only test with all HOME/XDG paths redirected
to an owned temporary directory, an explicit private bus address, and a nonempty
synthetic master password through a pipe. Do not use `--replace`, inherited
`GNOME_KEYRING_CONTROL`, SSH/PKCS11 components, PAM integration or host mounts.
A shell must never eval daemon output. Creation of a synthetic login collection
is a deliberate test-only side effect and must remain inside that disposable
container. Verify actual daemon foreground/exit semantics before CI adoption.
This follow-on can validate a real provider's at-rest restart and lock behavior;
it is not covered by the current in-memory fixture.

Sources: [GNOME daemon upstream manual](https://github.com/GNOME/gnome-keyring/blob/master/docs/gnome-keyring-daemon.xml)
and [D-Bus upstream license](https://github.com/d-bus/dbus/blob/master/COPYING).
