# Real GNOME Keyring disposable-container acceptance

This opt-in suite runs the distribution's **real gnome-keyring-daemon**, with only
synthetic passwords and a synthetic nonempty keyring master password. It is
separate from the in-memory wire fixture. Nothing is enabled in the application.

## Required CI boundary

Run only in a fresh GitHub Actions job container (for example the repository's
Debian trixie-slim test container), with no host HOME, runtime, D-Bus socket,
credential or device mounts. Install official `gnome-keyring`, `dbus-daemon`,
`ca-certificates` and `git` packages using the distribution archive. Use
`--no-install-recommends`, so optional UI/PAM packages are not requested. Package
maintainer scripts are scoped to that disposable image, not a real host.

Provision an unprivileged fixture user in the container, prepare the repository
and pinned Go toolchain, then invoke:

```
runuser -u meridian-gnome-ci -- env PATH="$PATH" GOTOOLCHAIN=local \
  GITHUB_ACTIONS=true MERIDIAN_GNOME_CONTAINER_TESTS=1 \
  GOPATH=/home/meridian-gnome-ci/go GOCACHE=/home/meridian-gnome-ci/.cache/go-build \
  bash integration/credentialstore/run-gnome-tests.sh
```

The script and Go test both require explicit opt-in, `GITHUB_ACTIONS=true`, the
Docker job marker and a non-root UID. These are misuse guards, not cryptographic
proof of isolation: the CI job must actually provide the disposable boundary.
A missing package or readiness failure fails the suite; it is not skipped.
The CI worker owns workflow integration; no shared workflow is edited here.

## Safety properties

- The daemon gets a fresh, minimal environment, dedicated temporary HOME,
  XDG_DATA_HOME, XDG_CONFIG_HOME, XDG_CACHE_HOME, XDG_RUNTIME_DIR and control
  directory, all under an owned 0700 temporary root.
- The session bus is the test's private Unix bus, with no activation directories.
  The system-bus address points at a nonexistent socket in that same temporary
  root. Host bus/environment selectors are never inherited.
- Only `--foreground --components=secrets --control-directory=<temporary>
  --unlock` is used. Never `--replace`, SSH/PKCS11 components, PAM integration,
  daemon-output eval, or the actual user's session/runtime directory.
- The synthetic master password travels through a pipe, never argv, environment,
  log or configuration. It is nonempty; this is not a passwordless-keyring test.
- Only temporary synthetic keyring files are created. The test deliberately
  exercises persistence across daemon restarts, then deletion persistence.
- Daemons receive TERM, have a bounded grace period, then are killed and reaped
  by their own process handle. Cleanup removes only the generated temporary root.
  A 120-second Go timeout and disposable container bound abnormal termination.
- Output is only test JSON and tool versions. Daemon stdout/stderr, synthetic
  keyring files, temporary HOME and D-Bus traffic must never be uploaded.

## Evidence produced

`TestCredentialGNOMERealLifecycle` exercises actual CreateItem/GetSecret/
SetSecret/Delete behavior through Store/execute/systemBus, including:

1. Missing item, save, read, replace, and replacement read.
2. Stop/restart/unlock with the same synthetic master password and confirm the
   replacement survives. This demonstrates persistence, not an encryption audit.
3. Create a second synthetic matching item using the real Secret Service API;
   reject ambiguous lookup and explicitly delete only that fixture duplicate.
4. Lock the real collection and ensure reads and writes fail closed without a
   prompt or silent replacement. Restart/unlock and confirm the original value.
5. Delete, confirm absence, restart again, and confirm deletion persisted.

The protocol fixture separately covers deterministic timeout and owner-switch
fault injection. This suite does not claim KWallet, other Linux distributions,
macOS/Windows credential storage, production NewSystem peer/path checks, hostile
wire decoding, UI consent, power-loss durability or encryption-at-rest review.

## Dependencies and current status

No new Go module is needed. `gnome-keyring-daemon` is an external GPL-2.0-or-later
test dependency according to its upstream source; D-Bus's upstream licensing is
GPL-2.0-or-later/AFL-2.1, with some files having narrower terms. Neither executable
is bundled into Meridian application artifacts. Preserve the exact distro
copyright/license records if redistributing a CI image.

The local editing environment has no working Go toolchain and did not start any
keyring service. Shell syntax and whitespace checks are not real acceptance.
The exact CI commit must compile and pass this suite before reporting success.

Official references reviewed:

- [GNOME daemon options](https://github.com/GNOME/gnome-keyring/blob/master/docs/gnome-keyring-daemon.xml)
- [GNOME daemon startup implementation/license](https://github.com/GNOME/gnome-keyring/blob/master/daemon/gkd-main.c)
- [D-Bus daemon configuration](https://dbus.freedesktop.org/doc/dbus-daemon.1.html)
- [D-Bus licensing](https://github.com/d-bus/dbus/blob/master/COPYING)
