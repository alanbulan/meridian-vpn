# Production Secret Service entry: isolated-container acceptance

This is an additional opt-in suite for `NewSystem`, not the protocol-only
`execute` fixture. It uses the actual fixed `/run/user/<fixture uid>/bus` path.
Never run it on a workstation, a persistent runner, a container with host runtime
or credential mounts, or a container sharing another user's session.

## Provisioning and invocation

Use a fresh disposable GitHub Actions job container with no host HOME, runtime,
D-Bus, credential or device mounts. Install the official distribution packages
and pinned Go toolchain listed in GNOME.md, plus `util-linux` (runuser), `coreutils`
and `libc-bin` (getent), from the distribution archive. Create a dedicated
non-root fixture user with a writable HOME/cache and checkout. Do not prepare
`/run/user/<uid>`: the runner requires it to be absent and creates it exclusively.

Run the root bootstrap inside that disposable container only:

```sh
GITHUB_ACTIONS=true MERIDIAN_PRODUCTION_CONTAINER_TESTS=1 \
  bash integration/credentialstore/run-production-tests.sh meridian-gnome-ci
```

The root shell checks its own UID, opt-in, Docker marker and parent directory
ownership/modes. An existing runtime path, including a dangling symlink, is a
hard failure: it is never inspected, chmodded, replaced or removed. The bootstrap
creates only the missing container runtime parent and an exclusive 0700 directory
owned by the fixture UID. All Go, D-Bus and GNOME processes run unprivileged.
Neither the marker nor the environment flags prove isolation; the job definition
must provide that boundary. There is intentionally no shared workflow change.

The test gets a minimal environment. GNOME additionally uses its existing fresh
HOME/XDG/control fixture directories and synthetic pipe-only master password.
The private bus has no activation directories. Daemon output and keyring files
are not artifacts; only the Go JSON test results may be retained.

## Coverage

- `NewSystem` with a missing fixed-path bus and with no Secret Service owner
  rejects reads without returning bytes.
- The real same-UID bus, EXTERNAL authentication, peer UID check, owner resolution
  and owner UID check lead to a fresh real GNOME collection. Synthetic
  save/load/delete work through the full production entry.
- Misleading session/system bus environment variables and XDG_RUNTIME_DIR cannot
  redirect that entry; the fixed isolated socket must still be used.
- Directory modes 0750, 0755, 0770 and 0777 reject read/save/delete. After restoring
  0700, the original synthetic password remains, proving the rejected mutations
  did not replace or delete it.
- Deletion yields not-found; service departure yields unavailable.

## Cleanup and limits

Cleanup stops/reaps only the spawned service/bus processes. If killing the private
bus leaves a socket, the test unlinks only its recorded socket inode. The bootstrap
removes only its originally created directory via `rmdir` after checking device
and inode identity. It never recursively removes a runtime directory; unexpected
leftovers fail the run and are left to whole-container disposal. A hard test
process timeout may bypass Go cleanup, so container disposal remains mandatory.

This first suite positively exercises peer and service owner UID verification,
but does **not** yet test a wrong-UID bus peer, wrong-UID service owner or runtime
directory owner. Those require a separately reviewed two-UID/root-supervised
fixture. It also does not prove service-owner replacement safety (covered only
by the private wire fixture), compatibility with other Secret Service providers,
real desktop permissions, visual/native GUI behavior, or Windows/macOS stores.
No suite has been executed in the editing environment. Successful CI on the exact
commit is required before claiming the covered behavior has been validated.
