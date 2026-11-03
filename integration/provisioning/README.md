# Offline UniVPN provisioning preparation

This checkpoint adds an executable **offline artifact verifier and workspace
stager**, not a system installer, service, rootfs distribution, or activation path.
It does not create users/cgroups, install files, execute binaries, call a package
manager, change permissions outside its new workspace directory, use sockets, or
change TUN/routes/DNS. No systemd unit or post-install hook is supplied because
there is no reviewed runnable service entry point. Default UniVPN remains disabled.

## Reviewed input contract

Provide a dedicated bundle directory and a separately reviewed JSON manifest:

```json
{"version":1,"files":[{"path":"rootfs/bin/meridian-univpn","sha256":"<64 lowercase hex characters>","mode":365,"size":12345}]}
```

The illustration is intentionally incomplete and cannot pass. All inventory
entries must include exact path, digest, decimal mode (292 = 0444, 365 = 0555),
and positive size. Required files:

- `rootfs/bin/meridian-univpn` and `bootstrap/meridian-worker-bootstrap` (0555).
- `licenses/OPENCONNECT-LGPL-2.1.txt`, `licenses/UNIVPN-CONNECT-MIT.txt`, and
  `licenses/THIRD_PARTY_NOTICES.md`. Preserve the original complete notices from
  `integration/univpn-native/licenses/` and applicable source/relink obligations.
- The explicitly reviewed loader/libraries/providers under rootfs `lib/`, `lib64/`,
  `usr/lib/`, and CA/OpenSSL configuration under `etc/ssl/` as needed. No other
  inventory paths are accepted. Loader symlinks must be materialized as reviewed
  regular files at the exact runtime paths, each separately hashed.

The manifest is an administrator/release-review trust input. A SHA digest is not
a signature or proof of safe code. Do not generate a manifest from untrusted
artifacts and call that verification. The tool checks byte equality, not library
closure, ELF correctness, configuration safety, license compliance or provenance.
The existing Go worker constructor separately checks bootstrap ELF structure
and both bootstrap/native hashes at launch; it does not parse native ELF structure. Provider/library loading and the conservative seccomp policy
still require VM validation. Never include private keys, account exports, gateway
credentials, host config, or personal certificate material in the rootfs bundle.

Manifest input is bounded to 2 MiB, 4096 files, 64 MiB/file, 256 MiB total. Unknown
fields, duplicate JSON keys/paths, ambiguous paths, writable/special-mode files,
symlinks, hardlinks, devices/FIFOs/sockets, extended file attributes (including
capabilities), extra files/directories and missing inventory entries are refused.
The verifier uses fd-relative NOFOLLOW traversal, detects file metadata changes,
and hashes the exact in-memory bytes later copied. It does not run `ldd` or any
artifact. Source directories may be owner-writable for workspace use, but never
group/world-writable or special-mode. This is **not** deployed immutable-root
validation, an ancestry audit, a mount-topology proof or protection from a hostile
owner/root mutating the workspace concurrently.

```sh
python3 provision.py --manifest reviewed-manifest.json --bundle ./reviewed-bundle
python3 provision.py --manifest reviewed-manifest.json --bundle ./reviewed-bundle --stage-parent ./workspace-output
python3 -m unittest -v
```

The first command is read-only. The second creates a new mode-0700
`meridian-offline-*` child in an existing trusted workspace directory. It never
replaces an existing deployment. The output contains verified bytes, sorted
manifest and `installation-plan.json`, whose activation and service enable/start
flags are always false. The manifest is outside the artifact inventory; to
reverify staged bytes, use a dedicated copy of only inventory paths, not the
whole output including plan/manifest. Source/output nesting is refused by CLI.

Staging requires a trusted parent with no concurrent external mutation. A failure
rolls back journaled paths in reverse order only when their inode/device identities
still match; replacements are retained, and cleanup failures report uncertainty.
It does not recursively erase arbitrary directories. Successful output belongs
to the caller; no automatic cleanup or installation follows. A crash/power loss
can leave an incomplete private directory: quarantine and inspect, do not use it
as an installed image. No crash-durable activation transaction is claimed.

## Identity and cgroup provisioning plan

Optional `--passwd-export` and `--group-export` accept a pair of administrator-
supplied NSS snapshots. Any occurrence of UID/GID 65532, the worker account name,
or an account with that primary GID is a conflict, even if the account looks like
ours. No account is adopted/reused automatically. The exports are never embedded
in the output. Empty/stale/incomplete exports or `/etc/passwd` alone cannot prove
live NSS uniqueness, remote mappings, process absence or reservation. A trusted
installer must reserve the fixed identity, refuse conflicts, verify all NSS
sources and active processes, and maintain exclusive identity use through runtime.
Do not copy account exports into a release artifact.

The generated plan names fresh dedicated cgroup v2 `domain`, cpu/memory/pids
controllers, initial proposed memory 256 MiB, pids 16 and one-CPU quota. These are
review starting limits, not empirically established native capacity. A future
manager must establish protected root-owned ancestry and controller delegation,
create only its own unique empty group, configure limits before launch and read
them back. Integrate the pinned FD with `processcontainment.Adopt` and atomic
`CLONE_INTO_CGROUP` start; never move an already-running PID as fallback. After any
start attempt, prove hierarchical emptiness through KillAndWait before removing
only that same created cgroup. Retain ownership and quarantine on uncertainty.
Never remove a preexisting group, reclaim a reused UID, change a manager-owned
parent controller set, or recursively delete a hierarchy as rollback.

No cgroup evidence snapshot, directory lock, dedicated UID or private worker
network namespace establishes exclusive host routing/resolver control. This
remains a separate release blocker. Rootfs ownership, immutable mount layout,
UID reservation and cgroup creation are **not implemented** here; the preparation
closes artifact-integrity/configuration work without pretending to install them.

## Future Linux packaging policy

No package is built or installed in this checkpoint. A future Debian package must
suppress both automatic enabling **and** starting (debhelper's `--no-enable
--no-start`), and review upgrade/uninstall behavior separately. Do not overwrite
administrator changes or auto-restart a quarantined backend. Presets alone are
not a reliable disabled default because administrator/distribution precedence can
override them; systemd recommends centralized distribution preset policy. No fake
`ExecStart=/bin/true` or activation marker is used as a security boundary here.

Primary references consulted:
- [Debian dh_installsystemd](https://manpages.debian.org/testing/debhelper/dh_installsystemd.1.en.html)
- [systemd preset policy and precedence](https://www.freedesktop.org/software/systemd/man/latest/systemd.preset.html)
- [systemd execution sandboxing](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)

Tests use temporary fixture files and injected failures only. They never run an
actual native worker/bootstrap, configure a user or cgroup, or use real credentials.
