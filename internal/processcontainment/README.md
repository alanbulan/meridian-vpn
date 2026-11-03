# Cgroup v2 lifecycle primitive (Linux only)

This package has an opt-in UniVPN worker-bootstrap adapter, but is **not wired
into default UniVPN deployment**. See `integration/worker-bootstrap/README.md`. It is not
an isolation provider, network-ownership lease, or a complete sandbox. Unit tests
inject all kernel operations and process starts. No cgroup/security settings were
changed and no privileged process was launched for this checkpoint.

## Implemented boundary

`Adopt` duplicates a trusted manager-provisioned, empty cgroup directory FD. It
requires the original FD already be CLOEXEC (the caller must preserve that), and
checks the cgroup2 filesystem, root-owned directory with no group/world write,
`domain` type, root-owned regular controls on the same cgroup2 filesystem,
`cgroup.kill` availability and strict `populated 0`/`frozen 0`. Fixed-name
controls are opened relative to the held directory, with NOFOLLOW and CLOEXEC.
The package neither creates directories nor reacquires a group by its name.

`Start` holds the directory alive across `exec.Cmd.Start`, selects Go's
`UseCgroupFD`/`CgroupFD` path, and never falls back to moving an already-running
PID. It preserves other configured launch attributes. A kernel without usable
clone3/CLONE_INTO_CGROUP fails the start. The target command must already be a
reviewed bootstrap; launching a privileged native VPN worker directly is unsafe.
Aliases of held cgroup descriptors are rejected by device/inode identity across
ExtraFiles and file-backed standard streams. A bootstrap must still restrict all
other powerful descriptors and paths.
The command is exclusive to this lifecycle and must not be started again through
another reference. Caller mutation concurrent with Start is not supported.

`KillAndWait` writes exactly `1` to the pinned kill control and checks hierarchical
populated state from the pinned events FD until empty, error or a maximum two
seconds, including waiting for a concurrent Start to finish. A pending Start
returns uncertainty and retains handles; it is never treated as an empty group.
It refuses malformed/duplicate/missing state and short writes. Failed
starts require this same cleanup proof. Failures retain handles for retry;
`Close` refuses to discard attempted-launch handles until termination succeeds.
Close returns a busy error rather than waiting on a pending Start or cleanup.
Close failures are sticky and no close is retried on a potentially reused FD.
Group directory removal belongs to the provisioning service, not this package.

The Go 1.27.3 toolchain used here routes UseCgroupFD through clone3, setting
CLONE_INTO_CGROUP. Atomic placement is documented in
[clone(2)](https://man7.org/linux/man-pages/man2/clone.2.html).
The meaning of hierarchical populated state and subtree kill is documented in
[Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html).

## Mandatory external prerequisites, not assertions this API proves

- A trusted service manager supplies a fresh dedicated non-root domain cgroup,
  excludes unrelated members and protects its parent hierarchy, permissions,
  membership and descendant groups for the entire session. A directory's uid,
  mode and empty-state readback alone do **not** establish these properties.
- Before native execution, a reviewed bootstrap must deny migration out of the
  group. No writable cgroup filesystem/FD, host proc view, namespace handles,
  powerful inherited credentials, or broker-control Unix socket can be exposed.
- Complete sandboxing must include a dedicated non-root identity with no
  supplementary groups/capabilities, appropriate filesystem/mount and network
  namespaces, restricted inherited FDs, no-new-privileges, and a reviewed syscall
  policy. Neither a cgroup nor an empty network namespace supplies all of these.
- A hostile host root/service manager or administrator changing these
  prerequisites is outside the threat model. No snapshot of process membership
  can prove the absence of future external migrations or permission changes.

No-new-privileges survives exec and prevents exec-based privilege gains; it does
not remove privileges already held or stop receipt of privileged descriptors.
[Kernel no-new-privileges documentation](https://docs.kernel.org/userspace-api/no_new_privs.html)

Seccomp is one layer, not a complete sandbox. Its bootstrap and ABI-aware policy
must be audited and tested in an authorized disposable VM. Go's SysProcAttr in the
current toolchain does not provide a general safe child pre-exec callback for
installing this policy. Calling prctl/setns in the broker's multithreaded runtime
is not an acceptable substitute. A separate static C bootstrap and concrete opt-in Go adapter now exist under
`integration/worker-bootstrap`; their injected tests do not replace the mandatory
authorized VM/kernel validation gate.
[Kernel seccomp documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)

## Why the exclusive host network lease remains unavailable

An open single-queue, nonpersistent TUN can bind device lifetime to broker-owned
FDs. It does not stop another host CAP_NET_ADMIN actor from changing the device,
route table, or namespace. A random name/alias, ifindex, netns FD, flock, or cgroup
cannot revoke those other actors' authority. Resolver configuration is a separate
writer surface. A runtime boolean claiming exclusivity would be a false proof.
[Kernel TUN documentation](https://docs.kernel.org/networking/tuntap.html)

There is deliberately no implementation returning success for UniVPNNetworkLease
or UniVPNHostLeaseProvider. Existing broker activation remains disabled. The exact
missing prerequisite is either an administrator-enforced, reviewed exclusive
network/resolver control domain, or an explicitly redesigned contract trusting
host network managers and handling conflicts without blanket exclusivity. A
private namespace containing both VPN and consuming applications is another
possible product, but does not deliver transparent host-wide routing/DNS.

## Acceptance before integration

An authorized disposable VM must demonstrate launch ordering; effective UID,
capabilities, seccomp and namespace identities; failed migration/namespace/socket
escape; forked descendants surviving leader exit and still being killed; no
unlisted inherited FDs; clone3 rejection without fallback; cancellation and
bootstrap/kill failures. Real gateway, TUN and host DNS/routing tests remain
separate gates. Mock tests here establish control flow only, not those properties.
