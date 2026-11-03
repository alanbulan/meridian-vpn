# Native worker bootstrap checkpoint (Linux x86-64 only)

This is a concrete **opt-in integrated but not VM-validated** trusted bootstrap, not a
production-ready UniVPN isolation provider. `make all` builds a static executable;
`make test` runs only injected stage failures and a userspace seccomp interpreter.
Neither target executes the production bootstrap or changes host security,
namespaces, mounts, credentials, network configuration, TUN, DNS or cgroups.
Do not install it setuid, run it manually, or enable UniVPN on this checkpoint.

## Trust and input contract

A reviewed privileged broker/service manager must:

- Reserve UID **65532** and GID **65532** exclusively for this worker service.
  Do not reuse an existing nobody/container/application identity. Refuse deployment
  on conflict. Untrusted host processes with that identity are outside this
  boundary: ordinary exec resets dumpability to 1. The bootstrap's dumpable=0
  protects its pre-exec phase only; it does NOT prove a nondumpable native worker.
- Provision a fresh dedicated domain cgroup, resource limits (including memory,
  CPU and pids), and protected parent hierarchy. Apply all requirements of
  `internal/processcontainment/README.md`. No external actor may move members or
  change the cgroup while the session is alive.
- Pin and verify the static bootstrap executable and its immutable root-owned
  pathname. No interpreter, dynamic bootstrap loader, caller-chosen executable,
  caller environment or setuid installation is accepted. This code is not a
  generic privileged launcher and must not be exposed as one.
- Provision `/var/lib/meridian/worker-root` as an immutable, minimal root-owned
  inventory: exactly the reviewed native `/bin/meridian-univpn`, its required
  loader/libraries, reviewed OpenSSL configuration/provider files and approved
  CA material. No host secrets, shell, auxiliary executables, proc, sysfs,
  cgroupfs, namespace handles, sockets, devices, writable paths or host bind views.
  Review symlinks and native/library hashes. A root-owned top directory does NOT
  establish this inventory. Keep ancestry, contents and host mount topology
  protected from changes for the session. The bootstrap validates the symlink-free
  fixed ancestry and pinned root inode, not every rootfs file or administrator.
- Construct a new bootstrap command using the broker's validated native arguments
  (including all mandatory session/transport/packet flags), a fresh minimal env,
  and exactly these explicit descriptors:

  | FD | Role |
  | --- | --- |
  | 0 | Read-only password pipe, no secret in argv/environment |
  | 1, 2 | Write-only `/dev/null`, never a broker channel |
  | 3 | Write-only session pipe |
  | 4, 5 | Distinct connected IPv4 TCP control/data sockets from fdtransport |
  | 6 | Unnamed nonblocking connected AF_UNIX SOCK_SEQPACKET packet endpoint |
  | 7 | Pinned root directory matching the fixed immutable root path |
  | 8 | Read-only SHA-pinned static bootstrap image, closed before native |

  Use `fdtransport.Prepare` to verify the **approved** peer, not just equality of
  both peers. Bootstrap independently verifies socket types, TCP protocol, equal
  peers, distinct inode identities and FD directions. `packetrelay` retains the
  opposite endpoint and the host TUN. The broker packet peer must never send
  SCM_RIGHTS/SCM_CREDENTIALS or act as an arbitrary descriptor broker. Native has
  no TUN, broker control, cgroup or namespace descriptor. Every nonlisted broker
  FD must already be CLOEXEC; close_range also removes all child FDs >=8 early.
  FD8 exists only for exact-image bootstrap exec through /proc/self/fd/8.
- Never send secrets to an unverified bootstrap image. Its trusted code does not
  read FD0: native reads only after every isolation operation succeeds. Exec start
  alone is not sandbox readiness; only the native authenticated session protocol
  after this verified bootstrap can progress the session.

## Exact launch and failure sequence

1. `processcontainment.Adopt` validates and pins the manager's empty cgroup. Pass
   the bootstrap command to `Group.Start`, which uses CLONE_INTO_CGROUP before
   any bootstrap/native instruction. Do not move a running PID as a fallback.
2. Static single-threaded bootstrap rejects non-root initial real/effective
   UID/GID, discards environment, limits core dumps, resets signal dispositions
   and mask, and makes its own pre-exec phase nondumpable.
3. Validate descriptor roles/identities, fixed root path and root FD. Close >=8
   with mandatory close_range. No proc scan or guessed upper bound is used.
4. `unshare` fresh mount/network/IPC/UTS namespaces, then make mount propagation
   recursively private. No interfaces are added or brought up in the new network
   namespace. The already-connected host TCP descriptors remain usable.
5. Nonrecursive bind the fixed minimal root onto itself (no inherited submounts).
   Traverse its **absolute** path to enter the new mount and recheck root inode.
   Use mount_setattr recursively for readonly/nosuid/nodev, pivot_root(".","."),
   detach the stacked old root, and chdir("/"). Unsupported calls fail closed.
6. Close all FDs >=7, including root handle. Limit open FDs to 64.
7. Clear ambient capabilities; drop and read back each supported bounding-set
   capability; lock NOROOT, NO_SETUID_FIXUP and KEEP_CAPS security bits. Clear
   supplementary groups and set all real/effective/saved GID and UID to 65532.
   Zero permitted/effective/inheritable sets with capset and verify with capget;
   read back all IDs/groups. Mark the bootstrap nondumpable again after UID change.
8. Set/read back no_new_privs. Install the x86-64 LP64 seccomp allowlist, with
   unknown ABI/syscalls defaulting to KILL_PROCESS. No runtime policy file or
   permissive fallback exists. x32 and i386 are rejected. Fork/clone, namespace
   creation/entry, mounts, socket creation/connect, ioctl, ptrace, process_vm,
   pidfd_getfd, signal sending, io_uring, bpf and keyring are unavailable.
   recvmsg is only allowed on FD6. sendto is limited to FDs4..6 with no destination.
   fcntl only supports GETFD/GETFL and constrained SETFD/SETFL, not signal ownership
   or O_ASYNC. TCP_NODELAY is the only setsockopt allowed, on FD4/5 with int
   length only. prlimit64 may only query self, never change limits. pipe/pipe2
   supports the native internal command pipe, with pipe2 flags bounded to
   CLOEXEC/NONBLOCK. Read-only rootfs plus FD closure provides filesystem isolation;
   seccomp cannot inspect path strings or msg_control contents.
9. Exec exactly `/bin/meridian-univpn` with LANG=C, LC_ALL=C and HOME=/.
   There are no hooks or child helper programs in this mode. The filter survives
   exec and forbids process creation. Any stage error immediately returns an exit
   code 100..107; any exec return exits 108. Argument absence exits 99. No secrets
   or raw syscall errors are printed. Failures never continue to native.
10. Broker must reap the leader and call `Group.KillAndWait` even on failed start,
    bootstrap failure, cancellation or native leader exit. Only hierarchical
    empty-state proof permits closing handles and release of network resources.
    Uncertainty retains ownership/handles and is not success. No host lease is
    supplied by this bootstrap.

## Opt-in Go integration

`NewUniVPNWorkerIsolation` in `internal/core/univpn_worker_bootstrap_linux.go`
accepts a concrete manager-adopted `*processcontainment.Group`, a CLOEXEC pinned
root directory, bootstrap path/hash and native hash. It checks the **actual
fixed-root native image hash**, not merely a separate host executable; validates
static x86-64 ELF; and duplicates/verifies the root identity. Constructor failure
does not take ownership of the caller's Group or Root. Success transfers Group
ownership and retains its own Root duplicate and bootstrap FD. The caller must
call RollbackLaunch(ctx,nil) if never handing it to Launch.

Use this instance as `UniVPNExecLauncher.Isolation`, with native session,
fdtransport and packet providers all present. The launcher requires its native
SHA to equal the root-image SHA. A private opt-in command-wrap step changes Path
to `/proc/self/fd/8`, supplies the exact verified bootstrap FD8 and root FD7, and
opens stdout/stderr as `/dev/null`. This happens BEFORE the existing immutable
command snapshot. `Prepare` still cannot alter protected launch fields. A private
atomic-start method dispatches to Group.Start instead of direct cmd.Start, and
there is no fallback to an uncontained start. Calls for another command or a
second launch are rejected. Teardown uses KillAndWait then Close; root/bootstrap
handles stay retained on uncertain termination. Early validation/acquisition
failures also clean the owned group. Failed FD closes are not blindly retried.

Approved native CA paths must exist with approved contents **inside** the minimal
root. This adapter does not manufacture the image, validate the full library/
provider inventory, reserve a UID, create a cgroup or satisfy host network leases.
Those remain trusted provisioning/release obligations, not boolean attestations.
No default application constructor selects this adapter, and normal UniVPN
availability remains disabled. Running it is NOT authorized by running its tests.

## What has and has not been verified

Passed: strict static compilation and no ELF interpreter, every injected stage
failure prevents later stages/exec, exec-return failure, userspace evaluation of
ABI rejection, forbidden syscalls, fd-number/high-word checks, sendto destination
restrictions, fcntl command/flag restrictions and narrowly bounded compatibility
syscalls. Injected Go adapter tests cover exact command/FD binding, atomic start,
repeated/foreign-command rejection, early failure/cancellation cleanup and
uncertain cleanup retaining handles. The default Go suite passes with existing
real-network and Unix credential tests skipped; targeted Go race tests pass. Mock tests do not execute or
prove kernel credential, capability, mount, seccomp or namespace behavior.

Required before production activation: an authorized disposable VM must exercise real
launch through Group.Start, inspect IDs/capabilities/seccomp/namespaces/FDs both
before and after native exec, validate the rootfs inventory and loader/provider
access, prove bootstrap failures never consume credentials, deny all escape and
FD-reception attempts, and verify failed-launch/cancellation/cgroup teardown.
The conservative syscall allowlist has NOT been tuned against a real sandboxed
native session; omitted calls intentionally kill rather than broadening it.
A native call rejected during VM tests needs specific review, not automatic
allowlisting. Startup/fork/descendant and exec-dumpability tests are mandatory.
Real gateway compatibility, host TUN/route/DNS ownership and the exclusive host
network lease remain independent, unresolved release gates.

## Primary references consulted

- [Kernel no_new_privs](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kernel seccomp filters](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Linux unshare](https://man7.org/linux/man-pages/man2/unshare.2.html)
- [Linux pivot_root, stacked-root sequence](https://man7.org/linux/man-pages/man2/pivot_root.2.html)
- [Linux mount_setattr](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)
- [Linux close_range](https://man7.org/linux/man-pages/man2/close_range.2.html)
- [Kernel cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
