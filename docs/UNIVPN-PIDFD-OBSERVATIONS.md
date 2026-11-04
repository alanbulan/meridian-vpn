# Creation-time native pidfd observations

`UniVPNNMBroker.ObserveNativeNamespaces(ctx)` is an optional, read-only diagnostic
API for the broker's own concrete native child after its offer has been bound.
It is not a host binding or host authority, does not issue a lease, and is not
connected to activation, publication, network policy, or application readiness.

## Provenance and ownership

The concrete launcher supplies its own `syscall.SysProcAttr.PidFD` output slot
before `cmd.Start`. Containment preparation may not replace or write that slot.
The concrete cgroup starter copies `SysProcAttr` and preserves the pointer when
adding `CLONE_INTO_CGROUP`. The resulting descriptor therefore comes from child
creation, including a bootstrap-to-native exec of that same child. It is not
opened later using a numeric PID. There is no `pidfd_open`, arbitrary-PID API,
user-supplied descriptor, or procfs lookup in this namespace observer.

The supplied descriptor remains caller-owned: Go's `os.ensurePidfd/getPidfd`
duplicates it for the independent `os.Process` handle. The launcher transfers
its descriptor to the process lifecycle exactly once. `Wait` closes it. Early
launch failures close any returned descriptor; Go's own failed-exec cleanup
normally resets the slot to `-1`. A nonnil partial-launch child is still returned
with the error so its sole `Wait` owner is retained. The NM broker already accepts
that ownership on error. The generic broker quarantines such a partial launch,
never calls readiness, and retains Stop/Wait plus cleanup ownership. This is
conservative contract hardening: the current concrete `Group.Start` directly
returns `cmd.Start` and has no additional post-success error path.

The existing proc-based `ObserveNativeProcess` API remains separate and retains
its existing limitations. A successful namespace observation does not upgrade
the provenance of independently read executable bytes or proc metadata.

## What is sampled

Each observation duplicates the owned pidfd with `F_DUPFD_CLOEXEC` under a short
lifecycle lock. It requests network, mount, user, and active PID namespaces via
`PIDFD_GET_NET_NAMESPACE`, `PIDFD_GET_MNT_NAMESPACE`,
`PIDFD_GET_USER_NAMESPACE`, and `PIDFD_GET_PID_NAMESPACE`, all with ioctl argument
zero. The active PID namespace is deliberately not the PID-for-children
namespace. Each returned descriptor must have `FD_CLOEXEC`, nsfs filesystem
type, a regular nonzero inode, and the exact expected `NS_GET_NSTYPE` value.

Two complete samples must match. All namespace descriptors and the observation's
pidfd duplicate must close before success. Unsupported ioctls/namespaces,
`EPERM`/`EACCES`, process exit, a changed sample, validation failure, or canceled
in-flight reads return no partial observations and invalidate future observations
for this generation. Missing pidfd capture is unavailable, never alternative
proof. The launcher does not retry a failed Start without pidfd support.

`Wait` invalidates observations promptly. It never waits behind an in-flight
ioctl. Kernel operations are not guaranteed interruptible, so any outstanding
observation still owns its duplicate until it returns. Such overlap is reported
as sticky `CleanupError` rather than claiming all descriptors are already gone.
Close errors are likewise sticky, are never retried against potentially reused
FD numbers, and propagate through observations and `Wait`/containment cleanup.

## What is not proven

A pidfd pins process identity, not namespace stability, executable identity,
execution history, or exclusive administrative control. Reads are not atomic;
two matching samples cannot exclude ABA changes, an exec away and back, changes
between namespace reads, or changes after return. A UID, PID 1, or a matching
namespace inode is not evidence of the initial host namespace. No namespace is
entered, no policy is applied, and no missing host authority is synthesized.

## Evidence and validation

The direct ioctl contract follows Linux v6.16
[pidfd UAPI](https://github.com/torvalds/linux/blob/v6.16/include/uapi/linux/pidfd.h)
and [pidfs implementation](https://github.com/torvalds/linux/blob/v6.16/fs/pidfs.c).
The namespace ioctl path obtains the task from the pidfd, requires argument zero,
and performs a ptrace filesystem-credential access check. Constants come from
the project's pinned `golang.org/x/sys/unix` v0.48.0, including architecture-specific
ioctl encodings. Go ownership was checked against the pinned toolchain's
`os/pidfd_linux.go` and `syscall/exec_linux.go`.

`TestUniVPNProcessPidfd*` uses only private injected syscall results and synthetic
FD integers. It covers exact ioctl selection, complete double sampling, invalid
types/filesystems/CLOEXEC, permissions/unsupported/exit, sticky failures,
cancellation, duplicate/original/namespace cleanup, creation-slot integrity,
failure/partial-start ownership, broker lifetime checks and concurrent Wait.
These tests do not launch a real child or touch live pidfds, procfs, namespaces,
sockets, host buses or networking. They are selected by the existing dedicated
NM workflow's `TestUniVPNProcess` prefix. Live Linux acceptance remains unrun
and requires a separately authorized isolated environment.
