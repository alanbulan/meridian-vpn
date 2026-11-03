# Broker packet boundary

This package is an executable, injected-I/O relay, **not** an activated VPN or a
standalone privilege broker. Its relay does not open a TUN device or configure
networking. A separate, application-disabled Linux `AcquireTUN` resource
constructor now implements new-device acquisition as described below. Invoking
that constructor would create an interface, but no test or application path does
so. Only synthetic packet/mocked-I/O tests have exercised that new code.

## Integration contract

1. A separately authorized host component opens/configures a single-queue Linux
   TUN with `IFF_TUN|IFF_NO_PI`, without virtual headers or offloads. The broker
   retains that descriptor; it must **never** pass the host TUN to the native
   child. `NewFilePackets` checks the existing descriptor using the read-only
   `TUNGETIFF` ioctl and requires pollable I/O. It refuses regular files, pipes,
   sockets, unsupported platforms, multiqueue and virtual-header configurations.
   Constructor failures leave ownership with the caller. Successful construction
   transfers ownership to the wrapper. The caller must not change its flags,
   duplicate or share it after validation.
2. Construct `NewPolicy` from separately authorized assigned IPv4, remote CIDRs,
   resolver addresses, explicit protocol switches and maximum packet size/MTU.
   A native child's offered address/prefixes are untrusted metadata, not authority.
   Inputs are copied. Empty/invalid policy and unspecified MTU fail closed.
3. Pass the broker-owned host endpoint and the child's **packet channel** to
   `Run`. Child packet channel adapters must preserve message boundaries and
   report truncation. `NewDatagramPackets` accepts only broker-side connected nonblocking unnamed AF_UNIX
   `SOCK_SEQPACKET` descriptors with protocol zero, verified with fstat, socket
   type/protocol, CLOEXEC and local/peer address queries. Datagram, named and abstract
   sockets are rejected. It uses recvmsg, detects MSG_TRUNC/MSG_CTRUNC,
   accepts no ancillary descriptors, and uses atomic message writes. It never
   creates/connects/binds/listens on a socket. Other transports require adapters; bare streams and pipe reads are not valid packet channels. Each
   `WritePacket` must consume exactly one packet. The separate `OpenPacketPair`
   constructor below creates a private local channel; neither API launches a child.
4. `Run` owns two distinct endpoints. `Close` must promptly unblock both reads
   and writes, including when the peer is stalled. `Run` closes each endpoint
   exactly once, waits for both pumps, and joins cleanup errors into its result.
   On `errors.Is(err, ErrCleanup)`, the caller must treat resource ownership as uncertain
   and quarantine the session, not start a replacement on these descriptors.

## Filtering semantics

Outbound is host to child: source equals the authorized assigned VPN address,
destination belongs to an authorized remote prefix. Inbound reverses this:
destination equals the assigned VPN address and source belongs to a remote
prefix. No forwarding to other local destinations is permitted.

IPv4 only, exactly a 20-byte IPv4 header, exact total length and valid header
checksum, nonzero TTL. All IPv4 options, fragments (including first fragments),
reserved flags and trailing bytes are rejected; DF is accepted. Unspecified,
loopback, link-local, multicast, class-E/limited broadcast and authorized subnet
network/broadcast endpoints are rejected. /31 and /32 remain usable for unicast
point-to-point/host routes. A packet cannot exceed the explicit MTU.

Protocol permissions are default-off:

- TCP: nonzero ports, complete and structurally valid header/options, reserved
  bits clear and valid pseudo-header checksum. No connection tracking: inbound
  unsolicited TCP is permitted within the configured source prefixes.
- UDP: nonzero ports and exact UDP length. Nonzero checksums must validate;
  zero UDP checksum is allowed by IPv4. No connection tracking.
- ICMP: echo request/reply only, code zero, minimum echo header and valid
  checksum. Redirects, destination unreachable and time-exceeded are rejected.
  Consequently PMTU discovery relying on ICMP errors is not implemented.
- Source/destination port 53 requires the exact remote resolver address;
  outbound destination must be 53 and inbound source must be 53. Resolver
  addresses must also be in an authorized remote prefix. This does not inspect
  DNS content or prohibit DNS over HTTPS/TLS inside allowed traffic.

This is a stateless endpoint/protocol filter, not a general firewall, resolver
implementation or authenticated tunnel. It does not prove a remote packet's
identity beyond the native transport's authentication. The host's configuration
must not enable TCP/UDP checksum offload: checksums must already be materialized.
Unsupported traffic terminates the relay rather than silently widening policy.
The two bounded buffers are each MTU+1 bytes; oversize/truncated reads cannot be
accepted. The relay records only packet counts and no contents. Any invalid
packet, I/O failure, partial write, or cancellation closes both endpoints.

## Validation

From repository root with its pinned toolchain environment loaded:

    go test -race ./internal/packetrelay
    go vet ./internal/packetrelay

Tests use in-memory packet endpoints, injected recvmsg/sendmsg/poller callbacks,
temporary regular files, and local AF_UNIX socketpairs. Address-rejection tests
bind a pair endpoint to an abstract or temporary pathname to verify rejection;
there is no listener or IP connection. Tests do not create devices, namespaces,
routes or DNS configuration. Actual TUN descriptor compatibility and native-worker integration
remain unverified.

## Separate retained TUN acquisition precursor

`AcquireTUN` is a concrete Linux device-acquisition implementation, not a live
acceptance result. It is not called by the application or native NM bridge. Its
production path would create an interface and therefore requires independent
deployment authorization before use. All new tests replace device/syscall
operations; they never open `/dev/net/tun` or run a real creation ioctl.

The constructor walks only `/dev/net/tun`, without symlinks or caller-supplied
paths. Root-owned ancestors must not be group/world writable. The node must be
a root-owned single-link character device with Linux TUN major/minor 10:200.
World-writable device-node permissions are allowed, as on ordinary Linux installs;
creation remains subject to kernel capability checks. Descriptors are opened
CLOEXEC/nonblocking. Only a trusted explicit ASCII interface name is accepted,
without percent templates, truncation, name lookup or automatic fallback.

The exact `TUNSETIFF` request is `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL`. A collision
is an error and never triggers adoption or retry. EXCL is an acquisition check,
not a persistent lock. The returned name must match, and later `TUNGETIFF` must
report exactly TUN/no-PI without persistence, multiqueue or virtual headers.
Poller deadline support and descriptor CLOEXEC/nonblocking state are checked.
Only the original handle is retained; no raw file, FD, PacketIO, duplication or
replacement endpoint is exposed. Acquisition alone does not start a relay.

Ownership is recorded before the mutating ioctl. Even an ioctl error can follow
a successful kernel mutation, so the constructor does not replay it. Every
acquired TUN handle is closed at most once on error/cancellation. A non-nil
resource is returned alongside an acquisition error to retain its cleanup
result. Close errors remain sticky as `ErrCleanup`; numeric close is not retried.
Observed name/mode drift permanently closes the resource. Historical observation
metadata survives local close, without turning metadata into fresh authority.

This is only local TUN acquisition. It does not establish the intended host
namespace, correlate an NM receipt or native generation, acquire an exclusive
host lease, attest offload/kernel policy, publish NM
configuration, expose Ready, or prove link/routes/DNS absence. Privileged actors
can change network state; equal sequential observations cannot prevent that.
Context checks cannot interrupt a kernel syscall. Complete namespace binding,
applied/global/dispatcher policy, native/NM relay integration, independent cleanup
readback and authorized real-kernel/real-NM acceptance remain deployment gates.

Primary sources: [Linux TUN documentation](https://docs.kernel.org/networking/tuntap.html),
[Linux TUN implementation](https://github.com/torvalds/linux/blob/master/drivers/net/tun.c),
[Linux TUN UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h),
and [x/sys ifreq](https://github.com/golang/sys/blob/v0.48.0/unix/ifreq_linux.go).

## Retained local TUN/relay binding precursor

`BindTUNRelay` now binds a successfully acquired `TUNResource` to the concrete
`DatagramPackets` child endpoint. Binding claims both original objects once,
without I/O or forwarding. Ownership transfers **only on successful binding**;
a rejected duplicate leaves the supplied objects with their existing owner and
cannot close an active alias. Claims never reset after stop or failure. There is
no generic endpoint injection in this public API, raw TUN exposure, duplication,
reopen-by-name, replacement or restart. Only package-private tests inject I/O.

`Start` consumes one attempt before checking context, separately authorized
packet policy, and a fresh original-descriptor observation. Failure closes both
owned handles and preserves their cleanup evidence. Success launches the existing
two-pump policy-filtered `Run`; it is not a readiness signal. The private TUN
adapter reads/writes only the original file and closes through its original
close-once owner. It never holds the TUN lifecycle mutex across blocking I/O.

`Stop` before start permanently prevents forwarding. During a run it cancels and
joins that original run without holding the lifecycle lock. `Wait` observes the
same completion without canceling it. A wait timeout is not a successful join;
the owner remains available to join later, and actual close errors remain sticky
as `ErrCleanup`. The operational error (including ordinary cancellation) is
available separately from `Stop`'s local-cleanup result. Closing or detecting drift
on the original TUN wakes the run, which closes the child and joins both pumps;
TUN `Close` itself does not prove that join, so the relay owner must Stop/Wait.

The opaque `TUNRelayBinding` checks only the exact retained process-local owner.
It survives failed start, stop, observation drift and cleanup uncertainty without
performing live I/O. It cannot authenticate an NM receipt or native generation,
survive process restart, authorize resource lookup or cleanup by name, or prove
host network absence. It is intentionally not `UniVPNNMHostBinding`.

All new execution tests use in-memory devices/endpoints, including bidirectional
filter failures, partial startup, duplicate ownership, concurrent start/stop,
blocked I/O, sticky close errors and late completion after a timeout. No real TUN,
socket, network namespace, NM activation or native worker is used by these tests.
Application/NM wiring, host namespace and applied policy, independent absence
readback and authorized real-kernel/real-gateway acceptance remain open.

## Concrete anonymous packet-pair acquisition

`OpenPacketPair` creates exactly one local anonymous `AF_UNIX` `SOCK_SEQPACKET`
pair with `SOCK_NONBLOCK | SOCK_CLOEXEC` in the original syscall. It accepts no
existing descriptor, pathname or IP destination and uses no bind/connect, flag-
setting fallback or retry. Both ends are inspected through retained `RawConn`
handles, including type, protocol, anonymous local/peer addresses, flags and
poller support. The native file and concrete `DatagramPackets` peer come from
that same successful syscall. Matching address strings alone would not prove
pairing for caller-supplied files.

Every successful raw descriptor becomes an owned `os.File` before validation or
cancellation checks. Post-acquisition failure closes both original endpoints
once and returns no partial endpoints. Successful wrapper ownership is respected
on cleanup. Close errors are returned as `ErrCleanup`; a numerical close is not
retried. A syscall failure's zero-valued Go result is not an acquired descriptor
and is never closed. Context covers acquisition only: after successful transfer,
the caller owns both endpoints even if that context later expires.

`core.NewUniVPNPacketPairProvider` is a resource-free, one-shot provider factory.
Its first call consumes the attempt before validating the 32-character lowercase
hex launch label and context. It calls the concrete acquisition above, preserves
the peer's concrete dynamic type, and maps uncertain cleanup to `core.CleanupError`.
Repeated, concurrent, zero-value and copied-provider calls cannot acquire another
pair; prior cleanup failures remain visible. The session label is not an
identity receipt, reconnect key or permission to adopt another endpoint.

The normal application still does not select this provider. Arbitrary trusted
`UniVPNPacketProvider` implementations do not gain its pairing guarantee. Later
production composition must explicitly choose the concrete provider and bind its
returned endpoint to the authenticated original native generation and TUN/NM
transaction. This local IPC pair establishes no host lease, readiness, applied
network policy, or independent host cleanup proof.

Tests exercise real unprivileged anonymous socketpairs, both message directions,
packet boundaries, truncation, peer EOF and close-unblocks-read/write behavior.
Private per-call seams test syscall/validation/wrapping/cancellation failures and
uncertain closes. Launcher integration uses the actual pair and native duplicate,
checks descriptor flags after command wiring, and exchanges local packets. No
command or VPN worker is started. These are local IPC tests, not TUN or gateway
acceptance. The address validator reuses the raw sockaddr-length fix from PR #3
(commit `8f651ec`): Go's converted `SockaddrUnix` name cannot distinguish an unnamed
endpoint from an empty abstract name. The exact kernel-reported family-only
length is required for both local and peer endpoints; empty abstract, other
abstract, pathname and unconnected sockets remain rejected. Linux 386 and s390x
use the reviewed socketcall ABI branch. CI cross-compiles 386, arm64 and s390x.

Sources: [socketpair semantics](https://man7.org/linux/man-pages/man2/socketpair.2.html),
[atomic socket flags](https://man7.org/linux/man-pages/man2/socket.2.html),
[Go Socketpair wrapper](https://go.dev/src/syscall/syscall_unix.go), and
[Go preexisting-nonblocking NewFile behavior](https://go.dev/src/os/file_unix.go).


## Non-owning retained packet identity

`TUNRelay.ObservePacketBinding` accepts only the exact concrete child endpoint
already claimed by that relay and reads the original retained TUN. It neither
starts forwarding nor consumes Start, changes ownership, consumes packets or
closes resources on rejection. It does not call the close-on-error `TUNResource.Observe`
path. The relay's existing owner still must Stop/Wait after a failed observation.
`CheckPacketBinding` checks historical exact child/relay identity and survives
stopped pumps, drift and uncertain closes. No same-name TUN, same-session string,
foreign pair or copied owner can replace the retained objects.

Core uses these methods only for an additional historical local-generation
association behind its still-mandatory independent HostBinding gate. A matching
name is not actual NM device ownership, host-namespace proof, a lease, readiness,
applied-policy verification or host absence. Observations remain sequential and
can become stale immediately; no new automatic application path is enabled.
