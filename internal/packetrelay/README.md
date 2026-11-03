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
   report truncation. `NewDatagramPackets` accepts only inherited connected nonblocking unnamed AF_UNIX
   `SOCK_SEQPACKET` descriptors with protocol zero, verified with fstat, socket
   type/protocol and local/peer address queries. Datagram, named and abstract
   sockets are rejected. It uses recvmsg, detects MSG_TRUNC/MSG_CTRUNC,
   accepts no ancillary descriptors, and uses atomic message writes. It never
   creates/connects/binds/listens on a socket. Other transports require adapters; bare streams and pipe reads are not valid packet channels. Each
   `WritePacket` must consume exactly one packet. This package does not create
   that channel or launch a child.
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
and temporary regular files only. They do
not create sockets, devices, namespaces, routes, or DNS configuration. Actual
TUN descriptor compatibility and native-channel integration remain unverified.

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
replacement endpoint is exposed. This slice does not start a relay.

Ownership is recorded before the mutating ioctl. Even an ioctl error can follow
a successful kernel mutation, so the constructor does not replay it. Every
acquired TUN handle is closed at most once on error/cancellation. A non-nil
resource is returned alongside an acquisition error to retain its cleanup
result. Close errors remain sticky as `ErrCleanup`; numeric close is not retried.
Observed name/mode drift permanently closes the resource. Historical observation
metadata survives local close, without turning metadata into fresh authority.

This is only local TUN acquisition. It does not establish the intended host
namespace, correlate an NM receipt or native generation, acquire an exclusive
host lease, attest offload/kernel policy, start or join a relay, publish NM
configuration, expose Ready, or prove link/routes/DNS absence. Privileged actors
can change network state; equal sequential observations cannot prevent that.
Context checks cannot interrupt a kernel syscall. Complete namespace binding,
applied/global/dispatcher policy, retained relay integration, independent cleanup
readback and authorized real-kernel/real-NM acceptance remain deployment gates.

Primary sources: [Linux TUN documentation](https://docs.kernel.org/networking/tuntap.html),
[Linux TUN implementation](https://github.com/torvalds/linux/blob/master/drivers/net/tun.c),
[Linux TUN UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_tun.h),
and [x/sys ifreq](https://github.com/golang/sys/blob/v0.48.0/unix/ifreq_linux.go).
