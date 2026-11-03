# Experimental UniVPN native transport

This is an isolated source restoration and reviewed Linux-only watchdog addition,
not a claim of production gateway compatibility. The native engine implements
password authentication, persistent control TLS plus data TLS, IPv4 packets,
heartbeats, strict framing and peer identity continuity. It does not implement
MFA, client-certificate authentication, QUIC, IPv6, proprietary endpoint policy,
server discovery or gateway updates.

## Provenance and licenses

- Bruce-lhq/univpn-connect commit `954274ba3b0a061b844279311afd9350f203ba7f`.
- OpenConnect commit `70d1e79d1e55849dfc71dcc199b1edb535b547e4`.
- Official base archive SHA256:
  `c193f6f0f197bf4cdcc15d74c8803f9073406ddcd2f4d4ce8455ee1f76dcb72f`.
- Four original patches are unchanged. Patch 0005 adds Meridian's Linux
  monotonic watchdog and three loopback tests. Patch 0006 makes UniVPN hooks
  direct-exec (no shell), keeps them in the native process group, and propagates
  pre-init/connect hook errors on Linux; other protocols retain upstream behavior.
  Patch 0007 adds the opt-in native-owned session lifecycle channel described below.
- `licenses/` preserves MIT management-code license, upstream third-party
  notices, and OpenConnect LGPL-2.1. The native code is LGPL, NOT MIT relicensed.
- `source/openconnect-upstream.tar.gz` plus the complete patch chain is the
  corresponding source for the experimental binary. `source/univpn.c` and
  `source/univpn-codec.h` are readable copies, not independent build inputs.

## Reproduce on Linux

Prerequisites: compiler, make, autoconf, automake, libtool, pkg-config, OpenSSL
and libxml2 development headers, zlib development headers, Python 3, git.
No installer is run by these scripts. Dependencies must already be available
or privately staged. The default vpnc script is `/bin/false`, intentionally
preventing accidental use of a host route/DNS configuration script.

From this directory:

```
python3 scripts/prepare_native.py --archive source/openconnect-upstream.tar.gz --destination "$PWD/build/openconnect"
(cd build/openconnect && sh ../../scripts/build_native.sh)
```

The prepare script verifies the official archive hash and exact patch list,
rejects archive links/device entries/path escapes, then checks and applies each
patch. The build runs the real native executable against a loopback TLS mock
using OpenConnect script-tun socket mode: **no kernel TUN, root, routes or DNS**.
The 17 mock tests take about two minutes. Only generated mock credentials and
short-lived self-signed test certificates are used.

`RESULTS.txt` is this restoration's actual test result. `BUILD-LOG.txt` is the
build log. SHA256SUMS inventories the packaged source/patches, not a signature.

## Watchdog behavior

The Linux monotonic clock bounds each channel independently: 45 seconds without
a complete valid frame, 15 seconds to complete a fragmented frame, and 15 seconds
for a queued write. Outbound traffic does not refresh peer liveness, and trickled
partial bytes do not refresh a frame deadline. Expiry closes the session rather
than replaying credentials. These policies are conservative experimental
choices, not verified protocol requirements. Gateways that do not reply to
heartbeats may be incompatible. Tests cover silent control, silent data and
partial-frame expiry. Dedicated blocked-write fault injection remains pending.

## Application and privileged broker boundary

`internal/core/univpn.go` provides a distinct adapter, strict argument builder,
and protocol router. The reviewed native executable and trusted continuous-
session broker must be configured explicitly. An executable alone never marks
this protocol available. No automatic PATH probing, installation, root request
or executable launch occurs during capability checks.

The existing NetworkManager adapter performs authentication then hands a cookie
to a new process. That cannot work here: this UniVPN token requires the original
control TLS connection to remain live while the second data TLS connection runs.
A production broker must own one continuous native process, pass secrets over
stdin/IPC (never argv), create and independently inspect the intended TUN,
validate assigned addresses/routes, apply authorized route/DNS changes
transactionally, and verify rollback after every stop/failure. IPC must authenticate
peer credentials and reject arbitrary executable/options/script injection.

Broker code and mock tests elsewhere in this restoration are preparatory work;
installation, privileged execution, real interface readiness, route/DNS rollback,
real gateway compatibility, packaging trust and independent security review are
not validated by these loopback tests. Do not replace readiness with stdout or
process-start signals. Do not bypass certificate validation to make tests pass.

## Direct hook hardening

`tests/univpn-hook.c` exercises the real native script function without a TUN:
successful execution, failed hook status, no shell interpretation, inherited
process group, and failed pre-init rejection before device creation. Broker
descendant containment is still required: a malicious or buggy hook can fork or
change groups itself. The trusted hook and its deployment are separate from
these native function tests.

## Native lifecycle channel (patch 0007, Linux only)

Explicit opt-in uses `--meridian-session-fd=N` and
`--meridian-session-id=<32 lowercase hexadecimal characters>`. The broker
creates an inherited write-only pipe and a fresh non-secret session nonce.
The FD must be at least 3, a writable FIFO, and specified once in canonical
unsigned decimal form on the command line, not in a configuration file.
Native code sets close-on-exec and nonblocking mode before authentication.
The session ID must also be specified exactly once. Other protocols and
script-tun mode are rejected. A closed channel cannot be reused.

In this mode the native process bypasses all hooks. It authenticates both TLS
channels, creates a fresh Linux TUN using `IFF_TUN_EXCL`, obtains its kernel
index, and sets its alias to `meridian-<session>` via acknowledged netlink.
Only after actual TUN registration does native code write one configuration
record. The persistent original control TLS connection remains alive.
Neither hooks nor stdout are authoritative. No config is emitted for
script-tun, authentication-only success, failed device acquisition, failed
alias setup, or unavailable control/data channels.

The version-1 newline-delimited JSON config record contains exactly `version`,
`event` (`config`), `session`, `interface`, `index`, `alias`, `addresses`
(IPv4 CIDR), `routes` (at most 128), `dns`, and `endpoint` (the numeric connected
control peer, without a port). DNS remains empty when the gateway supplies no
supported DNS information. No password, cookie, token, or TLS secret is emitted.
Records are bounded below 32768 bytes. A single nonblocking write that is
partial, blocked, or fails terminates setup; receivers must reject truncated
records. A full pipe is not allowed to stall the TLS liveness loop.

Graceful native shutdown emits `event: no-network` only if no successful
TUN acquisition ever occurred. It otherwise emits `event: closed`. Both carry
only version and session identity besides event. `closed` is diagnostic, not
rollback evidence. `no-network` is not sufficient on its own: the broker must
also verify process containment, EOF, and independent kernel absence. Abrupt
EOF, partial setup, or an unknown outcome require conservative quarantine.
The native acquisition flag is set immediately after successful TUNSETIFF,
before index lookup or alias mutation; a later failure cannot attest no-network.

`tests/univpn-session.c` exercises the actual native FD parser, serializer,
exclusive-device and alias ordering, failure propagation, bounded records,
closed/full pipes, and terminal reuse rejection using syscall-wrapped TUN and
netlink. Those tests do not create a kernel TUN or mutate host networking.
Real privileged setup and rollback remain unvalidated and disabled by default.

`tests/univpn-session --emit-fixture` writes actual config and no-network
serializer bytes from the syscall-wrapped test. Packaged `tests/testdata/`
records are generated by that test, not manually authored; their loopback
endpoint is for parser interoperability tests, not production route policy.
`tests/univpn-session-integration.py` additionally tests the actual executable's
CLI, inherited pipe, and successful/rejected TLS authentication against the
loopback gateway in authenticate-only mode, ensuring neither emits config.
Channel mode requires both TLS connections to use the same numeric IP, port,
and IPv6 scope before declaring the native session live; the broker therefore
needs only one validated endpoint escape route.

## Preconnected TLS sockets (patch 0008, Linux/OpenSSL/IPv4)

The native CLI accepts a paired `--meridian-control-fd=N` and
`--meridian-data-fd=N`. Only canonical decimal descriptors >=3 and below
FD_SETSIZE are accepted, once each, on the CLI (not configuration files).
The launcher must own descriptor allocation and reject conflicts with its
session/TUN descriptors; these are not user-controlled broker arguments.

The pair must be distinct underlying connected IPv4 TCP sockets, with the same
remote address and port and the URL's port. Files, UDP/listening/unconnected
sockets, duplicate integers or dup aliases, partial pairs, proxies and other
protocols are rejected. At TLS adoption the native code independently rereads
each socket's peer tuple, compares it to the validated expectation, and stores
the actual peer. The original gateway hostname/SNI and CA checks remain intact;
the data channel also must match the authenticated control certificate.

FD mode never resolves or opens a replacement connection, including after
consumption or failed TLS. Descriptors are transferred once, marked CLOEXEC,
and closed on failure/teardown. Unused data sockets close after authentication
failure. Narrow OpenSSL allocation-error fixes close the acquired descriptor
and handle null SSL/BIO objects; four fault-injected error tests verify one
close per acquired descriptor without network access.

The real loopback tests exercise successful IPv4 traffic with a deliberately
unresolvable, certificate-covered hostname, exact SNI on both TLS channels,
wrong hostname/untrusted CA/data-certificate rejection, descriptor rejection
cases, reverse argument order and unused-data closure. An LD_PRELOAD test
interposer rejects connect/getaddrinfo calls in FD-mode fixtures. This is a
regression guard, **not a production security sandbox**.

`tests/univpn-fd-session.c` and its Python driver combine both real TLS channels
with the canonical private lifecycle pipe. They prove the authenticated-live
gate, exact peer checks, one no-network terminal record, and terminal reopening
rejection without any TUN acquisition. A link-time open guard asserts zero TUN
open attempts. Existing mock-kernel session tests remain separate.

Both TCP sockets are connected before authentication, but data TLS begins only
after control authentication. A delayed-auth fixture checks that ordering;
enterprise gateways may reject the early idle data TCP socket, which remains
unverified. This patch does not create a network namespace, preopened TUN,
seccomp/capability policy, or complete host dataplane isolation. Broker/launcher
wiring must explicitly provide this mode; GUI live connection remains disabled
until the full reviewed deployment chain exists.

## Packet relay and authenticated offer (patch 0009, experimental)

`--meridian-packet-fd=N` accepts an inherited connected, unnamed AF_UNIX
SOCK_SEQPACKET descriptor, protocol zero, once on the CLI. It requires both
preconnected TCP descriptors and the private session pipe/nonce before any
authentication. Scripts and raw host TUN handles are not accepted. Descriptor
collisions, terminal reuse and live-session reauthentication are rejected.

The native process attaches this packet socket instead of opening a TUN. It
does not run interface hooks, vhost, TUN ioctls, or netlink alias operations.
It uses nonblocking recvmsg/send with complete-message, truncation, ancillary
data, zero-length/EOF and short-write checks. The native code is a transport,
not the security packet filter: host TUN must remain in the broker and the
separate `internal/packetrelay` policy must filter both directions.

After both TLS channels authenticate, the private pipe emits version 2 `offer`
with session nonce, assigned addresses, routes, DNS and the actual endpoint. It
contains no interface, index, alias or readiness assertion. Termination emits
version 2 `relay-closed`, never the legacy `no-network`/`closed` cleanup proofs.
The existing version 1 Go session source intentionally rejects these records.
A reviewed offer → broker-owned host lease → filtered relay integration remains
necessary before enabling packet mode; neither offer nor relay closure proves
host network setup or cleanup.

The packet fixture exercises actual inherited unnamed seqpacket IPC and local
TLS. Its test interposer aborts on TUN/vhost opens, IP/netlink socket creation,
DNS/connect and namespace calls. This is test instrumentation, not production
isolation. No named Unix listener is created, and the previously denied Unix
listen integration is not retried.
