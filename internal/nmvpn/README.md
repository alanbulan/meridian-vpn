# Experimental NetworkManager-owned configuration core

Linux-only, independent, and not integrated into the application. There is no
running VPN service, automatic system-bus connection, TUN operation, or production
broker in this package. `DBusPeer` supplies an experimental NM wire adapter with
a required, independently trusted broker; it is not application-ready. It does **not** implement `UniVPNHostLeaseProvider`, prove exclusive
host ownership, or turn a successful publish into `core.Ready`.

## Implemented scope

- Encode an authenticated, session-bound IPv4 offer into the actual NM VPN
  `Config` and `Ip4Config` dictionaries. Interface assignment and exact address,
  endpoint, and route allowlists belong to a trusted broker/administrator.
- Set `never-default`, disable IPv6/persistence in the payload, reject `/0`, DNS,
  search domains, unsupported addresses, duplicate/noncanonical routes, routes
  containing the endpoint, and an address prefix containing the endpoint. This
  is conservative endpoint protection; NM may normally add its own host route.
  Exact allowlisting is not a replacement for reviewing the complete route set.
- Persist intent before either publication; write the published phase only after
  both signals. A failed or canceled publication uses a fresh bounded cleanup
  context. Never replay configuration on restart.
- Bind cleanup to boot ID, **bus daemon ID** (`org.freedesktop.DBus.GetId`), NM's
  authenticated unique owner, profile UUID, active path, broker session generation
  and interface. Changed/unknown identity retains a quarantined record.
- Keep a private durable file journal with lifetime `flock`, atomic rename,
  directory `fsync`, canonical JSON keys, bounded input, no symlink traversal,
  one-link private regular files, and trusted/stable ancestor directory checks.
  Records contain identity and phase, not credentials or addresses.

The schema is experimental and has not been deployed. Old incomplete records
without `BusID` fail validation; they are never silently upgraded or deleted.

## Required trust boundary

`Peer` remains a security contract. `DBusPeer` implements protocol operations,
**not** the platform-authority guarantees delegated to `Broker`.
Before this package can perform any live operation, a real adapter must:

1. Use an authenticated, pinned system bus and NM owner. Verify bus ID (not the
   machine ID or server-address GUID), credentials, boot ID and unique owner.
   Invalidate on disconnect or owner change. Do not reconnect and reuse a pin.
2. Bind the broker session to the specific NM activation and the actual created
   link/worker handles, not just a device name, UUID or reusable process ID.
   Persist sufficient recovery authority outside untrusted desktop/gateway input.
3. Validate the **applied connection profile**, including static route, DNS and
   IPv6 settings. NM merges profile settings with plugin payloads; omitting DNS
   here does not establish that NM will leave DNS unchanged.
4. Revalidate on every operation. Deliver Config then Ip4Config only to the
   pinned unique NM owner, using the real plugin path/interface. A successful
   D-Bus send is not an acknowledgement of applied networking.
5. Deactivate only the exact recorded generation. Join its worker/relay and prove
   absence of its connection, link, routes and DNS effects. Merely seeing an NM
   object disappear is not enough. Unknown state means quarantine, not deletion.
6. Respect context cancellation/deadlines without leaving background mutations.
   This core cannot forcibly cancel an arbitrary broken Peer implementation.
7. Supply independent activation/network readback before exposing Ready. NM's
   public D-Bus API offers no atomic host-network ownership lease; do not invent
   one from sequential reads or an NM state enum.

One `Journal` instance belongs to exactly **one Controller**. Its method locks do
not authorize two Controllers to interleave lifecycle transactions. Hold the
FileJournal open throughout that ownership and close it only after management
has stopped. Another process may reopen it for reconciliation after release.
The file model trusts root and the effective user, but not other UIDs. Production
must use a broker-owned path; same-UID hostile mutation is not covered by `flock`
or permissions. Root/effective-user-owned sticky ancestors support private test
directories under `/tmp`; group-writable non-sticky ancestors fail closed.

## Verification and remaining gates

Default tests use in-memory Peers, private files and synthetic Unix sockets.
Opt-in `nmvpnintegration` tests additionally launch a fresh private D-Bus daemon
with a synthetic NM service. They never contact NetworkManager, a host bus or a
VPN gateway, alter host networking, or claim actual NM interoperability. Cases cover payload signatures/byte order, malformed offers,
persist-before-publish ordering, canceled/partial publication, failed durable
writes/readbacks, restart without replay, every identity component changing,
concurrent calls, private-file protections and JSON key aliases.

Run on Linux with the repository Go toolchain:

```
go test -count=1 ./internal/nmvpn
go test -race -count=1 ./internal/nmvpn
go vet ./internal/nmvpn
```

Still missing: the authenticated broker and incoming NM plugin service methods,
plugin registration/packaging, actual applied-profile/host-policy inspection,
native offer/worker binding, activation and real host cleanup readback, complete
startup/reboot recovery, `core.Session` integration, DNS/IPv6 support, disposable
real-NM acceptance, real gateway testing, permissions and deployment review. Passing
these unit tests does not close those gates.

## Experimental wire adapter

`OpenPinnedBus` takes ownership of an explicitly supplied fresh connected Unix
stream, verifies its socket peer UID, and performs EXTERNAL authentication and
Hello. It does not accept an already-authenticated stream, discover bus addresses
from environment variables, fall back to a session bus, or reconnect. `BusPin`
must come from trusted provisioning; checking a caller-provided pin alone does
not establish trusted endpoint provenance. Production requires the real system
bus and UID 0 for both its process and NM, not fixture UIDs.

The wrapper monitors NM and plugin name ownership synchronously in the incoming
message interceptor, before dispatching later replies. Loss/replacement or
release-and-reacquisition permanently invalidates it. Directed publication uses
`Emit` with a fixed destination injected before encoding. This avoids godbus
v5.2.2's raw signal `SendWithContext`, which does not reliably surface cancellation
and transport errors. No forged sender is supplied. The actual plugin unique
name must be the same connection NM contacted for that activation.

Operations use a ten-second context after acquiring the serialization lock.
Cancellation closes the owned raw Unix socket first, then the D-Bus connection,
and joins its callback. Closing `dbus.Conn` alone can wait behind its blocked
writer. There are no detached timeout writers or retries of an uncertain signal
or DeactivateConnection. A delivered signal cannot be retracted by cancellation;
local send success is neither NM acknowledgement nor networking readback. The
bound assumes Broker methods honor context; mutex contention is not included.

`ValidateProfile` accepts a narrow typed grammar, including empty modern/legacy
network arrays. Nonempty VPN data/secrets and unrecognized properties are still
unsupported. GetSettings inspects the current settings object, not the immutable
profile NM used for Connect. Broker evidence must bind the original authenticated
Connect, offer, real resource handles and host/global/dispatcher policy. The
minimal grammar alone cannot prove NM's applied routes or DNS.

Cleanup checks NM ActiveConnections independently of broker worker/link/route/DNS
absence, and never treats timeout or an arbitrary D-Bus error as absence. On NM
identity/withdrawal failure, `LocalStopper` gets a separate fresh ten-second
cleanup context and can stop only independently verified local worker handles.
An attempted local stop also permanently forbids further publication, even when
its result is uncertain. The journal stays quarantined regardless: stopping local workers does
not prove network cleanup. A broker that cannot prove the local generation must
refuse; autonomous teardown is not guaranteed in that case.

The fixed service-name claim does not install a service or implement incoming
Connect/NeedSecrets. The encapsulated connection currently has no external broker
export API, so real service integration still needs a narrow authenticated
handler implementation on this same connection. Do not expose the raw Conn as a
shortcut. Private-bus fixtures model outbound protocol and identity checks only.

Run the opt-in fixture only in a disposable environment with official
`dbus-daemon`, a compiler for race instrumentation, and the repository Go version:

```
MERIDIAN_NMVPN_WIRE_TESTS=1 bash integration/nmvpn/run-wire-tests.sh
```

## Primary references

- [NM VPN plugin D-Bus methods and signals](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.VPN.Plugin.html)
- [NM VPN constants](https://networkmanager.dev/docs/libnm/latest/libnm-nm-vpn-dbus-interface.html)
- [NM VPN configuration implementation](https://github.com/NetworkManager/NetworkManager/blob/main/src/core/vpn/nm-vpn-connection.c), especially native uint32 IPv4 memory representation and applied-profile merging.
- [NM active connection properties](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Connection.Active.html)
- [D-Bus specification](https://dbus.freedesktop.org/doc/dbus-specification.html), especially GetId, unique names and directed signals.
- [Go JSON field folding](https://go.dev/src/encoding/json/fold.go), motivating exact canonical journal keys before decoding into structs.

- [Pinned godbus connection implementation](https://github.com/godbus/dbus/blob/v5.2.2/conn.go) and [Emit implementation](https://github.com/godbus/dbus/blob/v5.2.2/export.go), including interceptor ordering and output/Close locks.
- [NM Settings.GetSettings contract](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Settings.Connection.html)
