# Experimental NetworkManager-owned configuration core

Linux-only, independent, and not integrated into the application. There is no
running VPN service, system-bus connection, TUN operation, or production `Peer` in
this package. It does **not** implement `UniVPNHostLeaseProvider`, prove exclusive
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

`Peer` is deliberately an interface, **not** an implemented security guarantee.
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

Tests use in-memory Peers and private temporary files only. They do not connect to
any D-Bus daemon, alter host networking, contact a VPN gateway, or claim actual NM
interoperability. Cases cover payload signatures/byte order, malformed offers,
persist-before-publish ordering, canceled/partial publication, failed durable
writes/readbacks, restart without replay, every identity component changing,
concurrent calls, private-file protections and JSON key aliases.

Run on Linux with the repository Go toolchain:

```
go test -count=1 ./internal/nmvpn
go test -race -count=1 ./internal/nmvpn
go vet ./internal/nmvpn
```

Still missing: the authenticated broker/NM service, plugin registration and
packaging, profile-policy inspection, native offer/worker binding, activation and
cleanup readback, full startup/reboot recovery strategy, integration into
`core.Session`, DNS/IPv6 support, private-bus wire fixtures, disposable real-NM
acceptance, real gateway testing, permissions and deployment review. Passing
these unit tests does not close those gates.

## Primary references

- [NM VPN plugin D-Bus methods and signals](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.VPN.Plugin.html)
- [NM VPN constants](https://networkmanager.dev/docs/libnm/latest/libnm-nm-vpn-dbus-interface.html)
- [NM VPN configuration implementation](https://github.com/NetworkManager/NetworkManager/blob/main/src/core/vpn/nm-vpn-connection.c), especially native uint32 IPv4 memory representation and applied-profile merging.
- [NM active connection properties](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Connection.Active.html)
- [D-Bus specification](https://dbus.freedesktop.org/doc/dbus-specification.html), especially GetId, unique names and directed signals.
- [Go JSON field folding](https://go.dev/src/encoding/json/fold.go), motivating exact canonical journal keys before decoding into structs.
