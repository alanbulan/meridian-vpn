# Experimental NetworkManager-owned configuration core

Linux-only and not enabled in the normal application. A conditional one-shot
[service composition](SERVICE.md) now wires the actual plugin, manager, native
bridge and publication controller, but there is no installed VPN service,
automatic system-bus connection, or production host-authority implementation. `DBusPeer` supplies an experimental NM wire adapter with
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

Still missing: concrete retained host-resource authority,
plugin registration/packaging, actual applied/global/dispatcher policy inspection,
real host relay/readback, activation and real host cleanup proof, complete
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

The fresh Hello identity accepts only one distinct validated unique name.
The pinned godbus version can list the same name twice when its asynchronous
NameAcquired bookkeeping runs before Names() is read. Identical repetitions are
accepted; any different unique or well-known name is rejected. A private-bus
round-trip regression deterministically exercises the duplicate shape without
sleeping, retrying bootstrap, or weakening the subsequent UID/bus/owner pins.

The wrapper monitors NM and plugin name ownership synchronously in the incoming
message interceptor, before dispatching later replies. Loss/replacement or
release-and-reacquisition permanently invalidates it. Directed publication uses
`Emit` with a fixed destination injected before encoding. This avoids godbus
v5.2.4's raw signal `SendWithContext`, which does not reliably surface cancellation
and transport errors. No forged sender is supplied. The actual plugin unique
name must be the same connection NM contacted for that activation.

Operations use a ten-second context after acquiring the serialization lock.
Cancellation closes the owned raw Unix socket first, then the D-Bus connection,
and joins its callback. Closing `dbus.Conn` alone can wait behind its blocked
writer. There are no detached timeout writers or retries of an uncertain signal
or DeactivateConnection. A delivered signal cannot be retracted by cancellation;
local send success is neither NM acknowledgement nor networking readback. The
bound assumes Broker methods honor context; mutex contention is not included.

The pinned dependency is godbus v5.2.4. A full private-bus run exposed v5.2.2's
uncaught header-padding read panic during concurrent connection closure. The
official fix returns an ordinary read error and is retained in v5.2.4; raw-socket
first cancellation remains necessary to unblock a saturated writer. A deterministic
truncated-padding regression protects this boundary in addition to the real
private-bus owner-loss fixtures. See [upstream fix #437](https://github.com/godbus/dbus/pull/437).

`ValidateProfile` accepts a narrow typed network grammar, including empty
modern/legacy network arrays. The incoming handler separately validates and
removes its small credential envelope. GetSettings inspects current settings,
not the immutable profile NM supplied to Connect. Current-settings checks accept
only that same bounded envelope, without secrets. Broker evidence still must
prove the activation receipt, actual handles and host/global/dispatcher policy.
The minimal grammar alone cannot prove NM's applied routes or DNS.

Cleanup checks NM ActiveConnections independently of broker worker/link/route/DNS
absence, and never treats timeout or an arbitrary D-Bus error as absence. On NM
identity/withdrawal failure, `LocalStopper` gets a separate fresh ten-second
cleanup context and can stop only independently verified local worker handles.
An attempted local stop also permanently forbids further publication, even when
its result is uncertain. The journal stays quarantined regardless: stopping local workers does
not prove network cleanup. A broker that cannot prove the local generation must
refuse; autonomous teardown is not guaranteed in that case.

The fixed service-name claim does not install a service. `ServePlugin` exports
only the incoming methods described below on the same encapsulated connection.
No raw Conn or arbitrary method-export API is exposed. Private-bus fixtures cover
inbound and outbound protocol against synthetic NM, not actual interoperability.

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

- [Pinned godbus connection implementation](https://github.com/godbus/dbus/blob/v5.2.4/conn.go) and [Emit implementation](https://github.com/godbus/dbus/blob/v5.2.4/export.go), including interceptor ordering and output/Close locks.
- [NM Settings.GetSettings contract](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Settings.Connection.html)


## Authenticated incoming activation and native binding

`ServePlugin` exports before claiming the fixed name. It accepts calls only from
the pinned NM unique owner, with exact path/interface/member/signature/destination
and reply semantics. Its closed method table contains Connect, NeedSecrets,
ConnectInteractive and Disconnect plus read-only State properties. Helper setters
and interactive secret replacement are not exported. Non-interactive fallback
returns the official `InteractiveNotSupported` error, not UnknownMethod.

`NewPluginPlan` generates a fresh 128-bit `meridian-activation` nonce. The trusted
manager must place it in its own single-flight activation profile before request.
The fixed name supports only `supports-multiple-connections=false`. The accepted
credential envelope permits that exact nonce, password-flags="2" (not-saved), an
exact planned vpn.user-name and only vpn.secrets.password. Password is 1–4095 UTF-8
bytes without CR/LF/NUL at Connect; missing password makes NeedSecrets return
"vpn". NeedSecrets may repeat and never launches or consumes the activation.
Native executable, gateway, CA, authgroup and launch options come only from
trusted provisioning, never this profile. There is no credentialstore fallback.

A single accepted Connect produces an opaque Activation. The sanitized network
snapshot has no credential envelope and shares no mutable collections. UsePassword
is one-shot, clears its owned bytes after callback return, and sanitizes errors.
Unused credentials expire after 30 seconds, erase their owned copy, and close the
plugin lifetime. D-Bus decoding creates immutable Go strings, so this does not
promise complete memory erasure. No secret enters journals, logs or reply text.

Disconnect is fenced in the synchronous reader before godbus's unordered handler
goroutines. Pending receipt/launch work is permanently revoked; bus/owner loss
also cancels and erases it. Disconnect before Connect directly stops the plugin.
An uncertain acceptance cannot leave a live empty receiver. Plugin state signals
are directed only to NM. STARTED is allowed only after both configuration signals;
it is not host readiness. State reports must run **outside** Broker callbacks:
DBusPeer holds its bus lock during those callbacks. Report STOPPED only after the
native owner has completed local teardown, never as host-network absence proof.

`StartUniVPNNMBroker` in internal/core is a conditional native bridge. Before
password use it requires a retained trusted HostAuthority result, validates the
receipt's local bus/owner/plugin/UUID/path pins and exact planned username versus
--user. The authority must independently correlate its own manager transaction
and captured nonce. Connect itself contains no active/settings path; UUID scans
or caller-created Binding values do not prove that correlation.

The bridge owns the concrete pinned native launcher, the original worker's sole
Wait, concrete process-bound offer source, packet endpoint and retained host
binding. It derives the session solely from the native offer, validates the frozen
IPv4/no-DNS policy, and transfers the packet endpoint exactly once to the required
host binding. It never calls the old direct-network UniVPNOfferController. It
returns retained recovery authority even on post-acquisition error. Uncertain
local cleanup is sticky; no arbitrary PID/name replacement or destructive retry.

Broker.Verify proves immutable generation provenance even after cancellation or
exit. PublicationVerifier separately requires live worker/host policy immediately
before each signal, and is mandatory for an installed incoming Plugin. Stop joins
only retained local handles; ProveAbsent additionally requires native containment
and independent host link/routes/DNS/relay absence. Neither normal application
wiring nor core.Ready is supplied. The HostAuthority/HostBinding TUN/relay, policy
and readback implementations remain mandatory missing deployment
gates. Mock bridge tests do not establish those proofs.

Additional primary sources: [NM service implementation](https://github.com/NetworkManager/NetworkManager/blob/a0f2961616e2ca50ebf8eeecde2900b00150ec4e/src/libnm-client-impl/nm-vpn-service-plugin.c),
[NM activation and secret flow](https://github.com/NetworkManager/NetworkManager/blob/a0f2961616e2ca50ebf8eeecde2900b00150ec4e/src/core/vpn/nm-vpn-connection.c),
and [godbus export dispatch](https://github.com/godbus/dbus/blob/v5.2.4/export.go).

## Concrete manager transaction and durable containment

`NewActivationManager` takes the already served Plugin and its exact PinnedBus,
an exclusively held ActivationJournal, and a trusted boot-identity reader. The
reader must honor its context and report the actual host boot, never desktop or
gateway input. One Plugin admits only one manager. The manager installs a fresh
128-bit nonce before any accepted Connect; a caller cannot choose the receipt's
nonce or object paths.

`Start` freezes the approved narrow network profile, forces autoconnect=false,
and adds only the planned username, nonce and not-saved password flag. It never
accepts a password. It durably records add-intent before Settings.AddConnection2
with flags `0x22` (IN_MEMORY | BLOCK_AUTOCONNECT), records the actual returned
settings path, then writes activate-intent before ActivateConnection. Both the
device and base connection argument are `/`; NM chooses the base connection.
Only the method-returned active path is recorded. No UUID lookup, object scan,
AddAndActivateConnection fallback, reconnect or uncertain mutation replay exists.

The opaque receipt's `Correlate` verifies the exact authenticated Activation,
nonce, immutable profile, current settings envelope, boot/bus/unique owners and
the direct returned active object's reference to the direct returned settings
object. Its Binding output has an empty native Session; the separate native
owner creates that generation. Both network snapshots pass the full strict grammar
before comparison. Only a closed list of typed defaults, empty collections and
NM bookkeeping fields may differ; unknown or policy-changing values still fail.
In particular absent DNS options are not equivalent to present-empty DNS options,
and interface binding, autoconnect, profile label and credential-envelope values
stay bound. See [profile equivalence](PROFILE-NORMALIZATION.md) for the exact list.
Activation's inbound Connect may arrive before
ActivateConnection replies, so the manager must not hold the bus serialization
lock while waiting for that method. A bounded, joined cancellation callback
closes the raw transport before the D-Bus connection.

`FileActivationJournal` uses the same strict private-directory/openat/flock,
atomic file/rename and directory-fsync model as FileJournal. Its independent flat
schema stores only identifiers and stages, including the nonce and both returned
paths. It rejects missing, duplicate, case-folded, unknown, null and malformed
fields. Use a distinct directory from the publication Controller: their common
lock and filename make accidental cross-schema reuse fail closed. There is no
public clearance method because this transaction cannot prove host cleanup.

Every preexisting journal record blocks a new transaction and is quarantined.
Corruption is retained unchanged. A missing reply, failed durable write, changed
boot/bus/NM owner or failed correlation fences the Plugin and invalidates the bus.
Recovery never reconstructs a receipt from disk or guesses a missing path. This
is durable restart containment, **not** automatic restart/reboot recovery or
network cleanup. Manual inspection and a future separately authenticated recovery
authority remain required. A newly started process cannot recover the former
Plugin unique owner, opaque Activation or host resource handles from identifiers.

The isolated wire workflow also uses the official libnm library to normalize a
credential-free SimpleConnection in memory and serializes its actual typed output.
Those generated values are used independently in synthetic Connect and GetSettings
calls. No NM.Client or system-bus connection is created. This proves the exercised
client-library serialization shapes, not a real NM daemon's applied profile,
manager-only legacy serialization, host policy or gateway compatibility.

This manager supplies only the manager-side transaction proof. It does not
implement UniVPNNMHostAuthority/HostBinding, acquire TUN or relay handles, inspect
applied/global/dispatcher policy, install services, or change normal application
enablement. The only exercised D-Bus service is synthetic NM on a private bus.

Primary references: [Settings.AddConnection2](https://www.networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Settings.html),
[ActivateConnection](https://www.networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.html),
and [AddConnection2 flags](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-dbus-types.html).

## Read-only host prerequisites

The [host-observation precursor](HOST-OBSERVATION.md) adds receipt-bound initial
NM state observations, retained trusted file pins, and original native-process
identity observations. These are deliberately not HostAuthority/HostBinding
implementations. An NM property, root UID, executable hash or matching namespace
identifier never grants exclusive host-network ownership, readiness or cleanup
authority. The separate packetrelay precursor now has concrete TUN acquisition
and retained local relay ownership. TUN operations remain injected; anonymous
local packet pairs are real. The local correlation described below connects their
retained identities without supplying the missing host-policy authority.
Applied/global/dispatcher policy, independent absence readback and authorized
real-kernel acceptance remain missing; normal application enablement is unchanged.

The same receipt now provides a separate post-publication `ObserveIPv4` path:
it reads the exact ACTIVATED connection's bounded NM IPv4 projection and compares
modern/legacy address and route fields with its already-bound native offer.
It rejects DNS/IPv6, unsupported attributes and observed drift, without NM writes
or a caller-selected path. The [observation contract](HOST-OBSERVATION.md#post-publication-ipv4-projection)
documents source-derived NM 1.52.1 shapes, export truncation/filtering/cache limits,
and private-bus tests. This is historical readback, not a full applied/global
policy validator, host authority, independent absence proof or Ready gate.


## Retained local generation correlation

`ActivationReceipt.RetainedCorrelation` reads only the original manager's local,
already-correlated receipt for the exact authenticated Activation. It does not
contact NM, read boot identity again, write the journal, quarantine, fence or close
anything on rejection. A foreign activation, uncorrelated receipt, local
revocation or quarantine fails. This is retained provenance, not fresh NM state.

The concrete native launch path preserves a private witness only when the
explicit `UniVPNPacketPairProvider` created the pair. The witness retains the exact
opposite packet endpoint, original process object and generated session through
fixed-FD wiring and the reviewed bootstrap wrapper. Other trusted providers do
not gain this proof. It is a reference to original identity, not a duplicate
handle, second owner, process lookup, or replacement cleanup path.

`UniVPNNMBroker.RetainLocalBinding` makes one non-owning attempt to correlate that
witness, the original process observation, the actual manager receipt and the
exact `TUNRelay` endpoint. The existing independently supplied HostBinding must
already have prepared the broker. This new association does not implement or
replace that boundary, start a relay or worker, create a TUN, mutate NM, or enable
the normal application. Receipt, process, offer, cancellation and relay identity
are checked again before the token is committed. Matching a retained TUN's name
to the NM interface is only consistency; it does not prove that NM controls this
particular device or that the device lives in the host network namespace.

The returned opaque local binding and copied snapshot remain historical evidence
after cancellation, worker exit or failed cleanup. `CheckLocalBinding` does not
perform live checks, authorize publication, or prove absence. Failed and repeated
attempts neither close an unrelated supplied relay nor transfer any ownership.
The existing broker/host and relay owners retain all cleanup obligations and
uncertain-close evidence. Sequential readbacks are not an atomic snapshot and
cannot exclude changes immediately after the final check.

Tests separately exercise concrete anonymous-pair/relay identity with injected
TUN I/O, private process-file fixtures, local receipt invariants and a real private
D-Bus synthetic-NM receipt. Core cross-package orchestration uses private test
seams, not a real TUN/native/NM end-to-end acceptance claim. Applied/global policy,
independent network absence, actual host namespace/device association and authorized
real-kernel/gateway acceptance remain open deployment gates.

## Read-only kernel observation boundary

The retained local association can now carry the original TUN's descriptor-derived
namespace pin and sequential rtnetlink link metadata. See the packetrelay
[namespace/link contract](../packetrelay/README.md#descriptor-namespace-and-link-observations).
This is not actual NM-device ownership, initial host-namespace identity, exclusive
HostAuthority/HostBinding, applied/global/dispatcher policy, Ready or independent
network-absence proof. The core wrapper deliberately preserves historical local
provenance without refreshing native/NM liveness. The normal application remains
disabled for this experimental path. Tests inject all TUN, namespace and netlink
operations; no real-kernel acceptance has run. The previous product gates remain
open rather than being marked complete by mock or CI evidence.


## Conditional service composition

`core.NewUniVPNNMService` now supplies the concrete native factory for
`nmvpn.Service.Run`: the same pinned Plugin accepts Connect, the manager correlates
its actual activation receipt, the native bridge prepares retained resources,
and DBusPeer/Controller publish and withdraw that exact generation. Missing host
authority, global-policy admission/revocation, launch inputs or durable barriers
fail closed before activation. No configured default enables the path.

A mandatory policy-revocation channel cancels forward work and initiates bounded
cleanup even after publication. It is provider evidence, not a new host lease.
Caller cancellation preserves the plugin bus through shutdown; uncertain in-flight
D-Bus calls still invalidate it. Each partial native result is retained and closed,
STOPPED is emitted only after local close, and activation intent remains quarantined
even after independent network-absence proof. Nothing here returns `core.Ready`.

See [SERVICE.md](SERVICE.md) for ownership, callback lock order, startup timeout,
private-bus verification and the still-missing executable/registration/deployment
and real-host acceptance gates. Synthetic NM and fake host authority are tests,
not interchangeable production providers.

## Correlated local/NM IPv4 observation

`UniVPNNMLocalBinding.ObserveIPv4` connects the post-publication NM projection to
its retained original receipt, concrete authenticated activation and historical
local worker/relay association. No caller supplies substitute identities, paths,
offers or expectations. It checks the local association before and after the NM
read, requires the complete native binding and address to agree, and returns
independent copies. The original receipt's one-attempt/quarantine semantics still
apply; the wrapper does not retry or recover a failed observation.

This is a read-only orchestration boundary, not a host policy implementation.
It does not read kernel routes, RPDB or resolver state, refresh historical local
liveness, supply the independent HostBinding, authorize Ready or cleanup, or
change application enablement. Core tests inject only the cross-package read;
existing private-bus tests cover the NM observer separately. No combined live
NM/TUN/gateway acceptance is implied.
