# Host-authority prerequisites: observations only

This slice adds bounded, read-only observations. It intentionally does not
implement `UniVPNNMHostAuthority`, `UniVPNNMHostBinding`, a host lease, readiness,
or cleanup proof. The normal application stays disabled for this experimental
path. Supplying these observations cannot replace the missing authority.

## Pending NM activation

An observation starts only from this process's opaque, already-correlated
ActivationReceipt and its exact authenticated Activation. It does not accept a
caller-selected UUID, active path, settings path or replacement connection.

The supported phase is initial `ACTIVATING`, before configuration publication.
The observer does not establish whether native credentials were consumed or a
worker was started. Requiring `ACTIVATED` here would be circular: NM needs
the plugin's later configuration to complete activation. The observation checks
the fixed boot/bus/unique-owner pins, current bounded profile/envelope, exact
returned active/settings references and membership in NM ActiveConnections.
It requires typed lifecycle/default/configuration references and records parent
device paths. Repeated reads must agree on the projected state. Missing, malformed,
unsupported, changed, canceled or inaccessible evidence fails closed.

The reads use the retained pinned connection and `NO_AUTO_START`; they do not
discover a system bus, reload NM, probe connectivity, reapply profiles, activate
another connection, deactivate, write properties or install a service. A failed
observation can quarantine the local transaction and close its own connection.

These are necessary distinctions:

- `Default=false` does not exclude split `/1` routes, other policy tables or
  external networking. It is NM's default-route attribution, not kernel policy.
- Configuration paths equal to `/` while ACTIVATING are unavailable evidence,
  not proof that routes, addresses or DNS effects are absent.
- ActiveConnection Devices can identify parent devices. Their
  `Device.GetAppliedConnection` is not the VPN's applied profile or a retained
  TUN handle. This slice does not make that substitution.
- GetSettings is the stored profile, not a complete applied/kernel/global-policy
  snapshot. `route-table=0` may inherit global configuration.
- Equal sequential samples detect observed drift only. They provide no atomic
  snapshot, lock, lease, or protection against changes after return.

## Post-publication IPv4 projection

`ActivationReceipt.ObserveIPv4` is a separate one-shot observation after both
configuration signals. It derives the exact binding and offer from the same
authenticated Activation, not caller-selected paths or an expected-route list.
It requires the correlated manager receipt, successful password handoff, immutable
native binding, and the exact active connection in ACTIVATED state. It reads that
connection's own IP4Config through the retained pinned bus with NO_AUTO_START.
It does not use a parent device's GetAppliedConnection. Call it outside Broker
callbacks, which already hold the bus serialization lock.

The closed projection checks one exact offered IPv4 address, every offered direct
route, no other route except the exact directly connected subnet, main-table
routes only, no default gateway, and empty DNS/WINS/search/options collections.
It requires `/` IPv6 and DHCP configuration references. Modern and deprecated
IPv4 arrays must agree, including metrics. Unknown address/route attributes,
missing properties, malformed signatures, duplicates, foreign references and
observed drift fail closed. Address/next-hop integers use native-endian in_addr
bytes; prefixes and metrics remain ordinary uint32 values. Routes are compared
as sets. DNS priority and route metrics are observed values, not approved global
policy. The supported source-derived shape is NM 1.52.1; there is no permissive
fallback for older versions with missing modern properties.

Two complete projections, current secret-free settings, active membership and
boot/bus/owner/local activation pins must agree. Success returns copied historical
data only. Failure quarantines the local transaction and closes its pinned
connection, but sends no NM mutation, installs no service, and owns no cleanup.
A copied receipt cannot repeat the observation. This cannot implement
HostBinding.CheckLive, ProveAbsent, a host lease or core.Ready. It does not poll
until activation or automatically wire the normal application.

The reviewed NM source limits address/route export to 100 records and excludes
non-unicast routes; deprecated Routes additionally omit defaults and non-main
tables. This observer rejects 100 or more projected routes and accepts at most
98 offered routes plus one connected prefix. That bound avoids accepting an
observed truncation boundary but does not recover omitted route types. IP4Config
also uses cached, rate-limited platform notifications. Even two matching samples
therefore cannot prove all kernel routes, RPDB rules, current resolver state,
initial host namespace identity, global configuration, dispatcher quiescence,
absence, or an atomic snapshot. It is a concrete NM read path, not the missing
independent kernel/global-policy proof.

The tests use a real private D-Bus daemon and synthetic NM with source-derived
values, including actual manager receipt correlation, credential handoff, binding
and both directed publications. No native worker, system bus or real NM daemon
is started. No TUN, NETLINK_ROUTE socket or host network operation is attempted.
These tests do not replace authorized real-NM/kernel/gateway acceptance.

Primary implementation references:
- [NM 1.52.1 IPv4 object and cached platform projection](https://github.com/NetworkManager/NetworkManager/blob/1.52.1/src/core/nm-ip-config.c)
- [NM 1.52.1 address/route serializers, limits and legacy byte order](https://github.com/NetworkManager/NetworkManager/blob/1.52.1/src/core/NetworkManagerUtils.c)
- [IP4Config property signatures](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.IP4Config.html)

## Explicit trusted file pins

The file observer opens only an explicitly provisioned, bounded list of paths and
SHA-256 pins. Production uses root-owned files and a root-owned ancestor walk,
retains opened file/directory descriptors, and never follows path symlinks.
It refuses untrusted writable components, unsafe types, hard-link aliases,
oversized files, content mismatches and observed metadata/path replacement.
Revalidation checks the retained objects and the approved pathname walk. No file
is created, rewritten, executed or deleted, and configuration bytes are not
exposed through the observation API.

This proves only the observed identity and bytes of the supplied files. It does
not prove that the manifest includes every NM configuration fragment, runtime
override, dispatcher directory or executable dependency. Root can change files
and mounts; owner-writable files are supported. Hash equality is not a code
signature or an approval of what a dispatcher script does. Filesystem reads can
block in the kernel, so bounded reads and cancellation checks are not a promise
that an arbitrary hostile filesystem operation is interruptible.

## Original native process

The original concrete launcher captures a `/proc` directory descriptor directly
after the child's successful Start, before returning it to the owner of the sole
Wait. Later observations use that retained descriptor, not a caller PID or a
name lookup. Linux does not retarget a stale proc directory descriptor to a reused
PID. Observation failure does not discard a started child or introduce another
Wait. The existing Wait invalidates the observation handle.

Identity is assessed only after the authenticated native offer, since the worker
bootstrap may legitimately exec and drop privileges first. Executable identity,
process start time, credentials and namespace identifiers are local observations.
A root UID is neither required of the isolated worker nor evidence of network
authority. Namespace device/inode pairs do not establish that a namespace is the
initial host namespace. Equal process samples do not exclude an exec-away-and-back
race, memory modification or same-privileged-user ptrace. Executable bytes do not
attest loaded libraries, mapped code or everything the process executed. No API
accepts a caller PID as ownership or signals a process based on this new evidence.

## Evidence still required

Independent retained TUN and relay handles, constrained packet policy, complete
applied/global/dispatcher policy, kernel route/RPDB/resolver readback and
generation-specific absence proof remain missing. Dispatcher scripts may run
asynchronously, in parallel, or after queued events become stale. Neither
ACTIVATED nor reading the script files establishes quiescence. Existing base
connection DNS is not automatically a VPN DNS leak.

Tests use synthetic NM on private buses, temporary files and synthetic process
records. They do not connect to real NM, modify host networking, install services
or establish real-gateway acceptance. Test-only filesystem/proc fixtures cannot
be selected through production APIs.

## Primary references

- [NM ActiveConnection](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Connection.Active.html)
- [NM Device.GetAppliedConnection](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.Device.html)
- [NM activation API](https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.html)
- [NM VPN parent/tunnel distinction](https://github.com/NetworkManager/NetworkManager/blob/main/src/core/vpn/nm-vpn-connection.c)
- [NM configuration](https://networkmanager.dev/docs/api/latest/NetworkManager.conf.html)
- [NM dispatcher](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/NetworkManager-dispatcher.html)
- [Linux proc filesystem and retained PID descriptors](https://docs.kernel.org/filesystems/proc.html)

## Separate TUN resource implementation

`packetrelay.AcquireTUN` now implements a narrow concrete new-TUN acquisition
path with retained private descriptors, strict creation/readback flags and
once-only cleanup. It is not wired to this observer, ActivationReceipt, native
bridge, or normal application. Its production invocation would change network
state; only injected tests run in CI. It cannot replace HostAuthority/HostBinding.
See [its resource contract](../packetrelay/README.md#separate-retained-tun-acquisition-precursor).
Actual namespace/activation/native-generation correlation, applied/global policy,
relay ownership and independent network-absence readback remain missing.

