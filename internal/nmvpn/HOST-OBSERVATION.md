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
