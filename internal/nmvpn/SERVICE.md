# Conditional single-activation service composition

This is a callable service runtime, not an installed NetworkManager plugin or a
production enablement switch. `core.NewUniVPNNMService` is the concrete native
entry. It returns an `nmvpn.Service`; `Run(ctx)` performs one lifecycle and never
returns `core.Ready` or a usable `core.Session`. The normal GUI/CLI remains disabled
for this experimental path. No command-line option, environment variable, package
install or D-Bus service-registration file bypasses the missing authority gates.

## Actual composition

The entry validates/snapshots administrator native arguments, gateway/CA policy
and exact planned username, requires containment with launch rollback, and rejects
any caller-supplied generic factory. Its private factory calls the existing concrete
`StartUniVPNNMBroker`, pinned `UniVPNExecLauncher` and `UniVPNNativeOfferSource`.
There is no alternate process provider on this path. Executable bytes are checked
before NM mutation and again by the launcher before execution. That existing
path-based check is not a retained-inode execution guarantee against root changes.

The platform must supply a fresh `PinnedBus` with independently trusted endpoint
provenance, an immutable narrow profile and nonempty bounded IPv4 allowlist, boot
identity, two distinct exclusively held durable journals, retained host authority,
and an independent global/dispatcher policy provider. Passing an interface,
matching a device name or returning nil from a callback does not establish those
security guarantees. No real host authority or policy implementation is provided.

`Run` performs, in order:

1. Native/host and global-policy preflight, then both empty journal barriers.
2. Serve the closed plugin ABI on the original pinned connection.
3. Persist and execute the one-shot manager activation; receive authenticated
   Connect, then correlate the exact returned receipt before native credentials.
4. Transfer that original receipt/Activation to trusted host authorization, then
   prepare the concrete native generation, retained packet endpoint and host owner.
5. Construct the real DBusPeer/Controller; publish Config then Ip4Config with
   native liveness and independent policy checks immediately before each signal.
6. Mark the NM plugin STARTED only after both publications. This is protocol
   state, not applied-network readiness or real gateway acceptance.
7. Wait for caller cancellation, authenticated Disconnect/owner loss, native
   generation loss or policy revocation, then join bounded teardown.

Every service and native factory is single-use. Copied objects, missing/nil/closed
lifetime channels and replacement receipts fail closed. Snapshots copy mutable
profile/launch/allowlist/offer data. Trusted provider instances remain shared
security dependencies and must not be mutated unsafely by their owner.

## Cancellation and policy

Startup has a 60-second cooperative cancellation bound, including waiting for
Connect. A joined timer stops without canceling the surviving native context after
successful startup. Providers must honor context; this does not forcibly interrupt
arbitrary callbacks, synchronous trusted executable hashing or kernel/filesystem
calls. No detached timeout worker continues a manager mutation in the background.

The plugin has a service-owned lifetime independent of caller cancellation so the
same connection can withdraw during normal shutdown. Cancellation of an in-flight
D-Bus operation still closes the original transport; such uncertain operations
are never retried or replayed.

`ServicePolicy.Done()` is a mandatory stable channel. Its provider closes it when
policy applicability is lost or cannot be proven. One joined watcher cancels
forward work on closure, including pending startup. The captured channel is checked
before activation and before/after publication checks. Revocation causes cleanup
using fresh contexts, not policy approval for more publication. A revocation channel
is not an atomic host-wide lease or protection against simultaneous privileged
changes; a real policy provider and real-host acceptance remain necessary.

`CheckPublication` and all DBusPeer broker callbacks run under the bus lock. They
must not call receipt correlation/observation, plugin state methods or any other
operation on that bus. Initial correlation and final STARTED/STOPPED emission run
outside callbacks. Recovery Verify/Stop/ProveAbsent do not depend on live policy.

## Ownership and shutdown

The constructor performs no D-Bus operation. On success, `Run` consumes the supplied
bus even if preflight fails. The caller owns the journals, keeps them exclusively
open until `Run` returns, and retains the Service after any uncertain result.
Its backend is retained even when native Start returns both a partial owner and an
error. The native owner's sole process Wait is unchanged; Done only observes its
lifetime and is not a second waiter.

After successful publication, Controller.Stop gets a fresh ten-second context.
Local backend.Close gets its own fresh ten-second context regardless of controller
failure. Only proven local stop permits a separately bounded STOPPED signal. Bus
and plugin close last. A failed Publish already performs its cleanup transaction;
the service does not repeat it. Native teardown is sticky and must never repeat a
possibly executed destructive action.

A failure before publication can leave an NM activation/profile without a complete
native binding. An empty publication journal does not authorize withdrawing that
activation. The service preserves/quarantines manager intent rather than inventing
cleanup proof. The activation journal is never cleared, even after Controller
independently proves absence. A new process therefore refuses another activation
until a separately authorized recovery design resolves it. This is durable
containment, not automatic restart/reboot recovery or reusable production service.

The result separates Published, LocalStopped, NetworkAbsent and
ReconciliationRequired. Published is local signal delivery. NetworkAbsent requires
the controller's NM and host proof and is withheld if subsequent local Close fails.
The result deliberately has no Ready flag.

## Verification boundary

Default tests exercise constructor rejection, immutable snapshots, native entry
validation, retained Done ownership, publication gating and the startup timer.
Opt-in private-wire tests execute the real Service/Plugin/ActivationManager/
DBusPeer/Controller over a fresh private dbus-daemon with synthetic NM and temporary
durable journals. The synthetic backend checks original receipt correlation and
performs the real one-shot Activation credential/binding contract. Host/native
resources remain fake; they are never evidence of production host authority.

The fixtures cover synchronous Connect before ActivateConnection replies,
publication/state ordering, cancellation with the cleanup bus alive, partial
acquisition, policy denial/revocation, stale/corrupt journals and single-use behavior.
They do not install/start a privileged service, discover a system bus, create a
TUN, open NETLINK_ROUTE, change real routes/DNS, or contact a gateway.

Still missing: concrete trustworthy host-device/namespace ownership, complete
applied/global/dispatcher policy inspection and revocation, actual independent
host cleanup/readiness readback, packaged executable and NM registration/permissions,
core.Session integration, real NM/kernel/native/gateway acceptance and authenticated
restart recovery. None of these gates is closed by the callable composition or CI.
