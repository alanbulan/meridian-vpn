# UniVPN isolated dataplane: implementable boundary and remaining gate

Status: design plus independently testable descriptor intake, not a deployment.
Nothing here grants a namespace lease, starts a privileged helper, configures a
host, or makes the native backend ready. Current default stays disabled.

## Why wrapping the current executable in `ip netns exec` is insufficient

The native executable currently acquires its TUN with administrative privilege.
Putting that TUN and its routes in a new network namespace does not carry the
host's application traffic. A host systemd-resolved link index does not address a
private-namespace interface. Mounting another resolv.conf only affects processes
using that mount view; it does not configure host DNS. A cgroup plus a process
exit is not a containment proof if the process can migrate itself or descendants.
A lock file cannot exclude other host CAP_NET_ADMIN writers.

Linux namespaces isolate network devices, stacks, route tables and firewall
state; namespace identity therefore belongs in every network resource handle,
not only a launcher option. [Linux network namespace documentation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)

## Preferred split: broker owns host networking, native owns TLS and packets

1. A trusted broker creates a fresh, nonpersistent, single-queue host TUN and
   retains its FD. It records the host namespace FD identity, ifindex, random
   session alias and exact approved configuration. The worker cannot create,
   rename, configure or replace interfaces.
2. Before publishing tunnel routes, the broker resolves and approves one IPv4
   endpoint and TCP port, creates separate connected control and data sockets,
   and verifies their actual peer. No gateway-provided redirect broadens policy.
   The native executable retains the original hostname for TLS SNI and certificate
   verification, and checks the data peer certificate against the control peer.
3. A trusted bootstrap creates an empty network namespace and a dedicated cgroup
   before native execution, passes only selected descriptors, drops all worker
   capabilities and supplementary groups, sets a dedicated unprivileged identity,
   no-new-privileges and a reviewed seccomp policy, and exposes no writable cgroup
   filesystem, namespace handles, host proc tree or broker control channel.
   It must also deny access to host filesystem Unix sockets, not merely AF_INET.
   The worker must not be able to create nested namespaces to regain capabilities.
   Inherited host TCP sockets remain its only transport. The retained TUN FD
   carries host packets without a veth, forwarding sysctl or NAT installation.
4. Native descriptor adoption must reject partial pairs, duplicates, reserved
   descriptors, proxies, reconnect/fallback connect attempts and redirected
   destinations. A disconnected channel ends the session; a new authenticated
   broker transaction is needed for another endpoint. TUN-FD adoption must skip
   native TUN creation/netlink configuration, not merely ignore permission errors.
5. The broker applies only approved split routes and per-host-TUN DNS route-only
   domains, then verifies actual state. No default-route or IPv6 compatibility is
   claimed. Host resolver configuration uses the host TUN identity, not a private
   worker interface index. The worker's resolver is unnecessary in FD mode.

This is a proposed architecture, not proof that the current native build supports
all required descriptor roles. The current `internal/fdtransport` code implements
only the preconnected TCP intake. Its `Prepare` duplicates first with
F_DUPFD_CLOEXEC, then checks socket type/protocol, connected IPv4 peer/port and
separate underlying socket identities. `Files` returns control then data for a
future trusted launcher's ExtraFiles. It neither connects nor spawns. The caller
must own the original FDs exclusively and close or stop using all aliases before
releasing the worker; duplicates share the same underlying socket state.

Compatibility constraint: opening both TCP connections before control authentication
changes connection timing. A server may reject or time out an idle data connection.
The existing native path opens data TLS after login. Loopback tests and actual
gateway acceptance must distinguish TCP connection timing from TLS/session timing.
If deferred data connection is required, introduce a narrow authenticated broker
connector protocol tied to the same approved endpoint, not arbitrary reconnect
rights or an unvalidated FD-transfer channel.

The proposed descriptor layout is stdin=password, stdout/stderr=discard,
3=session pipe, 4=TUN, 5=control TCP, 6=data TCP. Native transport flags are
`--meridian-control-fd=5 --meridian-data-fd=6`. They must be supplied by the trusted
launcher, never accepted from desktop IPC. The TUN role remains a separate change.

WireGuard documents the upstream userspace precedent: keeping a socket FD opened
in one namespace while switching namespaces. Its kernel interface's birthplace
behavior must not be assumed to apply automatically to this native client.
[WireGuard namespace integration](https://www.wireguard.com/netns/)

The kernel TUN API is FD-based; nonpersistent device lifetime follows its open
references. Retaining a broker FD allows cleanup ordering after worker exit.
[Linux TUN documentation](https://docs.kernel.org/networking/tuntap.html)

## The lease issue cannot be hidden

This architecture contains the native worker but does **not** meet the existing
UniVPNNetworkLease contract that excludes every competing CAP_NET_ADMIN writer
in the host namespace. A normal desktop host has NetworkManager, systemd-networkd
or other privileged services. Neither a random alias, an FD, nor a cgroup revokes
those services' host-network authority. NetworkManager's ownership of a profile
also is not an exclusion against all other privileged writers.

Two honest integration choices require separate review:

- Use an established host network manager's transaction model and explicitly
  define trusted host managers as part of the trusted computing base. Replace the
  current blanket exclusive-lease assumption with object-specific ownership,
  identity-safe operations and conservative conflict handling. Do not implement
  AssertHeld as unconditional success or relax current interfaces silently.
- Keep all tunnel configuration and consuming applications in a dedicated network
  namespace controlled by the broker. This provides isolated application access,
  not transparent whole-host VPN access. Host-wide forwarding/DNS remains a new
  policy surface and cannot be claimed as completed by this option.

Passing a host TUN FD also grants packet injection into the host stack. Dropping
capabilities and isolating network syscalls does not constrain packets written to
that FD. Approved split routes only constrain routing configuration, not the
source/destination of inbound TUN packets. Containment of a compromised native
worker or gateway therefore needs separately reviewed broker-owned ingress and
egress filtering/anti-spoof policy, or an explicit trust assumption for worker
packet payloads. This design does not claim packet confinement without that gate.

Neither defeats a malicious host root. The security model must say so. This
checkpoint selects neither policy downgrade nor permissive adapter.

## Bootstrap and termination implementation obligations

The bootstrap must use a verified native helper or a supported service-manager
transaction. Go's threaded runtime must not casually setns the broker process.
Atomic clone-into-cgroup or an equivalent held-before-exec manager lifecycle is
required; moving an already-running hostile child has a fork/escape window.
An fd-bound cgroup handle and namespace handle must survive PID reuse. Worker
code must not run before namespace/cgroup/capability restrictions are installed.
Passing a root executable to the existing Prepare hook is not sufficient.

The broker journals writes before attempting them. Cleanup closes worker input,
stops the entire cgroup (not merely the leader/PGID), verifies cgroup.events
populated=0 from the held group, drains or closes the session pipe, reverts owned
DNS, removes exact owned routes and releases the host TUN only when its identity
matches. Readback must prove resolver/link/route absence before reuse. Any
uncertain write, PID/namespace mismatch or cleanup failure quarantines the session.
Crash recovery must retain enough private journal identity for reconciliation;
without it, report unknown state instead of deleting matching names globally.

cgroup v2 provides hierarchical populated state and cgroup.kill, but access and
migration restrictions are separate requirements. The source of observation must
be bound to the held cgroup, not a user-supplied pathname.
[Kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

systemd offers relevant isolation directives, but a unit template alone does not
prove effective namespace identity, FD handoff or descendant cleanup on the
installed version. [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)

Per-link DNS APIs take link indices and support per-link domains, default-route
policy and revert. All operations and readbacks must use the matching resolver
and network context. [systemd-resolved API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html)

## Acceptance evidence required before enabling

- Host-capable disposable VM tests of bootstrap ordering, capabilities, namespace
  identity, attempts to migrate cgroups or enter host namespaces, descendant fork
  and leader exit; no fake adapters accepted as real isolation evidence.
- Broker TUN-FD adoption with no worker administrative privilege or new outbound
  sockets, control/data TLS peer verification, cancellation and crash cases.
- Real host application packets and route-only DNS reach only approved prefixes;
  stale resolver records, changing link indices and route conflicts fail closed.
- Disconnect, broker/worker crash and failed intermediate operations leave no
  owned routes/DNS; ambiguous unrelated objects are never removed.
- Real authorized gateway interoperability. Loopback fixtures prove transport
  mechanics, not enterprise compatibility or host routing/DNS recovery.

No host TUN, namespace, route, DNS, cgroup, capability or seccomp change was applied
for this design. The package tests use fake inspection plus ordinary pipe FDs;
real connected-TCP adoption is a separate native-loopback test responsibility.
