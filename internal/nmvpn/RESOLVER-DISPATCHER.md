# Resolver and dispatcher observations

These Linux APIs are independent read-only prerequisites. They do not implement
`ServicePolicy`, `UniVPNNMHostBinding`, network readiness or cleanup authority.
No application entry point enables them automatically.

## Complete sampled link membership

`packetrelay.ObserveKernelLinkSet` performs a complete `RTM_GETLINK` dump in an
independently identified current network namespace. It uses the existing bounded
kernel-only multipart transport, never `setns` or a caller-selected link subset.
Incomplete/interrupted replies, namespace drift and uncertain close return no
token. Its opaque self-bound token returns copied, sorted index/name metadata.
The maximum accepted set is 1024 links. Names and indexes are historical values,
not device generations; before/after agreement cannot exclude ABA or atomicity
races. A namespace inode alone does not establish initial-host provenance.

## Dedicated systemd-resolved observation

`OpenPinnedResolvedObserver` owns a fresh dedicated Unix stream and uses EXTERNAL
D-Bus authentication, socket peer UID, BusID, unique resolved owner and owner UID
pins. The system bus must have the independently provisioned root peer UID;
the resolver owner has its exact independently provisioned service UID, which
is normally systemd-resolve rather than root. Endpoint and service/namespace
provenance must come from trusted provisioning. It does not discover a bus, reconnect, activate a service, resolve
a DNS name or invoke any resolver setting method.

`ObserveAllLinks` brackets two resolver policy reads with concrete complete kernel
link observations. Every sampled link must have a successful `GetLink` and
supported individual property reads; loopback/down/unmanaged links and failures
are not silently omitted. Bounded introspection checks the exact target property
schema before and after each object read. `GetAll` is forbidden because its
dictionary decoding can conceal duplicate wire keys. The introspection parser
permits only the fixed inert standard D-Bus DOCTYPE preamble used by systemd; it
never fetches a DTD or expands custom entities. Manager and per-link policy must agree, and the returned membership must
remain identical. The closed capability contract requires the reviewed Manager
and Link property schemas and a successful empty `ListDelegates` (introduced
in systemd 258). This deliberately does not claim compatibility with older
resolved implementations. Resolver
observation is further capped at 256 links and 256 entries per property. Missing methods,
unknown properties, unsupported modes, malformed tuples and nonempty delegation
fail closed rather than downgrading to a partial projection. Known telemetry is
validated but omitted from policy equality. These application-level size limits
apply after D-Bus decoding; they are not a hard transport allocation bound.
Before/after schema agreement also cannot exclude transient schema changes.

The snapshot covers configured DNS and extended server parameters, domains,
default-route behavior and the supported LLMNR, multicast-DNS, DNS-over-TLS and
DNSSEC modes. It does not inspect positive trust-anchor files, NSS configuration,
other resolver processes, firewall policy, mount/initial-host provenance or
whether the pinned resolver process occupies that exact namespace. Those remain
independent requirements. Source-reviewed schemas are not live interoperability
proof for every systemd version.

## Sticky revocation monitoring

`StartResolvedPolicyMonitor` takes the dedicated observer after validating its
inputs, samples its baseline and repeats observation every second. Observed
owner/property changes, transport loss, changed policy/membership, read error or
cancellation permanently revoke it. It never rebaselines or reconnects. `Close`
cancels and joins its observation worker and revocation watcher; `Wait` reports
terminal loss and retained cleanup errors. A clean observation-transport close
is not network cleanup.

Many resolved properties explicitly do not emit change notifications, so signals
alone are insufficient. Polling supplements them but cannot detect every silent
transient change or guarantee future stability. Publication still requires a
fresh synchronous independent policy check. The monitor does not approve its
initial baseline or grant Ready merely because no change has yet been observed.
A deployment must establish and approve the intended phase before starting it;
creating the TUN after baseline capture changes membership and intentionally
revokes the monitor rather than silently authorizing that transition.
The underlying syscall and D-Bus cancellation/timeout caveats still apply.

## Complete empty dispatcher-tree observation

`OpenEmptyDispatcherObservation` fixes the two supported hook roots to
`/etc/NetworkManager/dispatcher.d` and `/usr/lib/NetworkManager/dispatcher.d`.
Both must exist. It walks descriptor-relative without following symlinks,
requires trusted root ownership and directory permissions, and retains every
ancestor/accepted directory identity. Only the four known immediate empty
subdirectories (`pre-up.d`, `pre-down.d`, `no-wait.d`, `device`) are accepted.
Unknown, hidden, disabled, non-executable and symlink entries are all rejected.
Repeated bounded enumeration observes omissions through the pinned parent.
`Check` permanently latches any change/error; copied or zero observers cannot
reuse another instance's handles. `Close` releases only the original handles.

This establishes a narrow sampled filesystem condition, not dispatcher
quiescence. It cannot exclude previously queued/running scripts, earlier script
effects, other build-specific search paths or concurrent privileged mount/root
changes. No script is read or executed. A future production host provider must
independently establish service/process/queue absence and its supported NM build
contract before relying on this condition. No background watcher is hidden in
the filesystem observer; composition must explicitly recheck it.

## Validation boundary and sources

Unit fixtures use temporary owned files and injected netlink/D-Bus data. Socket
restrictions in the development executor prevent live/private-bus listener
validation there; dedicated CI can exercise synthetic services. No privileged
host mutation, real system bus, actual TUN, systemd-resolved or VPN gateway
acceptance is implied by these tests.

- [systemd-resolved D-Bus API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.resolve1.html)
- [NetworkManager dispatcher behavior](https://networkmanager.dev/docs/api/latest/NetworkManager-dispatcher.html)

The documentation explicitly warns that dispatcher jobs can run after a later
event makes them obsolete. Empty directories alone must never become an
already-running/queued-job absence certificate.
