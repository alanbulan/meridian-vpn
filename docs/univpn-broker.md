# Linux UniVPN continuous-session broker: implementation and deployment boundary

The implementation in `internal/core/univpn_broker*_linux.go` provides:

- An unprivileged Unix socket client implementing `TunnelBroker`.
- A root-service socket handler with kernel `SO_PEERCRED`, explicit desktop UID admission, a root-owned socket and non-writable root-owned parent directory, bounded requests, connection limits, and deadlines.
- A server-owned executable path and option allowlist. Arbitrary scripts, proxy settings, certificate bypasses, duplicate options and executable substitutions are rejected. Approved CA files must also be root-owned, non-writable, regular files under trusted parents.
- A continuous native-process lifecycle with readiness from a trusted network controller, never output text. Cancellation, early exit and failed readiness lead to cleanup. Stop waits for cleanup acknowledgment; uncertainty is `CleanupError`. A dirty backend remains quarantined, including for other client instances, until out-of-band recovery/restart.
- A Go launcher that does not invoke a shell, requiring a SHA256-pinned root-owned executable and, outside native-channel mode, hook paths. Password goes through an inherited anonymous stdin pipe, never argv/logs/environment. Output is discarded. Leader termination escalates to identity-safe process Kill after two seconds. A mandatory injected isolation provider must prove the entire session cgroup, including hooks, is empty before cleanup. No isolation provider is supplied; the launcher refuses to run without one. Native patch 0006 makes the UniVPN hook a direct exec in the native process group and propagates hook errors; other OpenConnect protocols retain upstream behavior. Hook paths remain constrained to safe ASCII characters. A hook can still detach itself or spawn descendants, so checking only the native leader or its process group is insufficient. No launcher was executed during recovery testing.

## Deliberately unavailable deployment pieces

**This is not an installed or live-connect-ready VPN service.** Default GUI setup does not configure this broker. A concrete Linux controller and `ip`/`resolvectl` command adapter now exist, but they are **not live-validated or wired into the GUI/service**. An opt-in native inherited session source is now implemented (see below), but no exclusive namespace/session lease implementation, reviewed deployed native binary, or process-containment implementation is provided. Their interfaces are mandatory and fail closed without deployment implementations. The recovery-built native wrapper is not a root-trusted deployed executable and must not be configured as one.

A reviewed deployment must still provide all of:

1. Review and integrate the opt-in native inherited session channel, whose identity and lifecycle are bound to the original authenticated native process. The control TLS process must remain alive throughout the connection. A reusable cookie or stdout message is not proof of readiness.
2. Integrate and review the new narrow controller described below with the native session channel and namespace lease. Prove readiness and cleanup on the actual target Linux/iproute2/systemd versions. Cancellation must stop pending setup before rollback. A timeout quarantines the backend; administrators must establish actual cleanup before restarting it.
3. A root-owned deployment directory, pinned reviewed native ELF (and hook only outside native-channel mode), and a service-managed Unix listener. Dedicated-group/ACL socket access is permitted; other access is not. Parent directories must not be writable by desktop users. Exact allowed desktop UIDs are required. Configuration/maps are immutable after service start.
4. A service entry point and service-manager unit, a concrete `UniVPNProcessIsolation` provider that configures process/hook containment before launch and verifies all descendants gone after exit, sandbox/least-privilege policy, startup/restart recovery, deployment packaging, GUI opt-in wiring, and review of allowed gateways and CA policy. Root service code must never inherit caller-provided paths/scripts/environment.
5. Real authorized Linux integration tests for socket ownership/ACL/peer UID, native/hook identity, process cleanup, route/DNS rollback, DNS loss/recovery, endpoint changes and IPv4/IPv6. No privileged host operation, route/DNS modification, real credentials, or enterprise gateway was used here.

## Safe tests and blocked integration

Use the recovery Go environment, then `go test -race ./internal/core`. Mock tests cover readiness/lifecycle, credential-copy clearing, single-session admission, option rejection, cleanup failure quarantine, and bounded message parsing.

The actual `net.ListenUnix` peer-credential test was attempted and **blocked by sandbox EPERM**. It is not a passing integration test. Default runs explicitly skip it with that reason. Only in a separately authorized environment allowing local Unix sockets, run `UNIVPN_TEST_SOCKET=1 go test ./internal/core -run TestUniVPNBrokerPeerCredentialsAndDeniedUID -v`. Do not retry denied socket creation through another route in the recovery sandbox.


## Linux network controller implementation (mock-tested only)

`internal/core/univpn_network_linux.go` implements `UniVPNNetworkController`.
`univpn_network_command_linux.go` provides the privileged operation boundary using
absolute, root-owned regular executables, direct argv (no shell), a scrubbed
process environment, bounded output and bounded pipe drain after cancellation.
Constructors do not execute commands or modify networking.

Mandatory inputs are deliberately not replaced by permissive defaults:

- An authenticated `UniVPNNetworkSessionSource` must bind configuration to the
  original continuously authenticated native process and freshly-created TUN.
  It supplies the kernel ifindex and a fresh broker-generated alias, not an alias
  or interface claim from the gateway/client. Its `ProveNetworkGone` must account
  for partial acquisition, rejected configuration and any native/hook-owned state.
- `UniVPNNetworkLease.AssertHeld` must verify an already-held exclusive lease for
  the target network namespace and session, retained through cleanup. This must
  prevent competing CAP_NET_ADMIN writers, not merely lock broker goroutines.
  The command adapter checks index/alias/kind before mutations, but subprocess
  name-based `ip` operations cannot atomically check-and-mutate against another
  privileged writer. Do not deploy it without that isolation guarantee.
- Immutable administrator allowlists must explicitly approve exact interface
  addresses, canonical split-route prefixes, DNS servers, DNS routing domains,
  and endpoint IP addresses. A broad route does not authorize arbitrary pushed
  more-specific prefixes. Default routes are intentionally unsupported. DNS
  addresses must be reachable through an approved tunnel route or subnet.

The controller rejects a nonempty or unmarked initial TUN. It pins an endpoint
host escape route before tunnel routes, using create-only route adds, main table,
protocol 186 and a metric derived from the session alias. Existing exact host
routes cause refusal rather than replacement. Tunnel route readiness verifies
ownership attributes in addition to prefixes. Interface addresses and UP state,
DNS servers, route-only domains and explicit resolver default-route=no are read
back. DNS changes are per-link through systemd-resolved; resolv.conf is untouched.
Unrecognized command/resolver output is an error, never proof of readiness.

Cleanup removes only the same index/alias TUN and a successfully-created owned
escape route, then reads back absence of interface, routes, resolver servers,
routing domains/default-route state, and hook/native state. Failed escape
creation with an uncertain visible outcome does **not** authorize deletion:
it quarantines the backend for administrator investigation. Replacement
interfaces, failed commands, missing resolver evidence and partial cleanup also
fail closed. The native process must already be stopped with its descendants
proven empty by the broker's separate containment contract.

`univpn_network_linux_test.go` exercises these boundaries with deterministic fake
kernel/command/source/lease implementations, including partial mutation failures,
uncertain adds, foreign/replaced interfaces, rejected pushed policy, cancellation,
route table/protocol/metric mismatch, stale DNS domains, duplicate DNS readiness
records and missing absence proofs. These tests execute **no ip/resolvectl
processes, TUN creation, privileged service or real gateway connection**. They do
not prove that a target distribution's real command output or privileges work.

## Root-service admission and shutdown

`AllowedGateways` is an explicit, immutable, server-owned map of exact approved HTTPS URLs. Missing policy disables the backend. Requests to any other URL are rejected before credential delivery or native launch. The policy does not authorize redirect destinations or substitute for controller endpoint/route policy; deployment must review native redirect behavior and endpoint restrictions.

Service shutdown cancels active sessions, closes admission and joins all accepted connection handlers before reporting completion. The join is bounded to 20 seconds. Timeout or quarantined cleanup returns `CleanupError`, not successful shutdown. Service-manager policy must treat this as uncertain cleanup and retain the containment/recovery boundary rather than silently restarting a fresh unrestricted session.

## Native inherited session channel (experimental, not activated)

`UniVPNExecLauncher.NativeSessionChannel` opts into the pinned native channel
patch. The launcher creates an anonymous pipe inherited as descriptor 3 and a
fresh random 128-bit session ID. It passes these as broker-owned arguments;
client option validation does not allow either argument. Native channel mode
bypasses all script hooks, marks the descriptor close-on-exec, exclusively creates
the TUN, obtains its kernel interface index, and sets the broker-derived alias
`meridian-<session ID>`. A configuration record is emitted only after native
TUN registration and authenticated live control/data state. None of these
properties is inferred from logs, cookies, environment variables or hook output.

`UniVPNNativeSessionSource` accepts only the launcher-created process object and
its private channel. Each JSON line is bounded to 32768 bytes. Unknown fields,
duplicate keys, incorrect session IDs or aliases, invalid addresses, repeated
configuration, and records after a terminal event are errors that stop the native
process. The record is input to the existing allowlist and kernel/resolver
readback controller, not a readiness acknowledgment. Native channel EOF or a
`closed` record is never cleanup proof. Cleanup requires the isolation provider's
whole-tree empty proof, completed channel drainage, and independent kernel,
route and resolver absence queries.

Graceful failure before any successful TUN acquisition can emit a sole
`no-network` terminal attestation. The source still requires EOF, containment and
independent kernel alias-absence readback. Abrupt death before a complete
configuration, partial acquisition, malformed records, or missing proof remains
quarantined. Reconnection or changing pushed configuration in a running session
is intentionally rejected; it requires a new broker session.

The native emitter's TUN/netlink calls are tested with syscall wrappers, not
executed against the host. Go tests use anonymous in-memory streams and injected
kernel/isolation results. These tests do not prove deployment isolation. An
ordinary filesystem lock cannot prevent competing CAP_NET_ADMIN writers in the
host namespace. Likewise a cgroup membership check alone does not stop a
privileged native process from migrating out. A concrete isolation/lease provider
must enforce those guarantees before it can be supplied. A private namespace
would also need an explicit user-traffic forwarding and namespace-correct DNS
design: host `resolvectl` interface indices cannot be reused for a private
namespace. No service or GUI activation is provided by this channel work.
