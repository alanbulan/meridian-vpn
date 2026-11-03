# Existing macOS L2TP service control (not enabled in the application)

This package implements actual CoreFoundation/SystemConfiguration function
bindings, not a simulated backend. It is an **unintegrated development primitive**,
not a completed VPN backend. It is not called by the GUI or `meridianctl`.

## Scope

- Opens an explicit service identifier, not a display name. Requires an enabled
  service whose interface chain is PPP over L2TP. IDs are limited to 127 ASCII
  alphanumeric/hyphen bytes, leaving a NUL byte in the 128-byte native text buffer. Never creates, edits or removes
  a system VPN profile, installs a helper, requests elevation or writes secrets.
- `StartExistingL2TP` requires explicit authorization for that existing service.
  This includes use of credentials already configured in macOS; the package makes
  no claim that those system credentials are ephemeral or absent from Keychain.
- Refuses a service already connecting/connected/disconnecting. Calls
  `SCNetworkConnectionStart` with NULL overrides and `linger=false` and retains
  the returned native reference. The OS can deny the request.
- Start is asynchronous. `WaitConnected` tolerates initial Disconnected until
  Connecting/Connected is observed; regression to Disconnected after progress is
  a failure. Callers must supply a deadline/cancelable context to bound a start
  that never advances. Progress is retained across waits and Status observations.
- `WaitConnected` observes only the OS's high-level status. **It does not satisfy
  `core.Session.Ready`**: interface/address, route/DNS and intranet verification
  are still absent. A successful start request alone is never Connected.
- Caller must call `Stop` after successful Start, including after a canceled or
  failed wait. Stop uses `forceDisconnect=false`; it cannot forcibly disconnect
  another application's interest. It releases the reference only after observing
  Disconnected. On timeout/error the caller retains the Session and must report
  cleanup uncertainty and may retry Stop. Do not abandon the session silently.
- OS arbitration is not exclusive ownership. A second application may race the
  initial disconnected check or edit a system service. This primitive does not
  create an immutable configuration lease and is not suitable as a security
  boundary against concurrent privileged configuration changes.

The main Engine currently requires per-attempt L2TP password/PSK. Reusing an
existing system service needs a distinct, explicit UI/configuration mode; quietly
mapping a Meridian profile to a similarly named service would be incorrect.
No automatic dispatch has therefore been added.

## Verification

- Platform-independent fake tests cover authorization, identifier validation,
  refusal to adopt active services, failed/canceled start, connected-state polling,
  stop failure, cleanup uncertainty, retry and reference release. Deterministic
  asynchronous status fixtures cover delayed propagation, missed Connecting,
  never-advancing starts, regression after progress, and progress across retries.
- Darwin-only fake bindings test CF ownership, strict service types and the exact
  NULL/no-linger/non-force parameters. These do not exercise a real macOS ABI.
- Intended commands: `go test ./internal/macosvpn`, `go test -race
  ./internal/macosvpn`; on macOS also run the Darwin fake tests with those commands.
  Cross-compile both supported macOS architectures with `go test -c` (compilation
  is not ABI execution).
- This editing environment has no usable Go compiler (`/usr/bin/go` is a different
  program). Tests and cross-compilation have **not been executed here**. Native
  framework loading, real system configuration, signing/entitlements, route/DNS
  restoration, crash behavior and real gateway connectivity are **not validated**.
- Before integration, run read-only native API checks on the minimum supported
  macOS and an authorized isolated L2TP fixture. Do not run mutation tests in CI
  on ordinary hosts or claim connected state proves complete network readiness.

## Official API references

- [SCNetworkConnection header and ABI](https://github.com/apple-oss-distributions/configd/blob/main/SystemConfiguration.fproj/SCNetworkConnection.h)
- [SCNetworkConfiguration interface APIs](https://github.com/apple-oss-distributions/configd/blob/main/SystemConfiguration.fproj/SCNetworkConfiguration.h)
- [SCNetworkConnectionStart](https://developer.apple.com/documentation/systemconfiguration/scnetworkconnectionstart(_:_:_:))
- [SCNetworkConnectionStop](https://developer.apple.com/documentation/systemconfiguration/scnetworkconnectionstop(_:_:))

The ABI uses `int32_t` connection states, one-byte CoreFoundation Boolean,
pointer-width CFIndex, and opaque CF pointers. Frameworks are loaded only on an
explicit call, from absolute Apple system framework paths. No Go callbacks are
registered. This needs execution on macOS to validate beyond source inspection.

## Read-only service-to-interface evidence slice

`Session.InspectInterface` now performs a concrete native read path:

1. Confirm this retained connection is Connected and not stopping.
2. Read `SCNetworkConnectionCopyServiceID` and require the exact requested ID.
3. Read assigned IPv4 addresses from `SCNetworkConnectionCopyExtendedStatus`.
4. Read only `State:/Network/Service/<ID>/IPv4` from SCDynamicStore; extract its
   InterfaceName and Addresses using CF type checks and bounded arrays/strings.
5. Require equal nonempty IPv4 address sets, a `ppp<number>` interface, and a real
   `net.InterfaceByName` with a positive index, Up + PointToPoint flags and all
   those assigned addresses. Private IPv4 addresses are valid; loopback,
   unspecified, multicast, broadcast, link-local and IPv4-mapped IPv6 are rejected.
6. Recheck Connected after inspection. Return interface evidence, not Ready.

This is read-only; it never queries credentials or returns raw native dictionaries.
It currently covers IPv4 only. The reads are **not atomic**: a reconnect between
status samples, stale configuration or interface name/index reuse can escape the
checks. It neither proves exclusive ownership nor validates routes, DNS, traffic
flow, IPv6 policy, tunnel identity over time or cleanup. Do not connect this method
straight to `core.Session.Ready`.

Fake tests cover mismatched service/address/interface data, missing/down/non-PPP
interfaces, invalid CF types, oversized arrays, CF ownership/release, disconnected
state during inspection, rejection after Stop, and serialized Inspect/Stop calls.
These tests have not been run in this environment (no Go compiler); real API
execution is likewise untested.

Official references:
- [Extended status schema](https://developer.apple.com/documentation/systemconfiguration/scnetworkconnectioncopyextendedstatus(_:))
- [Dynamic store API](https://developer.apple.com/documentation/systemconfiguration/scdynamicstore-gb2)
- [Apple schema constants and value types](https://github.com/apple-oss-distributions/configd/blob/main/SystemConfiguration.fproj/SCSchemaDefinitions.h)

## Remaining bridge design gates (not implemented)

- Introduce an explicit "existing macOS system service" profile mode, with a
  selected service ID and a review of its gateway/configuration. Do not reuse the
  per-attempt L2TP password/PSK mode, infer identity from display names, silently
  ignore profile options, or fetch saved secrets into Meridian.
- Bind a session generation to service ID, PPP connection time and interface
  identity, and revalidate the user-approved non-secret configuration around
  activation. Document which concurrent changes can and cannot be excluded.
- Read actual kernel routing state and compare only the expected tunnel policy.
  Declared route settings in SystemConfiguration are not installed-route proof.
- Read service DNS configuration and validate relevant effective resolver
  selection. A populated DNS dictionary is not proof that domain queries select
  it; a successful generic DNS query can be satisfied outside the VPN. Do not
  claim DNS-leak prevention from these observations.
- Before activation capture a bounded baseline for service-owned network state.
  After non-force Stop, require disappearance of this session's service/interface
  state and attributable route/DNS changes. Do not overwrite a global baseline:
  Wi-Fi changes, another VPN and other apps may legitimately alter the network.
  Ambiguous ownership, stale state or another application's retained interest
  must result in cleanup uncertainty, not force-disconnect or global rollback.
- Only after those contracts are established, implement a core Adapter with
  bounded startup/stop, single Ready/Done publication, cancellation, continuous
  generation-aware observation and CleanupFailed mapping. Its UI must disclose
  existing system credential usage and the limited verification guarantee.
- Validate on authorized isolated macOS hosts: real API ABI, supported OS versions,
  delayed state propagation, concurrent system changes, adapter reuse, route/DNS
  recovery and real gateway traffic. Compilation/fixtures cannot replace this.

### Additional verification gates

Native SystemConfiguration and `net.Interface` reads are synchronous. They have
no cancellation/context deadline and execute under the Session mutex, so a slow
read can delay Stop. A caller context does not bound these native calls. Designing
and verifying a bounded, cancellation-safe inspection/stop path is a production
integration gate; the current primitive makes no bounded-native-call claim.

Additional fake tests inject failures at Copy/Create allocation/read stages and
compare every acquired CF reference against every release, including failures
while reading dictionaries/arrays. Boundary fixtures cover 127/128-byte native
strings and service IDs, empty/negative/16/17-element arrays, bad IPv4 values,
duplicates, and 15/16-byte PPP interface names. These are authored test cases,
not executed results in this environment.
