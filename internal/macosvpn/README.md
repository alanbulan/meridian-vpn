# Existing macOS L2TP service control (not enabled in the application)

This package implements actual CoreFoundation/SystemConfiguration function
bindings, not a simulated backend. It is an **unintegrated development primitive**,
not a completed VPN backend. It is not called by the GUI or `meridianctl`.

## Scope

- Opens an explicit service identifier, not a display name. Requires an enabled
  service whose interface chain is PPP over L2TP. Never creates, edits or removes
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
