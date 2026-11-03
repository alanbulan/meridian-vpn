# Linux independent verification matrix — 2026-11-03

Scope: native MyGo client source; no actual host route/DNS edits, VPN activation, privileged service installation, test credential insertion or external gateway authentication performed by reviewer. macOS/Windows work paused at user direction.

| Layer | Evidence | Result / remaining gate |
|---|---|---|
| Profile/store validation | Independent isolated tests: >1MiB config followed by hidden JSON; multiline profile name | Pass after builder fixes |
| Authentication parser | Duplicate RESOLVE key where first value empty; existing injection tests | Pass after builder fixes; strict supported-output subset, not universal auth |
| State/concurrency | Whole copied core suite, Go race detector, 100 repetitions | Pass |
| Tunnel monitor failure | Start mock NM session, await Connected, then change mock status to notReady; run actual 2s monitor | Pass: Failed, not ordinary Disconnected |
| Terminal readiness | 100 sessions with successful Ready and terminal Done already queued | Pass: no Connected/readiness event |
| Typed-nil adapter session | Initial independent stress found nil dereference in Stop; latest builder nilInterface guard | Fixed; repeated stress passes |
| Activation/deletion contracts | Existing mocked tests inspect ephemeral profile, UUID ownership, stdin tuple and cleanup errors | Pass in suite; mocked only |
| OS subprocess fidelity | No real OpenConnect/NM activation | NOT established by mocks |
| Real tunnel | No approved live gateway test | NOT VERIFIED |
| Network correctness | Routes, internal DNS, IPv4/IPv6 leakage, MTU, DTLS, sleep/network switches | NOT VERIFIED |
| Real failure recovery | Gateway auth errors/MFA, OS authorization denied, NM daemon restart, process crash, physical link loss | Source/mocks partial; live tests required |
| Distribution | Host architecture build not equivalent to signed packaged release | Release verification pending |

Commands:
- `GOCACHE=/tmp/mygo-go-cache GOPATH=/tmp/mygo-gopath /workspace/shared/toolchains/go/bin/go test -race -count=100 ./core` in isolated copied `/tmp/mygo-vpn-adversarial`: PASS (`ok audit/core 1.736s`).
- Same toolchain `go test -race -run TestAudit -v ./core`: all 5 independent tests PASS (`ok audit/core 3.025s`).
- Independent source/test artifacts: `/tmp/mygo-vpn-adversarial/core/adversarial_test.go`.

## Live Linux acceptance prerequisites
An explicitly authorized disposable Linux test machine or isolated network lab with working TUN, NetworkManager/OpenConnect plugin, system D-Bus and Polkit; an identified AnyConnect-compatible gateway, test account/auth requirements and scoped network-change authorization. Credentials should be entered by the user privately, never pasted into source or argv. Record before/after routes and DNS, tunnel IP, accepted server identity, intended internal endpoint reachability, and cleanup. Existing user VPNs must be untouched. A container with no usable NM/TUN is not adequate evidence of full-chain operation.

## Relevant official contracts
- https://www.infradead.org/openconnect/nonroot.html — separate unprivileged auth and NM cookie/gateway/gwcert/resolve tuple.
- https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html — activation, ephemeral `add save no`, UUID-oriented deletion.
- https://raw.githubusercontent.com/GNOME/NetworkManager-openconnect/main/src/nm-openconnect-service.c — named TUN supported by plugin.

## Advanced-feature review, 01:23 UTC
- Real option flow reviewed: auth-group and additional CA in unprivileged authentication; proxy in both phases; MTU and disable-UDP in NetworkManager plugin configuration.
- Found/fixed: ignored OpenConnectArgs CA validation error; FIFO path could block CA open. Current CA preflight uses bounded cert-only PEM parsing, IsCA validation and Linux nonblocking/no-follow file open with identity recheck.
- Proxy privacy: embedded credentials and unsupported HTTPS proxy schemes rejected. The auth subprocess uses --proxy-auth=none. Since the NM plugin cannot restrict integrated auth in phase two, fresh explicit per-session consent is required; consent is not JSON serializable/importable and UI resets it. This is not anonymous-proxy support.
- Metrics are actual counters/IP on the generated owned interface, cached off the UI path. Missing counters are unavailable, not fabricated 0; disconnect clears session metrics/time.
- Auth parser accepts actual OpenConnect RESOLVE= empty output without accepting arbitrary unquoted assignments or shell evaluation.
- Fresh isolated `go test -race -count=1 -v ./core` PASS (3.090s), `go vet ./core` PASS, including independent adversarial cases. Explicit real OpenConnect loopback tests remain opt-in (not counted as executed in this run).
- No additional critical source finding at this snapshot.
