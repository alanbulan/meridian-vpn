# Linux L2TP/IPsec backend

Implemented in `internal/core/l2tp.go`, using the installed distribution-supported NetworkManager-l2tp service. This is an implemented, mock-tested adapter, not a claim of successful connection to an enterprise gateway.

## Configuration

- Protocol: `l2tp`; gateway: bare hostname or IP address, not an HTTPS URL or host:port.
- Username and session-only password plus IPsec PSK are required. IPsec cannot be disabled.
- Typed `l2tp` options: `ppp_auth` (`pap`, `chap`, `mschapv2`; omitted defaults to MSCHAPv2), `domain`, `remote_id`, `ike`, `esp`, `force_encapsulation`, and `mru`. The shared MTU field is supported.
- Exactly one PPP authentication method is allowed. PAP/CHAP are legacy methods and should only be selected for an administrator-confirmed gateway; encryption is supplied by required IPsec.
- IKE/ESP accept a single algorithm proposal. Lists, whitespace, delimiter injection and arbitrary plugin options are rejected. Empty proposals leave the installed plugin's defaults in effect, which may include legacy algorithms. An administrator should supply approved proposals when policy requires them.
- OpenConnect-specific proxy, TLS certificate, authentication-group, interactive-MFA and disable-UDP settings are rejected rather than silently ignored.

## Secret and lifecycle boundaries

Passwords and PSKs live in `Credentials`, not `Profile`, and do not serialize to JSON. The engine copies and clears its secret buffers. Activation passes secrets on stdin through `/proc/self/fd/0` to nmcli's password-file reader, never command arguments or application-generated files. Secret flags use `2` (not saved). This does not promise that a privileged distro plugin never writes root-only runtime secrets as part of its own IPsec integration.

The adapter creates an in-memory `save no` profile with autoconnect disabled, activates only its newly generated UUID, and deletes only that UUID on failure or disconnect. It verifies activated VPN state and a PPP interface whose address matches that UUID's IP configuration. A random requested PPP unit reduces collisions; pppd can select a different unit during a race, so mismatches fail closed and trigger cleanup. Cleanup uncertainty remains `CleanupFailed` and blocks reconnects.

Dependencies are detected independently for OpenConnect and L2TP. Linux, running NetworkManager, nmcli, the L2TP plugin and its administrator-installed PPP/IPsec dependencies are necessary. OS authorization may be required for actual activation. No dependency installation or host network changes were performed during development.

## Verification

Added controlled tests cover secret-free argv, ephemeral profile and secret flags, typed option mapping, JSON exclusion, invalid host/parameter/secret rejection, missing plugin, cancellation, add/activation/readiness/address failures, rollback, and cleanup failure. `go test ./...`, `go vet ./...`, and `go test -race ./internal/core` passed on the restored source during implementation.

Still requires an explicitly authorized Linux integration environment and gateway: distro/plugin version compatibility, actual IKE/PPP negotiation, policy-authorized proposal selection, routed traffic and DNS, cancellation under real polkit authorization, and verified network restoration. No real TUN, routes, DNS, PPP or IPsec service was changed in tests.

## Primary references inspected

- Maintained project and dependency documentation: https://github.com/nm-l2tp/NetworkManager-l2tp
- Property names and authentication types: https://github.com/nm-l2tp/NetworkManager-l2tp/blob/main/shared/nm-service-defines.h
- Plugin property validation, secret dictionary, PPP and IPsec mapping: https://github.com/nm-l2tp/NetworkManager-l2tp/blob/main/src/nm-l2tp-service.c
- nmcli temporary profiles, UUID activation/deletion and password-file: https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html
- PPP unit collision behavior: https://github.com/ppp-project/ppp/blob/master/pppd/sys-linux.c

No upstream implementation code was copied into this adapter.
