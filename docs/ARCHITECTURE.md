# Architecture and trust boundaries

Meridian uses MyGo v0.7.4 native `ui` drawing: no DOM, HTML, JavaScript, Electron, Tauri, Wails or webview. `CGO_ENABLED=0` builds the application. Linux requires GTK3 and font libraries; MyGo loads these with purego at runtime. GPU rendering is optional; `MYGO_GPU=0` selects MyGo's documented CPU renderer.

## Layers

- `cmd/meridian`: process lifetime, native window, tray and configuration location.
- `internal/desktop`: presentation and editing state, immediate-mode native components, no host network configuration.
- `internal/core`: profiles, strict validation, atomic local persistence, adapter contracts, synchronized connection state machine, structured bounded activity history.
- Platform adapters: external trusted system networking service owns privilege, route and DNS cleanup. No GUI privilege escalation and no arbitrary shell commands.

## State machine

Disconnected → Connecting → Connected only after a trusted adapter verifies the actual tunnel, never after process spawn or by matching arbitrary stdout. Cancellation requests Disconnecting; cleanup must finish before reporting Disconnected. Start/readiness failures report Failed and expose no raw subprocess errors. Every start requires explicit authorization. Duplicate starts are rejected. Credentials are not members of persistent configuration and are never logged.

## Persistence

Profiles contain ID, display name/description, HTTPS gateway plus at most15 additional gateways, protocol/account, authentication group, server CA/client certificate/private-key file references, interactive-auth mode, explicit proxy URL, MTU and TCP-only policy. They never contain certificate/key contents, passwords, cookies, one-time codes, key passphrases or proxy system-auth consent. TLS verification cannot be disabled. The JSON schema rejects unknown fields, including accidental secret fields. Configuration is size-limited, versioned and checked for duplicate IDs. Save uses a mode-0600 temporary file, sync and same-directory atomic rename. A corrupt configuration is not silently replaced. POSIX file modes do not substitute for Windows ACL hardening; deployment must secure the per-user directory.

## Compatibility is not a promise

OpenConnect has specific protocol implementations, not universal enterprise SSLVPN compatibility. Proprietary posture checks, authentication and gateway versions can differ. Unknown LeagSoft UniVPN gateways must not be assumed supported. Protocol selection is not proof of a successful gateway interoperability test. macOS and Windows require a separately validated platform backend and packaging/signing integration. This build must never label unavailable prerequisites or a local fixture as a real VPN connection.

## Tests

Core tests use controlled adapters and do not change networking. Native UI tests use MyGo's actual headless UI/test engine, not a browser. Real desktop QA runs the compiled native binary through the cloud Linux desktop; screenshots are captured from that window, separate from test rendering.

## Interactive authentication

The MyGo GUI and CLI build with CGO_ENABLED=0. Optional `meridian-auth-helper` is a separate unprivileged C executable dynamically linked to official libopenconnect. It obtains authentication only, never creates a tunnel. Typed length-prefixed private pipes carry bounded challenge/answer frames, session IDs and round IDs. A helper failure, untrusted TLS, cancellation or malformed/stale frame fails closed. Native UI fields render server labels as inert plain text. Initial credentials and form answers are memory-only; byte buffers are cleared where owned. Go strings and platform input components are garbage-collected, so perfect in-memory forensic erasure is not claimed.

## Switching and diagnostics

Quick switch requests disconnect of the current session, waits for confirmed cleanup, then opens a fresh authentication form for the new profile. It cannot transfer secrets or consent across gateways. Additional gateways are explicit choices, never automatic credential replay. Diagnostics uses only bounded read-only probes with allowlisted output; no network authentication or route/DNS modifications occur. CLI imports create a separate merged file rather than race the GUI's active store.
