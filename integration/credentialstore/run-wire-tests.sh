#!/usr/bin/env bash
# Explicit opt-in only. This starts private temporary fixture buses, never a
# user's session/system bus. All credential values are synthetic test literals.
set -euo pipefail
umask 077
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
command -v dbus-daemon >/dev/null || { echo 'Install the official dbus-daemon package in an isolated CI container.' >&2; exit 2; }
command -v go >/dev/null || { echo 'A supported Go toolchain is required.' >&2; exit 2; }
go version >/dev/null
# No caller-provided bus selector reaches the tests. The tests start a private
# daemon using their own no-activation config and known temporary Unix socket.
unset DBUS_SESSION_BUS_ADDRESS DBUS_SYSTEM_BUS_ADDRESS DBUS_STARTER_ADDRESS DBUS_STARTER_BUS_TYPE
export MERIDIAN_CREDENTIAL_WIRE_TESTS=1
reports="reports/credential-wire"
mkdir -p "$reports"
dbus-daemon --version > "$reports/dbus-version.txt"
go version > "$reports/go-version.txt"
# Do not enable shell tracing or upload HOME, temporary directories or keyrings.
go test -count=1 -timeout=60s -tags credentialintegration \
  -run '^TestCredentialWire' -json ./internal/credentialstore \
  | tee "$reports/tests.jsonl"
