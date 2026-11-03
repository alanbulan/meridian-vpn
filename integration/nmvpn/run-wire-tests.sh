#!/usr/bin/env bash
# Synthetic wire fixtures only. Never connect to a host NetworkManager or bus.
set -euo pipefail
umask 077
[[ ${MERIDIAN_NMVPN_WIRE_TESTS:-} == 1 ]] || { echo 'Explicit MERIDIAN_NMVPN_WIRE_TESTS=1 opt-in is required.' >&2; exit 2; }
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
command -v dbus-daemon >/dev/null || { echo 'Install the official dbus-daemon package in disposable CI.' >&2; exit 2; }
command -v go >/dev/null || { echo 'A supported Go toolchain is required.' >&2; exit 2; }
# Resolve the selected official toolchain before replacing HOME.
go version >/dev/null
private="$(mktemp -d "${TMPDIR:-/tmp}/meridian-nmvpn-run.XXXXXXXX")"
trap 'rm -rf -- "$private"' EXIT
export HOME="$private/home" XDG_RUNTIME_DIR="$private/runtime" XDG_CONFIG_HOME="$private/config" XDG_CACHE_HOME="$private/cache" XDG_DATA_HOME="$private/data" XDG_STATE_HOME="$private/state" TMPDIR="$private/tmp"
mkdir -m 700 -p "$HOME" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME" "$TMPDIR"
unset DBUS_SESSION_BUS_ADDRESS DBUS_SYSTEM_BUS_ADDRESS DBUS_STARTER_ADDRESS DBUS_STARTER_BUS_TYPE DBUS_SESSION_BUS_PID DBUS_SESSION_BUS_WINDOWID
reports=reports/nmvpn-wire
mkdir -p "$reports"
dbus-daemon --version > "$reports/dbus-version.txt"
go version > "$reports/go-version.txt"
python3 integration/nmvpn/export-profile-fixture.py "$reports/libnm-profile.json"
export MERIDIAN_NMVPN_PROFILE_FIXTURE="$root/$reports/libnm-profile.json"
go test -race -count=1 -timeout=120s -tags nmvpnintegration -run '^TestNMVPNWire' -json ./internal/nmvpn | tee "$reports/tests.jsonl"
