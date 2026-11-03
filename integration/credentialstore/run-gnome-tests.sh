#!/usr/bin/env bash
# Only for an explicitly provisioned disposable GitHub Actions job container.
# Never invoke against a user's desktop or a host-mounted HOME/runtime directory.
set -euo pipefail
umask 077
if [[ "${GITHUB_ACTIONS:-}" != true || "${MERIDIAN_GNOME_CONTAINER_TESTS:-}" != 1 || ! -f /.dockerenv || "$(id -u)" == 0 ]]; then
  echo 'Real keyring fixtures require explicit opt-in, a disposable GitHub container, and an unprivileged fixture user.' >&2
  exit 2
fi
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
for tool in go dbus-daemon /usr/bin/gnome-keyring-daemon; do
  command -v "$tool" >/dev/null || { echo 'Missing official CI tool dependency.' >&2; exit 2; }
done
go version >/dev/null
unset DBUS_SESSION_BUS_ADDRESS DBUS_SYSTEM_BUS_ADDRESS DBUS_STARTER_ADDRESS DBUS_STARTER_BUS_TYPE GNOME_KEYRING_CONTROL GNOME_KEYRING_PID SSH_AUTH_SOCK
export MERIDIAN_CREDENTIAL_WIRE_TESTS=1
reports=reports/credential-gnome
mkdir -p "$reports"
go version > "$reports/go-version.txt"
dbus-daemon --version > "$reports/dbus-version.txt"
# --version exits immediately; no service or keyring operation is requested.
/usr/bin/gnome-keyring-daemon --version > "$reports/gnome-version.txt"
go test -count=1 -timeout=120s -tags 'credentialintegration credentialgnome' \
  -run '^TestCredentialGNOME' -json ./internal/credentialstore \
  | tee "$reports/tests.jsonl"
