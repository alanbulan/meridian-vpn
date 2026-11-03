#!/usr/bin/env bash
# Root bootstrap ONLY in a fresh disposable GitHub container. All test/service
# processes run as an already-provisioned non-root fixture user.
set -euo pipefail
umask 077
if [[ "${GITHUB_ACTIONS:-}" != true || "${MERIDIAN_PRODUCTION_CONTAINER_TESTS:-}" != 1 || ! -f /.dockerenv || "$(id -u)" != 0 || $# != 1 ]]; then
  echo 'Requires explicit opt-in, a fresh disposable GitHub container, root bootstrap and one fixture username.' >&2
  exit 2
fi
user="$1"
uid="$(id -u -- "$user")"
gid="$(id -g -- "$user")"
if [[ ! "$uid" =~ ^[0-9]+$ || "$uid" == 0 ]]; then
  echo 'A dedicated existing non-root fixture user is required.' >&2
  exit 2
fi
for tool in runuser go dbus-daemon /usr/bin/gnome-keyring-daemon; do
  command -v "$tool" >/dev/null || { echo 'Missing official CI tool dependency.' >&2; exit 2; }
done
go_dir="$(dirname -- "$(command -v go)")"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
# Reject symlinks and unexpected writable parents before creating anything.
if [[ -L /run || ! -d /run || "$(stat -c '%u:%a' /run)" != '0:755' ]]; then
  echo 'Unexpected container runtime parent.' >&2; exit 2
fi
if [[ ! -e /run/user && ! -L /run/user ]]; then mkdir -m 0755 /run/user; fi
if [[ -L /run/user || ! -d /run/user || "$(stat -c '%u:%a' /run/user)" != '0:755' ]]; then
  echo 'Unexpected container runtime user parent.' >&2; exit 2
fi
runtime="/run/user/$uid"
if [[ -e "$runtime" || -L "$runtime" ]]; then
  echo 'Fixture runtime already exists; refusing to inspect, replace or delete it.' >&2
  exit 2
fi
# mkdir must create a new directory, never reuse or chmod a preexisting session.
mkdir -m 0700 -- "$runtime"
created_inode="$(stat -c '%d:%i' "$runtime")"
cleanup() {
  status=$?
  # No recursive cleanup or unlink fallback. Abnormal leftovers stay inside the
  # disposable container; changing identity also prevents this cleanup entirely.
  if [[ ! -L "$runtime" && -d "$runtime" && "$(stat -c '%d:%i' "$runtime")" == "$created_inode" ]]; then
    if ! rmdir -- "$runtime"; then echo 'Fixture runtime is not empty; container disposal must clean it.' >&2; status=1; fi
  else
    echo 'Fixture runtime identity changed; refusing cleanup.' >&2; status=1
  fi
  exit "$status"
}
trap cleanup EXIT
chown -- "$uid:$gid" "$runtime"
unset DBUS_SESSION_BUS_ADDRESS DBUS_SYSTEM_BUS_ADDRESS DBUS_STARTER_ADDRESS DBUS_STARTER_BUS_TYPE GNOME_KEYRING_CONTROL GNOME_KEYRING_PID SSH_AUTH_SOCK
# The checkout, toolchain and this user's cache must be provisioned by the CI job.
# env -i avoids carrying host/session selectors or credentials into the test.
runuser -u "$user" -- env -i \
  PATH="$go_dir:/usr/bin:/bin" HOME="$(getent passwd "$uid" | cut -d: -f6)" LANG=C.UTF-8 GOTOOLCHAIN=local \
  GITHUB_ACTIONS=true MERIDIAN_GNOME_CONTAINER_TESTS=1 MERIDIAN_CREDENTIAL_WIRE_TESTS=1 \
  MERIDIAN_PRODUCTION_CONTAINER_TESTS=1 MERIDIAN_FIXTURE_UID="$uid" \
  go test -count=1 -timeout=120s -tags 'credentialintegration credentialgnome credentialproduction' \
  -run '^TestCredentialProductionEntry$' -json ./internal/credentialstore
