#!/usr/bin/env bash
# Dedicated fresh container only. Root supervises two unprivileged fixture UIDs.
set -euo pipefail
umask 077
if [[ "${GITHUB_ACTIONS:-}" != true || "${MERIDIAN_CROSS_UID_TESTS:-}" != 1 || ! -f /.dockerenv || "$(id -u)" != 0 || $# != 2 ]]; then
  echo 'Requires an explicitly opted-in disposable GitHub container, root and two fixture usernames.' >&2; exit 2
fi
uid_a="$(id -u -- "$1")"; gid_a="$(id -g -- "$1")"
uid_b="$(id -u -- "$2")"; gid_b="$(id -g -- "$2")"
for value in "$uid_a" "$gid_a" "$uid_b" "$gid_b"; do
  if [[ ! "$value" =~ ^[0-9]+$ || "$value" == 0 ]]; then echo 'Fixture identities must be non-root.' >&2; exit 2; fi
done
if [[ "$uid_a" == "$uid_b" || "$gid_a" == "$gid_b" ]]; then echo 'Use distinct fixture users and primary groups.' >&2; exit 2; fi
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
ancestor="$root"
while :; do
  if [[ -L "$ancestor" || ! -d "$ancestor" || "$(stat -c %u "$ancestor")" != 0 || -n "$(find "$ancestor" -maxdepth 0 -perm /022 -print)" ]]; then
    echo 'Root checkout path must not be replaceable by fixture users.' >&2; exit 2
  fi
  [[ "$ancestor" == / ]] && break
  ancestor="$(dirname -- "$ancestor")"
done
# CI must supply a fresh root-owned checkout before invoking this root script.
# Do not repair an untrusted checkout in place or execute fixture-writable code.
if [[ -n "$(find . -path './.git' -prune -o \( -type l -o \( -type d \( ! -uid 0 -o -perm /022 \) \) -o \( -type f \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' \) \( ! -uid 0 -o -perm /022 \) \) \) -print -quit)" ]]; then
  echo 'Test sources must be root-owned, non-writable by fixtures and without symlinks.' >&2; exit 2
fi
for tool in go /usr/bin/dbus-daemon; do command -v "$tool" >/dev/null || { echo 'Official Go and D-Bus packages are required.' >&2; exit 2; }; done
go_dir="$(dirname -- "$(command -v go)")"
if [[ -L /run || ! -d /run || "$(stat -c '%u:%a' /run)" != '0:755' ]]; then echo 'Unexpected runtime parent.' >&2; exit 2; fi
if [[ ! -e /run/user && ! -L /run/user ]]; then mkdir -m 0755 /run/user; fi
if [[ -L /run/user || ! -d /run/user || "$(stat -c '%u:%a' /run/user)" != '0:755' ]]; then echo 'Unexpected runtime user parent.' >&2; exit 2; fi
for uid in "$uid_a" "$uid_b"; do
  if [[ -e "/run/user/$uid" || -L "/run/user/$uid" ]]; then echo 'Existing fixture runtime is forbidden; leave it untouched.' >&2; exit 2; fi
done
# /run and this fresh directory are root-owned. Fixture users can execute the
# binary but cannot alter it or replace any parent path.
build="$(mktemp -d /run/meridian-crossuid-build-XXXXXX)"
build_inode="$(stat -c '%d:%i' "$build")"
cleanup(){
  status=$?
  if [[ ! -L "$build" && -d "$build" && "$(stat -c '%d:%i' "$build")" == "$build_inode" ]]; then
    rm -rf -- "$build" # Only this root-created build/cache tree, never /run/user.
  else echo 'Build tree changed; refusing cleanup.' >&2; status=1; fi
  exit "$status"
}
trap cleanup EXIT
chmod 0755 "$build"
mkdir -m 0700 "$build/home" "$build/cache" "$build/modules"
env -i PATH="$go_dir:/usr/bin:/bin" HOME="$build/home" GOCACHE="$build/cache" GOPATH="$build/modules" GOTOOLCHAIN=local \
  go test -c -tags 'credentialintegration credentialcrossuid' -o "$build/credential-crossuid.test" ./internal/credentialstore
chmod 0555 "$build/credential-crossuid.test"
env -i PATH=/usr/bin:/bin HOME="$build/home" LANG=C.UTF-8 \
  GITHUB_ACTIONS=true MERIDIAN_CROSS_UID_TESTS=1 MERIDIAN_CROSS_UID_ROLE=supervisor \
  MERIDIAN_A_UID="$uid_a" MERIDIAN_A_GID="$gid_a" MERIDIAN_B_UID="$uid_b" MERIDIAN_B_GID="$gid_b" \
  "$build/credential-crossuid.test" -test.timeout=120s -test.v -test.run='^TestCredentialCrossUIDSupervisor$'
