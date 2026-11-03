#!/bin/sh
# Extracts pinned official Debian packages into a private directory. Never installs
# packages, starts services, creates interfaces, or changes host configuration.
set -eu
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || { echo 'This fixture staging script supports Linux amd64 only.' >&2; exit 1; }
if [ "$#" -ne 1 ]; then echo "Usage: $0 /absolute/workspace/staging-directory" >&2; exit 1; fi
case "$1" in /*) ;; *) echo 'Destination must be absolute.' >&2; exit 1;; esac
stage=$1
manifest=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/debian-packages.sha256-urls
mkdir -p "$stage/packages" "$stage/root"
while read -r checksum url; do
 file=${url##*/}
 curl --fail --location --proto '=https' --tlsv1.2 "$url" -o "$stage/packages/$file"
 printf '%s  %s\n' "$checksum" "$stage/packages/$file" | sha256sum -c -
 dpkg-deb -x "$stage/packages/$file" "$stage/root"
done < "$manifest"
LD_LIBRARY_PATH="$stage/root/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$stage/root/usr/sbin/openconnect" --version
printf '\nAuthentication-only test environment:\n'
printf 'MERIDIAN_OPENCONNECT_TEST_BINARY=%s/root/usr/sbin/openconnect\nLD_LIBRARY_PATH=%s/root/usr/lib/x86_64-linux-gnu\n' "$stage" "$stage"
