#!/bin/sh
# Private workspace extraction only: no system packages, scripts or services.
set -eu
[ "$#" -eq 1 ] || { echo "Usage: $0 /absolute/private/workspace/staging-directory" >&2; exit 1; }
case "$1" in /*) ;; *) echo 'Destination must be absolute.' >&2; exit 1;; esac
stage=$1
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
"$here/../authfixture/stage-debian-client.sh" "$stage"
file=libopenconnect-dev_9.12-3+deb13u2_amd64.deb
curl --fail --location --proto '=https' --tlsv1.2 "https://deb.debian.org/debian/pool/main/o/openconnect/$file" -o "$stage/packages/$file"
printf '%s  %s\n' c38741a011ce2840bf792c3727bfa14d0b661dc02f58f500af5f907641caafd8 "$stage/packages/$file" | sha256sum -c -
dpkg-deb -x "$stage/packages/$file" "$stage/root"
OPENCONNECT_STAGE="$stage/root" "$here/build.sh" "$stage/meridian-auth-helper"
LD_LIBRARY_PATH="$stage/root/usr/lib/x86_64-linux-gnu" "$stage/meridian-auth-helper" --protocol-version
printf '\nMERIDIAN_MFA_HELPER_TEST_BINARY=%s/meridian-auth-helper\nLD_LIBRARY_PATH=%s/root/usr/lib/x86_64-linux-gnu\n' "$stage" "$stage"
