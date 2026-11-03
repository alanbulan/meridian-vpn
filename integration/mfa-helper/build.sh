#!/bin/sh
# Builds only an unprivileged auth helper. Never installs packages or services.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CC=${CC:-cc}
out=${1:-"$here/../../build/meridian-auth-helper"}
mkdir -p "$(dirname -- "$out")"
if [ -n "${OPENCONNECT_STAGE:-}" ]; then
  lib="$OPENCONNECT_STAGE/usr/lib/x86_64-linux-gnu"
  "$CC" -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -I"$OPENCONNECT_STAGE/usr/include" "$here/main.c" -L"$lib" -Wl,-rpath-link,"$lib" \
    -Wl,-z,relro,-z,now -lopenconnect -o "$out"
else
  pkg-config --atleast-version=9.12 openconnect
  "$CC" -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    $(pkg-config --cflags openconnect) "$here/main.c" -Wl,-z,relro,-z,now \
    $(pkg-config --libs openconnect) -o "$out"
fi
printf 'Built authentication-only helper: %s\n' "$out"
