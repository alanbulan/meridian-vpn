#!/bin/sh
# Runs only inside a disposable CI container; never on a user's host.
set -eu
[ "${MERIDIAN_DISPOSABLE_INSTALL_TEST:-}" = 1 ]
[ -f /.dockerenv ]
[ "$(id -u)" = 0 ]
export DEBIAN_FRONTEND=noninteractive
export LANG=C.UTF-8 LC_ALL=C.UTF-8
# Prevent dependency packages starting services in this disposable environment.
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
# Slim base images exclude documentation. Retain this package's own files so
# installation integrity/source checks exercise the complete desktop package.
printf 'path-include=/usr/share/doc/meridian\npath-include=/usr/share/doc/meridian/*\n' > /etc/dpkg/dpkg.cfg.d/zz-meridian-test-docs
apt-get update
apt-get install -y --no-install-recommends /input/meridian_0.1.0~alpha.1-1_amd64.deb xvfb xauth xdotool openbox x11-utils dbus-x11 desktop-file-utils fonts-dejavu-core
dpkg-query -W -f='${Package} ${Version}\n' libc6 libopenconnect5 libgtk-3-0t64 2>/dev/null || true
[ "$(dpkg-query -W -f='${Version}' meridian)" = '0.1.0~alpha.1-1' ]
[ "$(readlink -f /usr/bin/meridian)" = /usr/lib/meridian/meridian ]
[ "$(stat -c '%U:%G:%a' /usr/lib/meridian/meridian-auth-helper)" = 'root:root:755' ]
[ -z "$(find /usr/lib/meridian -perm /6000 -print)" ]
for script in preinst postinst prerm postrm; do [ ! -e "/var/lib/dpkg/info/meridian.$script" ]; done
[ ! -e /etc/xdg/autostart/meridian.desktop ]
[ ! -e /lib/systemd/system/meridian.service ]
sha256sum -c /usr/share/doc/meridian/SHA256SUMS-installed
desktop-file-validate /usr/share/applications/meridian.desktop
useradd --create-home --shell /bin/sh meridian-test
runuser -u meridian-test -- meridian --version | grep -Fx 'Meridian 0.1.0-alpha.1 (8e0aaa94034e44150345733dc482126a03469d9a)'
runuser -u meridian-test -- meridianctl version | grep -Fx 'Meridian CLI 0.1.0-alpha.1'
runuser -u meridian-test -- /usr/lib/meridian/meridian-auth-helper --protocol-version | grep -Fx 'meridian-auth-helper/1'
# No profile or gateway is configured. Verify a real visible X11 window, then
# close the unconnected application; never click Connect or invoke networking.
runuser -u meridian-test -- dbus-run-session -- xvfb-run -a sh -eu <<'GUI'
  openbox > /tmp/meridian-wm.log 2>&1 &
  sleep 1
  meridian > /tmp/meridian-gui.log 2>&1 &
  pid=$!
  trap "kill -TERM $pid 2>/dev/null || true" EXIT
  for n in $(seq 1 30); do
    kill -0 "$pid"
    window=$(xdotool search --onlyvisible --all --pid "$pid" --class "^Meridian$" 2>/dev/null | head -n 1 || true)
    if [ -n "$window" ] && xdotool getwindowgeometry --shell "$window" | awk -F= '/^WIDTH=/{w=$2} /^HEIGHT=/{h=$2} END{exit !(w>=800 && h>=500)}'; then
      xdotool getwindowname "$window"
      xdotool getwindowgeometry --shell "$window"
      kill -TERM "$pid"
      wait "$pid" || true
      exit 0
    fi
    sleep 1
  done
  xwininfo -root -tree || true
  kill -QUIT "$pid" || true
  sleep 1
  cat /tmp/meridian-wm.log
  cat /tmp/meridian-gui.log
  exit 1
GUI
mkdir -p /home/meridian-test/.config/meridian
printf 'preserve user data\n' > /home/meridian-test/.config/meridian/install-test-sentinel
apt-get purge -y meridian
[ ! -e /usr/bin/meridian ]
[ ! -e /usr/bin/meridianctl ]
[ ! -e /usr/lib/meridian ]
[ ! -e /usr/share/applications/meridian.desktop ]
[ ! -e /usr/share/icons/hicolor/scalable/apps/meridian.svg ]
[ -f /home/meridian-test/.config/meridian/install-test-sentinel ]
printf 'PASS: real package install, non-root visible window, helper runtime, purge, user-data preservation; no live VPN acceptance.\n'
