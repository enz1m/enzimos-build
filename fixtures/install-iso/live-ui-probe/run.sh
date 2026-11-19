#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# DIAGNOSTIC payload: run the live medium's graphical-installer unit (root kiosk on tty1)
# on an installed system and copy its journal to the serial console. Demo mode only.
set -uo pipefail
here=$(dirname "$0")
if [[ -f $here/enzimos-installer ]]; then
    install -m0755 "$here/enzimos-installer" /usr/bin/enzimos-installer
    cp -r "$here/data/usr/." /usr/ && chmod 0755 /usr/lib/enzimos-installer-ui/installer-session
fi
systemctl stop greetd
id enzimos-live >/dev/null 2>&1 || useradd -r -m -d /var/lib/enzimos-live -s /usr/bin/nologin enzimos-live
sed 's|^Environment=XDG_SESSION_TYPE=wayland XDG_SESSION_CLASS=user|&\nEnvironment=ENZIMOS_INSTALLER_ARGS=--demo|; /^OnFailure=/d' "$here/enzimos-installer-ui.service" > /run/systemd/system/enzimos-installer-ui.service
systemctl daemon-reload
systemctl start enzimos-installer-ui.service
sleep 45
printf '\nENZIMOS_REVIEW_UI_UP\n'
systemctl status --no-pager enzimos-installer-ui.service | sed 's/^/ENZIMOS_PROBE_STATUS /'
journalctl -b --no-pager -u enzimos-installer-ui.service | tail -80 | sed 's/^/ENZIMOS_PROBE_LOG /'
sleep infinity
