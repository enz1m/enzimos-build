#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# REVIEW payload (human review, not a qualification): replaces the greeter with the enzimOS
# Installer kiosk in --demo mode (simulated installation; no disk is written) so the UI can
# be judged over VNC. Restarting from the finished page relaunches it.
set -uo pipefail
here=$(dirname "$0")
if [[ -f $here/enzimos-installer ]]; then
    install -m0755 "$here/enzimos-installer" /usr/bin/enzimos-installer
    cp -r "$here/data/usr/." /usr/ && chmod 0755 /usr/lib/enzimos-installer-ui/installer-session
    printf 'ENZIMOS_REVIEW_UI_BUILD %s\n' "$(sha256sum /usr/bin/enzimos-installer | cut -c1-16)"
fi
cat > /etc/greetd/config.toml <<'CONF'
# REVIEW VM: the enzimOS Installer preview instead of the greeter.
[terminal]
vt = 1

[default_session]
command = "env XDG_STATE_HOME=/var/cache/enzui-greeter ENZIMOS_INSTALLER_ARGS=--demo /usr/lib/enzimos-installer-ui/installer-session"
user = "greeter"
CONF
systemctl restart greetd
for _ in $(seq 240); do
    if pgrep -u greeter -x enzimos-installe >/dev/null || pgrep -u greeter -f /usr/bin/enzimos-installer >/dev/null; then
        sleep 5; printf '\nENZIMOS_REVIEW_UI_UP\n'; break
    fi
    sleep 1
done
pgrep -f /usr/bin/enzimos-installer >/dev/null || { printf 'ENZIMOS_REVIEW_UI_MISSING\n'; tail -40 /var/cache/enzui-greeter/enzimos-installer/compositor.log 2>/dev/null; journalctl -b --no-pager -u greetd | tail -20; }
sleep infinity
