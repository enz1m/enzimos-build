#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# TEST payload: the Settings backend API on a fresh install, as the Settings app would use it.
# The admin runs the client in a real local login session (tty2) with a polkit text agent.
set -uo pipefail
payload=/run/enzimos-testpayload
printf 'ENZIMOS_SETTINGS_BACKEND_BEFORE %s\n' "$(systemctl is-active enzimos-system-backend.service)"
# A test network profile (never activated) for the trust controls.
nmcli connection add type ethernet con-name enzimos-test-lan ifname enzimos-test0 autoconnect no >/dev/null
nmcli -g connection.uuid connection show enzimos-test-lan > /run/enzimos-test-lan.uuid
chmod 644 /run/enzimos-test-lan.uuid
install -m0644 "$payload/settings_client.py" /run/settings_client.py
# An ordinary user outside any session: status must be refused (not active and local).
useradd -m enzimos-other 2>/dev/null
runuser -u enzimos-other -- python -I -B /run/settings_client.py denied > /run/settings-denied.log 2>&1
cat /run/settings-denied.log
systemctl mask --runtime --now getty@tty2.service autovt@tty2.service >/dev/null 2>&1; chvt 2
systemd-run --quiet --wait --collect --unit=enzimos-settings-client --uid=admin --property=PAMName=login --property=TTYPath=/dev/tty2 \
    --property=StandardInput=tty-force --property=StandardOutput=append:/run/settings-client.log --property=StandardError=append:/run/settings-client.log \
    --setenv=XDG_SESSION_TYPE=tty --setenv=XDG_SESSION_CLASS=user /usr/bin/python -I -B /run/settings_client.py admin
status=$?
cat /run/settings-client.log
printf 'ENZIMOS_SETTINGS_TIMER %s\n' "$(systemctl is-enabled enzimos-home-history.timer)"
printf 'ENZIMOS_SETTINGS_ZONE %s\n' "$(nmcli -g connection.zone connection show enzimos-test-lan)"
if (( status == 0 )) && grep -q '^ENZIMOS_SETTINGS_CLIENT_PASS' /run/settings-client.log && grep -q '^ENZIMOS_SETTINGS_DENIED_PASS' /run/settings-denied.log; then
    printf '\nENZIMOS_SETTINGS_PASS\n'
else
    journalctl -b --no-pager -u enzimos-system-backend -n 40 | sed 's/^/ENZIMOS_SETTINGS_JOURNAL /'
    printf '\nENZIMOS_SETTINGS_FAILURE\n'
fi
systemctl --no-block poweroff
