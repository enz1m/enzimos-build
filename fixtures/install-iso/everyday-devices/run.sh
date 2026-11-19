#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Explicit disposable installed-guest acceptance, never a default service.
set -u
python -B /run/enzimos-testpayload/check.py
status=$?
if (( status != 0 )); then
    printf 'ENZIMOS_EVERYDAY_FAIL status=%s\n' "$status"
    journalctl -b -u cups.service -u avahi-daemon.service --no-pager -n 20
fi
sync
systemctl --no-block poweroff
exit "$status"
