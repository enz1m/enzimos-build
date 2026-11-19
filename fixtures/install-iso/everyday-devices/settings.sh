#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Manual native Settings acceptance in an explicit disposable installed guest.
set -u
python -B /run/enzimos-testpayload/settings_check.py
status=$?
if (( status != 0 )); then
    printf 'ENZIMOS_PRINTER_SETTINGS_NATIVE_FAIL status=%s\n' "$status"
fi
sync
systemctl --no-block poweroff
exit "$status"
