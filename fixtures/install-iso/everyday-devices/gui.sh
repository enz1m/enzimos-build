#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Explicit native/manual gate; never installed as a production service.
set -u
python -B /run/enzimos-testpayload/gui_check.py
status=$?
if (( status != 0 )); then
    printf 'ENZIMOS_EVERYDAY_GUI_FAIL status=%s\n' "$status"
    journalctl -b -u cups.service -u cups-pk-helper.service --no-pager -n 20
fi
sync
systemctl --no-block poweroff
exit "$status"
