#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -u
python -B /run/enzimos-testpayload/check.py
status=$?
if (( status != 0 )); then printf 'ENZIMOS_GAMING_FAIL status=%s\n' "$status"; fi
sync
systemctl --no-block poweroff
exit "$status"
