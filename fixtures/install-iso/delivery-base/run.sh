#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -uo pipefail
python -B /run/enzimos-testpayload/check.py; status=$?
(( status == 0 )) || printf '\nENZIMOS_DELIVERY_BASE_FAILURE status=%s\n' "$status"
systemctl --no-block poweroff
