#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# TEST payload: a real enzimOS generation update on a freshly installed system.
set -uo pipefail
python -B /run/enzimos-testpayload/update.py; status=$?
(( status == 0 )) || printf '\nENZIMOS_UPDATE_FAILURE status=%s\n' "$status"
# shellcheck disable=SC2015  # a failed reboot request falls back to poweroff
[[ -f /run/enzimos-test-reboot ]] && systemctl --no-block reboot || systemctl --no-block poweroff
