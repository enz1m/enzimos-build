#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# TEST payload: installed local backup without Settings (scratch disk serial enzimos-fixture).
# The scenario file selects "initialize" (default) or "adopt"; see backup_check.py.
set -uo pipefail
payload=/run/enzimos-testpayload
scenario=$(cat "$payload/scenario" 2>/dev/null || printf initialize)
printf 'ENZIMOS_BACKUP_PAYLOAD_START %s\n' "$scenario"
/usr/bin/python -I -B "$payload/backup_check.py" "$scenario"
status=$?
if (( status == 0 )); then
    printf '\nENZIMOS_BACKUP_PAYLOAD_PASS %s\n' "$scenario"
else
    printf '\nENZIMOS_BACKUP_PAYLOAD_FAILURE %s\n' "$scenario"
fi
systemctl --no-block poweroff
