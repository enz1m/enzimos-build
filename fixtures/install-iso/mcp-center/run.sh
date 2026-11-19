#!/usr/bin/bash
set -uo pipefail
python -B /run/enzimos-testpayload/check.py; status=$?
(( status == 0 )) || printf '\nENZIMOS_MCP_CENTER_FAILURE status=%s\n' "$status"
systemctl --no-block poweroff
