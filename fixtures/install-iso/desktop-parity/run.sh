#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# TEST ONLY: disposable installed guest, public fixture account; powers off.
set -uo pipefail
python -B /run/enzimos-testpayload/prepare_usb.py || exit 1
python -B /run/enzimos-testpayload/check.py; status=$?
if (( status != 0 )); then
    runuser -u admin -- env XDG_RUNTIME_DIR=/run/user/1000 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus journalctl --user --no-pager -n40 -u enzimos-activity.service
    printf "ENZIMOS_PARITY_DIAGNOSTIC_HOLD\n"
    for (( n=0; n<900; n++ )); do [[ -f /home/admin/parity-diagnostic-done ]] && break; sleep 1; done
fi
(( status == 0 )) || printf '\nENZIMOS_DESKTOP_PARITY_FAILURE status=%s\n' "$status"
for file in /home/admin/.local/state/enzui/{shell,desktop-start}.log; do
    [[ -f $file ]] && tail -30 "$file" | sed "s|^|ENZIMOS_PARITY_SESSION_LOG |"
done
systemctl --no-block poweroff
