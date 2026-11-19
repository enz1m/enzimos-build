#!/bin/bash
# Explicit disposable alongside fixture: prove preservation, then real desktop login.
set -euo pipefail
[[ -b /dev/vda5 ]]
python3 /run/enzimos-testpayload/check-alongside.py
wait_for() {
    for _ in $(seq 90); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
    printf 'ENZIMOS_DESKTOP_TIMEOUT alongside-login\n'
    return 1
}
wait_for pgrep -u greeter -f /usr/share/enzui/bin/enzui-greeter
printf 'ENZIMOS_DESKTOP_GREETER_UP\n'
wait_for pgrep -u admin -f /usr/share/enzui/bin/enzui-shell
printf 'ENZIMOS_DESKTOP_SESSION_UP\n'
sleep 45
printf 'ENZIMOS_ALONGSIDE_DESKTOP_PASS\n'
systemctl --no-block poweroff
