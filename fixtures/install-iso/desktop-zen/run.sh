#!/usr/bin/bash
# Disposable installed desktop qualification; public fixture authentication only.
set -uo pipefail
python -B /run/enzimos-testpayload/check.py; status=$?
(( status == 0 )) || printf '\nENZIMOS_DESKTOP_ZEN_FAILURE status=%s\n' "$status"
for f in /home/admin/.local/state/enzui/{shell,desktop-start,wallpaper}.log /var/cache/enzui-greeter/greeter-session.log; do
    [[ -f $f ]] && tail -35 "$f" | sed "s|^|ENZIMOS_DESKTOP_LOG ${f##*/} |"
done
systemctl --no-block poweroff
