#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# TEST payload: the enzUI desktop PREVIEW on a fresh install. Reports the greeter, waits for the
# harness to log in through it (keystrokes over QMP), then reports the user session and logs.
set -uo pipefail
wait_for() { local label=$1 limit=$2; shift 2; for _ in $(seq "$limit"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; printf 'ENZIMOS_DESKTOP_TIMEOUT %s\n' "$label"; return 1; }
report() { journalctl -b --no-pager -u greetd | tail -40 | sed 's/^/ENZIMOS_DESKTOP_JOURNAL /'; for f in /home/*/.local/state/enzui/*.log /var/log/greetd*.log; do [[ -f $f ]] && tail -40 "$f" | sed "s|^|ENZIMOS_DESKTOP_LOG ${f##*/} |"; done; }
printf 'ENZIMOS_DESKTOP_GREETD %s\n' "$(systemctl is-active greetd)"
if wait_for greeter 240 pgrep -u greeter -f /usr/share/enzui/bin/enzui-greeter; then
    printf '\nENZIMOS_DESKTOP_GREETER_UP\n'
else report; systemctl --no-block poweroff; exit 0; fi
if wait_for session 300 pgrep -u admin -f /usr/share/enzui/bin/enzui-shell; then
    printf '\nENZIMOS_DESKTOP_SESSION_UP\n'
    sleep 40
    # An offline-installed Flathub app (GTK/libadwaita) opened inside the enzUI session.
    signature=$(find /run/user/1000/hypr -mindepth 1 -maxdepth 1 -printf "%f\n" 2>/dev/null | head -1)
    runuser -u admin -- env XDG_RUNTIME_DIR=/run/user/1000 HYPRLAND_INSTANCE_SIGNATURE="$signature" \
        /usr/bin/hyprctl dispatch 'hl.dsp.exec_cmd("flatpak run org.gnome.Calculator")' | sed 's/^/ENZIMOS_DESKTOP_DISPATCH /'
    if wait_for flatpak-app 120 pgrep -u admin -f gnome-calculator; then sleep 20; printf '\nENZIMOS_DESKTOP_APP_UP\n'; sleep 30; fi
    printf 'ENZIMOS_DESKTOP_PROCESSES %s\n' "$(pgrep -u admin -a -f /usr/share/enzui | awk '{print $2}' | xargs -n1 basename | sort | tr '\n' ' ')"
    loginctl list-sessions --no-legend | sed 's/^/ENZIMOS_DESKTOP_SESSION /'
    report
    printf '\nENZIMOS_DESKTOP_PASS\n'
else report; fi
systemctl --no-block poweroff
