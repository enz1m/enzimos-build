#!/bin/bash
set -euo pipefail
exec >/dev/ttyS0 2>&1
sleep 5
if [[ -f /run/enzimos-recovery-console ]]; then
    if systemctl is-active --quiet greetd; then printf 'ENZIMOS_CONSOLE_FAIL unexpected graphical/console service\n'; exit 1; fi
    if pgrep -x enz-hyprland || pgrep -x Hyprland; then printf 'ENZIMOS_CONSOLE_FAIL unexpected graphical/console service\n'; exit 1; fi
    if pgrep -x plymouthd; then printf 'ENZIMOS_CONSOLE_FAIL unexpected graphical/console service\n'; exit 1; fi
    systemctl is-active --quiet enzimos-recovery-console
    if journalctl -b -u plymouth-start --no-pager | grep 'Started Show Plymouth' >/dev/null; then printf 'ENZIMOS_CONSOLE_FAIL graphical splash started\n'; exit 1; fi
    printf 'ENZIMOS_CONSOLE_OK no-graphical-services\n'
    /usr/bin/enzimos-recovery-cli list
    /usr/bin/enzimos-recovery-cli status
    printf 'ENZIMOS_CONSOLE_OK cli-adapter\n'
else
    systemctl is-active --quiet greetd
    if systemctl is-active --quiet enzimos-recovery-console; then printf 'ENZIMOS_CONSOLE_FAIL unexpected graphical/console service\n'; exit 1; fi
    printf 'ENZIMOS_CONSOLE_OK normal-graphical-services\n'
fi
systemctl --failed --no-legend
printf 'ENZIMOS_CONSOLE_OK boot-check-complete\n'
