#!/usr/bin/bash
# Disposable VM only: collect the actual initramfs Plymouth trace after unlock.
set -eu
printf '\nENZIMOS_PLYMOUTH_TRACE_BEGIN\n'
cat /proc/cmdline
find /run /var/log -maxdepth 2 -iname '*plymouth*' -ls
[[ -f /var/log/plymouth-debug.log || -f /run/plymouth-debug.log ]]
for log in /run/plymouth-debug.log /var/log/plymouth-debug.log; do [[ ! -f $log ]] || tail -c 200000 "$log"; done
journalctl -b --no-pager -u plymouth-start.service -u systemd-udev-trigger.service -u systemd-udevd.service
printf '\nENZIMOS_FIRSTBOOT_FIRMWARE %s\n' "$([[ -d /sys/firmware/efi ]] && echo uefi || echo bios)"
printf 'ENZIMOS_DISPLAY_TRACE_PASS\n'
sync
systemctl --no-block poweroff
