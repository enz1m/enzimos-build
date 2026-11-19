#!/usr/bin/bash
# Disposable VM: check bounded DRM coldplug ordering before graphical disk unlock.
set -eu
rm -f /usr/lib/systemd/system/plymouth-start.service.d/25-enzimos-coldplug.conf
mkinitcpio -P
systemctl stop enzimos-boot-menu.path enzimos-boot-menu.service
sed -i '/^[[:space:]]*cmdline:/s/$/ plymouth.debug/' /boot/limine/limine.conf
cat /boot/limine/limine.conf
printf '\nENZIMOS_FIRSTBOOT_FIRMWARE %s\n' "$([[ -d /sys/firmware/efi ]] && echo uefi || echo bios)"
printf 'ENZIMOS_DISPLAY_PREPARE_PASS\n'
sync
systemctl --no-block poweroff
