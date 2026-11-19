#!/usr/bin/bash
# Disposable VM: qualify periodic static repaint after renderer scanout changes.
set -eu
cp /run/enzimos-testpayload/enzimos.script /usr/share/plymouth/themes/enzimos/enzimos.script
rm -f /usr/lib/systemd/system/plymouth-start.service.d/25-enzimos-coldplug.conf
mkinitcpio -P
systemctl stop enzimos-boot-menu.path enzimos-boot-menu.service
sed -i 's/ plymouth.debug//g' /boot/limine/limine.conf
printf '\nENZIMOS_FIRSTBOOT_FIRMWARE %s\n' "$([[ -d /sys/firmware/efi ]] && echo uefi || echo bios)"
printf 'ENZIMOS_DISPLAY_PREPARE_PASS\n'
sync
systemctl --no-block poweroff
