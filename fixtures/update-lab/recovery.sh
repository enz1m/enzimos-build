#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Independent RAM userspace restores only a named interrupted guest transaction.
set -euo pipefail
export PATH=/usr/bin LC_ALL=C
exec > /dev/console 2>&1
trap 'printf "\nENZIMOS_UPDATE_FAILURE recovery-line=%s\n" "$LINENO"' ERR
[[ $(cat /proc/1/comm) == systemd && ! -e /dev/mapper/lab-root-crypt ]]
printf '\nENZIMOS_UPDATE_RECOVERY_RAM_STARTED root-locked\n'
udevadm settle --timeout=30
password=$(systemd-ask-password --no-tty --timeout=120 'ENZIMOS recovery passphrase:')
crypt=/dev/disk/by-id/virtio-enzimos-lab-target-part3
printf '%s' "$password" | cryptsetup open --key-file - "$crypt" lab-root-crypt
unset password
mkdir -p /mnt /boot
mount -t btrfs -o subvolid=5 /dev/mapper/lab-root-crypt /mnt
mount -t vfat /dev/disk/by-id/virtio-enzimos-lab-target-part2 /boot
[[ -d /mnt/upd-pre && -d /mnt/upd-live && ! -e /mnt/upd-recovered ]]
[[ -f /mnt/upd-live/var/lib/pacman/db.lck ]]
grep -q '\[ALPM\] upgraded linux (' /mnt/upd-live/var/log/pacman-update-lab.log
if grep -q '\[ALPM\] transaction completed' /mnt/upd-live/var/log/pacman-update-lab.log; then
    printf 'ENZIMOS_UPDATE_FAILURE transaction-was-complete\n'; exit 1
fi
cat /mnt/upd-live/var/log/pacman-update-lab.log
pacman --root /mnt/upd-live --config /mnt/upd-live/etc/pacman.conf -Q > /run/interrupted-packages.txt
cat /run/interrupted-packages.txt
# No interrupted-root executable is invoked; all tools are in this recovery initrd.
(cd /mnt/upd-authority && sha256sum --strict -c /mnt/upd-pre/var/lib/enzimos-update-lab/authority.sha256)
gpg --homedir /mnt/upd-authority --batch --no-autostart --export-ownertrust | grep -v '^#' | sort > /run/ownertrust.actual
sort /mnt/upd-authority/approved.trust > /run/ownertrust.expected
diff -u /run/ownertrust.expected /run/ownertrust.actual
cryptsetup luksHeaderBackup "$crypt" --header-backup-file /run/lab-header.backup
[[ $(sha256sum /run/lab-header.backup | cut -d' ' -f1) == "$(< /mnt/upd-pre/var/lib/enzimos-update-lab/header.sha256)" ]]
rm /run/lab-header.backup
btrfs subvolume snapshot /mnt/upd-pre /mnt/upd-recovered
sed -i 's/subvol=upd-live/subvol=upd-recovered/g' /mnt/upd-recovered/etc/fstab
for flavor in linux linux-lts; do
    cp "/boot/generations/old/vmlinuz-$flavor" "/boot/vmlinuz-$flavor"
    cp "/boot/generations/old/initramfs-$flavor.img" "/boot/initramfs-$flavor.img"
    cmp "/boot/generations/old/vmlinuz-$flavor" "/boot/vmlinuz-$flavor"
    cmp "/boot/generations/old/initramfs-$flavor.img" "/boot/initramfs-$flavor.img"
    sed -i 's/subvol=upd-live/subvol=upd-recovered/g' "/boot/loader/entries/$flavor.conf"
done
sed -i 's/subvol=upd-live/subvol=upd-recovered/g' /boot/limine/limine.conf
[[ $(< /mnt/lab-home/update-lab-marker) == home-created-after-update-snapshot ]]
state_dir=/mnt/upd-recovered/var/lib/enzimos-update-lab
pacman --root /mnt/upd-recovered --config /mnt/upd-recovered/etc/pacman.conf -Q | sort > /run/recovered-packages.txt
diff -u "$state_dir/old-packages.txt" /run/recovered-packages.txt
[[ ! -e /mnt/upd-recovered/var/lib/pacman/db.lck ]]
printf 'rollback\n' > "$state_dir/state"
printf 'default linux-lts.conf\ntimeout 0\neditor no\n' > /boot/loader/loader.conf
sed -i 's/^default_entry: .*/default_entry: 2/' /boot/limine/limine.conf
sync
printf '\nENZIMOS_UPDATE_RECOVERY_PASS interrupted-transaction old-root-and-boot current-authority newer-home header-bytes\n'
systemctl --no-block poweroff
