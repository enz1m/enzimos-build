#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Configure only a fresh private COPY of the pinned encrypted lab disk.
set -euo pipefail
export PATH=/usr/bin LC_ALL=C SYSTEMD_OFFLINE=1
exec > /dev/console 2>&1
trap 'printf "\nENZIMOS_UPDATE_FAILURE setup-line=%s\n" "$LINENO"' ERR
case " $(cat /proc/cmdline) " in
    *' enzimos.scenario=success '*) scenario=success ;;
    *' enzimos.scenario=interrupt '*) scenario=interrupt ;;
    *) exit 1 ;;
esac
udevadm settle --timeout=30
crypt=/dev/disk/by-id/virtio-enzimos-lab-target-part3
esp=/dev/disk/by-id/virtio-enzimos-lab-target-part2
payload=/dev/disk/by-id/virtio-enzimos-lab-payload
[[ -b $crypt && -b $esp && $(blockdev --getro "$payload") == 1 ]]
cryptsetup isLuks --type luks2 "$crypt"
mkdir -p /payload /mnt /target
mount -t iso9660 -o ro,nodev,nosuid,noexec "$payload" /payload
(cd /payload && sha256sum --strict -c SHA256SUMS)
cryptsetup open --key-file /payload/fixture-primary "$crypt" lab-root-crypt
mount -t btrfs -o subvolid=5 /dev/mapper/lab-root-crypt /mnt
[[ -f /mnt/lab-restored/usr/lib/systemd/systemd && ! -e /mnt/upd-live && ! -e /mnt/upd-authority ]]
btrfs subvolume snapshot /mnt/lab-restored /mnt/upd-live
btrfs subvolume create /mnt/upd-authority
cp -a /payload/public-keys/. /mnt/upd-authority/
chmod 700 /mnt/upd-authority
mount -t btrfs -o subvol=upd-live /dev/mapper/lab-root-crypt /target
mount -t vfat "$esp" /target/boot
mkdir -p /target/var/lib/enzimos-update-lab /target/usr/lib/enzimos-update-lab
cp /payload/root.sh /target/usr/lib/enzimos-lab/root-smoke.sh
cp /payload/common.sh /target/usr/lib/enzimos-update-lab/common.sh
cp /payload/old-packages.txt /payload/new-packages.txt /payload/kernels.env /payload/authority.sha256 /target/var/lib/enzimos-update-lab/
printf '%s\n' "$scenario" > /target/var/lib/enzimos-update-lab/scenario
printf 'update\n' > /target/var/lib/enzimos-update-lab/state
cp /payload/pacman.conf /target/etc/pacman-update-lab.conf
sed -i 's/subvol=lab-restored/subvol=upd-live/g' /target/etc/fstab
root_uuid=$(blkid -s UUID -o value /dev/mapper/lab-root-crypt)
printf 'UUID=%s /etc/pacman.d/gnupg btrfs subvol=upd-authority 0 0\n' "$root_uuid" >> /target/etc/fstab
mkdir -p /target/boot/generations/old /target/boot/enzimos-update-recovery
cp /target/boot/vmlinuz-linux /target/boot/vmlinuz-linux-lts /target/boot/initramfs-linux.img /target/boot/initramfs-linux-lts.img /target/boot/generations/old/
cp /payload/recovery.img /target/boot/enzimos-update-recovery/initrd.img
cp /payload/recovery.kernel /target/boot/enzimos-update-recovery/kernel
(cd /target/boot && sha256sum generations/old/* enzimos-update-recovery/*) > /target/var/lib/enzimos-update-lab/retained.sha256
for flavor in linux linux-lts; do
    sed -i 's/subvol=lab-restored/subvol=upd-live/g' "/target/boot/loader/entries/$flavor.conf"
done
sed -i 's/subvol=lab-restored/subvol=upd-live/g;s@enzimos-recovery/@enzimos-update-recovery/@g' /target/boot/limine/limine.conf
sed -i 's@enzimos-recovery/@enzimos-update-recovery/@g' /target/boot/loader/entries/recovery.conf
printf 'default linux.conf\ntimeout 0\neditor no\n' > /target/boot/loader/loader.conf
sed -i 's/^default_entry: .*/default_entry: 1/' /target/boot/limine/limine.conf
# No header is restored. Hash a temporary backup to compare the complete header area later.
cryptsetup luksHeaderBackup "$crypt" --header-backup-file /run/lab-header.backup
sha256sum /run/lab-header.backup | cut -d' ' -f1 > /target/var/lib/enzimos-update-lab/header.sha256
rm /run/lab-header.backup
# The running-system transaction can take longer than the earlier diagnostic unit.
mkdir -p /target/etc/systemd/system/enzimos-root-smoke.service.d
printf '[Service]\nTimeoutStartSec=25min\n' > /target/etc/systemd/system/enzimos-root-smoke.service.d/timeout.conf
sync
printf '\nENZIMOS_UPDATE_SETUP_PASS scenario=%s\n' "$scenario"
unset SYSTEMD_OFFLINE
systemctl --no-block poweroff
