#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Fixed encrypted lab sequence; the fault below is confined to this disposable root.
set -euo pipefail
export PATH=/usr/bin LC_ALL=C
exec > /dev/console 2>&1
trap 'printf "\nENZIMOS_CRYPT_FAILURE line=%s\n" "$LINENO"' ERR
[[ $(cat /proc/1/comm) == systemd ]]
phase=$(< /var/lib/enzimos-lab/phase)
case "$phase" in
    0) flavor=linux; mode=uefi ;;
    1) flavor=linux-lts; mode=uefi ;;
    2) flavor=linux; mode=bios ;;
    3) flavor=linux-lts; mode=bios ;;
    6) flavor=linux; mode=uefi ;;
    7) flavor=linux-lts; mode=bios ;;
    *) exit 1 ;;
esac
[[ $(uname -r) == "$(< "/var/lib/enzimos-lab/uname-$flavor")" ]]
if [[ $mode == uefi ]]; then
    [[ -d /sys/firmware/efi ]]
    bootctl status --no-pager > /run/bootctl-status.txt
    cat /run/bootctl-status.txt
    grep -q 'Product: systemd-boot' /run/bootctl-status.txt
else
    [[ ! -d /sys/firmware/efi ]]
fi
cryptsetup status lab-root-crypt
cryptsetup status lab-root-crypt | grep -q 'type:.*LUKS2'
# Btrfs uses an anonymous superblock device number, not the mapper's MAJ:MIN.
mounted_source=$(findmnt -n -o SOURCE /)
mounted_source=${mounted_source%%\[*}
[[ $(readlink -f "$mounted_source") == "$(readlink -f /dev/mapper/lab-root-crypt)" ]]
[[ $(findmnt -n -o UUID /) == "$(blkid -s UUID -o value /dev/mapper/lab-root-crypt)" ]]
[[ $(findmnt -n -o FSTYPE /) == btrfs && $(findmnt -n -o FSTYPE /boot) == vfat ]]
[[ $(findmnt -n -o FSROOT /home) == /lab-home ]]
pacman -Q | sort > /run/installed-packages.txt
diff -u /var/lib/enzimos-lab/expected-packages.txt /run/installed-packages.txt
[[ $(stat -c %u:%g:%a /var/lib/enzimos-lab/metadata) == 12345:12346:640 ]]
getfacl -n /var/lib/enzimos-lab/metadata | grep -qx 'user:12347:r--'
[[ $(getfattr --only-values -n user.enzimos-lab /var/lib/enzimos-lab/metadata) == persisted ]]
getcap /var/lib/enzimos-lab/capability-probe | grep -q 'cap_net_bind_service=ep$'
[[ $(stat -c %u:%g:%a /usr/bin/passwd) == 0:0:4755 ]]
root_lock=$(getent shadow root | cut -d: -f2)
[[ $root_lock == '*'* || $root_lock == '!'* ]]
(cd /boot && sha256sum --strict -c /var/lib/enzimos-lab/boot.sha256)
cat /var/lib/enzimos-lab/boot.sha256
modprobe dm_crypt
grep -q '^dm_crypt ' /proc/modules
if (( phase >= 6 )); then
    [[ $(findmnt -n -o FSROOT /) == /lab-restored ]]
    [[ $(< /etc/enzimos-lab-generation) == baseline ]]
    [[ $(< /home/enzimos-lab-home-marker) == newer-home-preserved ]]
fi
if (( phase == 3 )); then
    [[ $(findmnt -n -o FSROOT /) == /lab-root ]]
    mkdir -p /run/lab-top
    mount -t btrfs -o subvolid=5 /dev/mapper/lab-root-crypt /run/lab-top
    [[ ! -e /run/lab-top/lab-pre-update && ! -e /run/lab-top/lab-restored ]]
    sync
    btrfs subvolume snapshot -r / /run/lab-top/lab-pre-update
    printf 'newer-home-preserved\n' > /home/enzimos-lab-home-marker
    printf 'synthetic-bad-generation\n' > /etc/enzimos-lab-generation
    # NOT an actual package update: deliberately make only this named root unbootable.
    mv /usr/lib/systemd/systemd /usr/lib/systemd/systemd.lab-broken
    printf '0\n' > /run/lab-top/lab-recovery-state
    printf 'default recovery.conf\ntimeout 0\neditor no\n' > /boot/loader/loader.conf
    sed -i 's/^default_entry: .*/default_entry: 3/' /boot/limine/limine.conf
    umount /run/lab-top
elif [[ $flavor == linux ]]; then
    printf 'default linux-lts.conf\ntimeout 0\neditor no\n' > /boot/loader/loader.conf
    sed -i 's/^default_entry: .*/default_entry: 2/' /boot/limine/limine.conf
else
    printf 'default linux.conf\ntimeout 0\neditor no\n' > /boot/loader/loader.conf
    sed -i 's/^default_entry: .*/default_entry: 1/' /boot/limine/limine.conf
fi
printf '%s\n' "$((phase + 1))" > /var/lib/enzimos-lab/phase
sync
printf '\nENZIMOS_CRYPT_KERNEL=%s\nENZIMOS_CRYPT_MODE=%s\nENZIMOS_CRYPT_PHASE=%s\nENZIMOS_CRYPT_ROOT_PASS mapped-root packages metadata home boot-files\n' "$(uname -r)" "$mode" "$phase"
systemctl --no-block poweroff
