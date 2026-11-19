#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Self-check and advance a four-boot disposable-image test, then power off.
set -euo pipefail
export PATH=/usr/bin LC_ALL=C
trap 'printf "\nENZIMOS_ROOT_FAILURE line=%s\n" "$LINENO" > /dev/console' ERR
exec > /dev/console 2>&1
[[ $(cat /proc/1/comm) == systemd ]]
[[ $(findmnt -n -o FSTYPE /) == btrfs ]]
[[ $(findmnt -n -o FSTYPE /boot) == vfat ]]
phase=$(< /var/lib/enzimos-lab/phase)
case "$phase" in
    0) flavor=linux; mode=uefi ;;
    1) flavor=linux-lts; mode=uefi ;;
    2) flavor=linux; mode=bios ;;
    3) flavor=linux-lts; mode=bios ;;
    *) exit 1 ;;
esac
[[ $(uname -r) == "$(< "/var/lib/enzimos-lab/uname-$flavor")" ]]
if [[ $mode == uefi ]]; then
    [[ -d /sys/firmware/efi ]]
    bootctl status --no-pager > /run/bootctl-status.txt
    cat /run/bootctl-status.txt
    grep -q 'Product: systemd-boot' /run/bootctl-status.txt
    grep -qw 'enzimos.lab.loader=systemd-boot' /proc/cmdline
else
    [[ ! -d /sys/firmware/efi ]]
    grep -qw 'enzimos.lab.loader=limine-bios' /proc/cmdline
fi
pacman -Q | sort > /run/installed-packages.txt
diff -u /var/lib/enzimos-lab/expected-packages.txt /run/installed-packages.txt
[[ $(stat -c %u:%g:%a /var/lib/enzimos-lab/metadata) == 12345:12346:640 ]]
getfacl -n /var/lib/enzimos-lab/metadata | grep -qx 'user:12347:r--'
[[ $(getfattr --only-values -n user.enzimos-lab /var/lib/enzimos-lab/metadata) == persisted ]]
getcap /var/lib/enzimos-lab/capability-probe | grep -q 'cap_net_bind_service=ep$'
[[ $(stat -c %u:%g:%a /usr/bin/passwd) == 0:0:4755 ]]
[[ $(stat -c %u:%g:%a /usr/bin/su) == 0:0:4755 ]]
root_lock=$(getent shadow root | cut -d: -f2)
[[ $root_lock == '*'* || $root_lock == '!'* ]]
(cd /boot && sha256sum --strict -c /var/lib/enzimos-lab/boot.sha256)
modprobe dm_crypt
grep -q '^dm_crypt ' /proc/modules
# No UI, automatic account login, or hibernation attempt in this fixture.
if [[ $flavor == linux ]]; then
    printf 'default linux-lts.conf\ntimeout 0\neditor no\n' > /boot/loader/loader.conf
    sed -i 's/^default_entry: .*/default_entry: 2/' /boot/limine/limine.conf
else
    printf 'default linux.conf\ntimeout 0\neditor no\n' > /boot/loader/loader.conf
    sed -i 's/^default_entry: .*/default_entry: 1/' /boot/limine/limine.conf
fi
printf '%s\n' "$((phase + 1))" > /var/lib/enzimos-lab/phase
sync
printf '\nENZIMOS_ROOT_KERNEL=%s\nENZIMOS_ROOT_MODE=%s\nENZIMOS_ROOT_PHASE=%s\nENZIMOS_ROOT_PASS btrfs packages owners acl xattr capability boot-files dm-crypt\n' "$(uname -r)" "$mode" "$phase"
systemctl --no-block poweroff
