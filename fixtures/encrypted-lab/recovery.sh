#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Self-contained headless recovery: no executable/library is used from the main root.
set -euo pipefail
export PATH=/usr/bin LC_ALL=C
exec > /dev/console 2>&1
trap 'printf "\nENZIMOS_CRYPT_FAILURE recovery-line=%s\n" "$LINENO"' ERR
[[ $(cat /proc/1/comm) == systemd && ! -e /dev/mapper/lab-root-crypt ]]
[[ $(findmnt -n -o FSTYPE /) != btrfs ]]
printf '\nENZIMOS_RECOVERY_RAM_STARTED root-still-locked\n'
udevadm settle --timeout=30
crypt=/dev/disk/by-id/virtio-enzimos-lab-target-part3
esp=/dev/disk/by-id/virtio-enzimos-lab-target-part2
[[ -b $crypt && -b $esp ]]
cryptsetup isLuks --type luks2 "$crypt"
# The passphrase comes from the console, never an embedded key file or main-root agent.
password=$(systemd-ask-password --no-tty --timeout=120 'ENZIMOS recovery passphrase:')
printf '%s' "$password" | cryptsetup open --key-file - "$crypt" lab-root-crypt
unset password
mkdir -p /mnt /boot
mount -t btrfs -o subvolid=5 /dev/mapper/lab-root-crypt /mnt
mount -t vfat "$esp" /boot
[[ ! -e /mnt/lab-root/usr/lib/systemd/systemd ]]
[[ -f /mnt/lab-root/usr/lib/systemd/systemd.lab-broken ]]
[[ $(< /mnt/lab-root/etc/enzimos-lab-generation) == synthetic-bad-generation ]]
[[ $(< /mnt/lab-home/enzimos-lab-home-marker) == newer-home-preserved ]]
[[ -f /mnt/lab-pre-update/usr/lib/systemd/systemd ]]
[[ $(< /mnt/lab-pre-update/etc/enzimos-lab-generation) == baseline ]]
cryptsetup luksDump --dump-json-metadata "$crypt" > /run/luks-metadata.json
diff -u /mnt/lab-root/var/lib/enzimos-lab/luks-metadata.json /run/luks-metadata.json
if [[ -d /sys/firmware/efi ]]; then
    mode=uefi; phase=4
    [[ $(< /mnt/lab-recovery-state) == 0 && ! -e /mnt/lab-restored ]]
    btrfs subvolume snapshot /mnt/lab-pre-update /mnt/lab-restored
    sed -i 's/subvol=lab-root/subvol=lab-restored/g' /mnt/lab-restored/etc/fstab
    for flavor in linux linux-lts; do
        sed -i 's/subvol=lab-root/subvol=lab-restored/g' "/boot/loader/entries/$flavor.conf"
    done
    sed -i 's/subvol=lab-root/subvol=lab-restored/g' /boot/limine/limine.conf
    printf '6\n' > /mnt/lab-restored/var/lib/enzimos-lab/phase
    printf '1\n' > /mnt/lab-recovery-state
else
    mode=bios; phase=5
    [[ $(< /mnt/lab-recovery-state) == 1 && -f /mnt/lab-restored/usr/lib/systemd/systemd ]]
    printf 'default linux.conf\ntimeout 0\neditor no\n' > /boot/loader/loader.conf
    sed -i 's/^default_entry: .*/default_entry: 1/' /boot/limine/limine.conf
    printf '2\n' > /mnt/lab-recovery-state
fi
pacman --root /mnt/lab-restored --config /mnt/lab-restored/etc/pacman.conf -Q | sort > /run/recovered-packages.txt
diff -u /mnt/lab-restored/var/lib/enzimos-lab/expected-packages.txt /run/recovered-packages.txt
(cd /boot && sha256sum --strict -c /mnt/lab-restored/var/lib/enzimos-lab/boot.sha256)
[[ $(stat -c %u:%g:%a /mnt/lab-restored/var/lib/enzimos-lab/metadata) == 12345:12346:640 ]]
getfacl -n /mnt/lab-restored/var/lib/enzimos-lab/metadata | grep -qx 'user:12347:r--'
getcap /mnt/lab-restored/var/lib/enzimos-lab/capability-probe | grep -q 'cap_net_bind_service=ep$'
sync
printf '\nENZIMOS_CRYPT_MODE=%s\nENZIMOS_CRYPT_PHASE=%s\nENZIMOS_RECOVERY_PASS broken-root snapshot-restored home-preserved header-unchanged\n' "$mode" "$phase"
systemctl --no-block poweroff
