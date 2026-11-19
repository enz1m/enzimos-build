#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Guest-only migration from a read-only, provenance-bound lab image to NEW LUKS2.
set -euo pipefail
export PATH=/usr/bin LC_ALL=C SYSTEMD_OFFLINE=1
exec > /dev/console 2>&1
trap 'printf "\nENZIMOS_CRYPT_FAILURE line=%s\n" "$LINENO"' ERR
udevadm settle --timeout=30
target=$(readlink -f /dev/disk/by-id/virtio-enzimos-lab-target)
source_disk=$(readlink -f /dev/disk/by-id/virtio-enzimos-lab-source)
payload=$(readlink -f /dev/disk/by-id/virtio-enzimos-lab-payload)
[[ -b $target && -b $source_disk && -b $payload && $target != "$source_disk" ]]
[[ $(blockdev --getsize64 "$target") == 8589934592 ]]
[[ $(blockdev --getro "$source_disk") == 1 && $(blockdev --getro "$payload") == 1 ]]
[[ -z $(wipefs --noheadings --output TYPE "$target") ]]
mkdir -p /payload /source /source-home /source-boot /target
mount -t iso9660 -o ro,nosuid,nodev,noexec "$payload" /payload
(cd /payload && sha256sum --strict -c SHA256SUMS)
mount -t btrfs -o ro,rescue=nologreplay,subvol=lab-root /dev/disk/by-id/virtio-enzimos-lab-source-part3 /source
mount -t btrfs -o ro,rescue=nologreplay,subvol=lab-home /dev/disk/by-id/virtio-enzimos-lab-source-part3 /source-home
mount -t vfat -o ro /dev/disk/by-id/virtio-enzimos-lab-source-part2 /source-boot
pacman --root /source --config /source/etc/pacman.conf -Q | sort > /run/source-packages.txt
diff -u /payload/expected-packages.txt /run/source-packages.txt
sfdisk "$target" <<'LAYOUT'
label: gpt
start=2048, size=2048, type=21686148-6449-6e6f-744e-656564454649, name="enzimos-crypt-bios"
size=1048576, type=c12a7328-f81f-11d2-ba4b-00a0c93ec93b, name="enzimos-crypt-esp"
type=ca7d7ccb-63ed-4c53-861c-1742536059cc, name="enzimos-crypt-data"
LAYOUT
udevadm settle --timeout=30
esp=/dev/disk/by-id/virtio-enzimos-lab-target-part2
crypt=/dev/disk/by-id/virtio-enzimos-lab-target-part3
[[ -b $esp && -b $crypt ]]
# Defaults are calibrated inside this VM; no forced iterations or reduced memory.
cryptsetup luksFormat --type luks2 --pbkdf argon2id --batch-mode --key-file /payload/fixture-primary "$crypt"
cryptsetup luksAddKey --pbkdf argon2id --key-file /payload/fixture-primary "$crypt" /payload/fixture-recovery
cryptsetup luksDump "$crypt"
cryptsetup luksDump --dump-json-metadata "$crypt" > /run/luks-metadata.json
cat /run/luks-metadata.json
if printf 'INTENTIONALLY-WRONG-LAB-PASSWORD' | cryptsetup open --test-passphrase --key-file - "$crypt"; then
    printf 'ENZIMOS_CRYPT_FAILURE wrong-password-accepted\n'; exit 1
fi
cryptsetup open --test-passphrase --key-file /payload/fixture-recovery "$crypt"
printf '\nENZIMOS_CRYPT_KEYS_PASS wrong-rejected recovery-accepted\n'
cryptsetup open --key-file /payload/fixture-primary "$crypt" lab-root-crypt
mkfs.fat -F 32 "$esp"
mkfs.btrfs -f /dev/mapper/lab-root-crypt
mount -t btrfs /dev/mapper/lab-root-crypt /target
btrfs subvolume create /target/lab-root
btrfs subvolume create /target/lab-home
umount /target
mount -t btrfs -o subvol=lab-root,compress=zstd /dev/mapper/lab-root-crypt /target
cp -a --preserve=all /source/. /target/
mount -t vfat "$esp" /target/boot
mount -t btrfs -o subvol=lab-home,compress=zstd /dev/mapper/lab-root-crypt /target/home
cp -a --preserve=all /source-home/. /target/home/
cp -a /source-boot/. /target/boot/
mount --rbind /dev /target/dev
mount --make-rslave /target/dev
mount -t proc proc /target/proc
mount -t sysfs sysfs /target/sys
mount -t tmpfs tmpfs /target/run
luks_uuid=$(cryptsetup luksUUID "$crypt")
root_uuid=$(blkid -s UUID -o value /dev/mapper/lab-root-crypt)
esp_uuid=$(blkid -s UUID -o value "$esp")
printf 'lab-root-crypt UUID=%s none luks,x-initrd.attach\n' "$luks_uuid" > /target/etc/crypttab
printf 'UUID=%s / btrfs subvol=lab-root,compress=zstd 0 0\nUUID=%s /home btrfs subvol=lab-home,compress=zstd 0 0\nUUID=%s /boot vfat umask=0077 0 2\n' "$root_uuid" "$root_uuid" "$esp_uuid" > /target/etc/fstab
cp /payload/target-mkinitcpio.conf /target/etc/mkinitcpio.conf
chroot /target mkinitcpio -P
cp /payload/root-smoke.sh /target/usr/lib/enzimos-lab/root-smoke.sh
printf '0\n' > /target/var/lib/enzimos-lab/phase
printf 'baseline\n' > /target/etc/enzimos-lab-generation
printf 'original-home\n' > /target/home/enzimos-lab-home-marker
cp /run/luks-metadata.json /target/var/lib/enzimos-lab/luks-metadata.json
mkdir -p /target/boot/enzimos-recovery
cp /payload/recovery.img /target/boot/enzimos-recovery/initrd.img
cp /payload/recovery.kernel /target/boot/enzimos-recovery/kernel
printf 'default linux.conf\ntimeout 0\neditor no\n' > /target/boot/loader/loader.conf
printf 'timeout: 0\ndefault_entry: 1\nserial: yes\n' > /target/boot/limine/limine.conf
for flavor in linux linux-lts; do
    options="rd.luks.name=$luks_uuid=lab-root-crypt root=/dev/mapper/lab-root-crypt rootflags=subvol=lab-root rw console=ttyS0,115200 systemd.log_color=no panic=5"
    printf 'title enzimOS encrypted lab %s\nlinux /vmlinuz-%s\ninitrd /initramfs-%s.img\noptions %s\n' "$flavor" "$flavor" "$flavor" "$options" > "/target/boot/loader/entries/$flavor.conf"
    printf '/enzimOS encrypted lab %s\n    protocol: linux\n    path: boot():/vmlinuz-%s\n    module_path: boot():/initramfs-%s.img\n    cmdline: %s\n' "$flavor" "$flavor" "$flavor" "$options" >> /target/boot/limine/limine.conf
done
recovery_options='console=ttyS0,115200 rd.systemd.unit=enzimos-target-provision.target systemd.log_color=no panic=5'
printf 'title Independent enzimOS lab recovery\nlinux /enzimos-recovery/kernel\ninitrd /enzimos-recovery/initrd.img\noptions %s\n' "$recovery_options" > /target/boot/loader/entries/recovery.conf
printf '/Independent enzimOS lab recovery\n    protocol: linux\n    path: boot():/enzimos-recovery/kernel\n    module_path: boot():/enzimos-recovery/initrd.img\n    cmdline: %s\n' "$recovery_options" >> /target/boot/limine/limine.conf
chroot /target bootctl --esp-path=/boot --no-variables install
chroot /target limine bios-install "$target" 1
(cd /target/boot && sha256sum vmlinuz-* initramfs-*.img EFI/BOOT/BOOTX64.EFI limine/limine-bios.sys enzimos-recovery/*) > /target/var/lib/enzimos-lab/boot.sha256
cat /target/var/lib/enzimos-lab/boot.sha256
chroot /target pacman -Q | sort > /run/installed-packages.txt
diff -u /payload/expected-packages.txt /run/installed-packages.txt
sync
printf '\nENZIMOS_CRYPT_PROVISION_PASS luks2 argon2id two-keyslots migrated-146\n'
unset SYSTEMD_OFFLINE
systemctl --no-block poweroff
