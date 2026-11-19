#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Runs only in a fresh private COPY of the pinned encrypted lab disk.
set -euo pipefail
export PATH=/usr/bin LC_ALL=C SYSTEMD_OFFLINE=1
exec > /dev/console 2>&1
trap 'printf "\nENZIMOS_FOUNDATION_FAILURE setup-line=%s\n" "$LINENO"' ERR
udevadm settle --timeout=30
mkdir -p /payload /mnt /target /run/keys
mount -t iso9660 -o ro,nodev,nosuid,noexec /dev/disk/by-id/virtio-enzimos-lab-payload /payload
(cd /payload && sha256sum --strict -c SHA256SUMS)
if [[ -b /dev/disk/by-id/virtio-enzimos-lab-patch ]]; then
    mkdir -p /patches /base-payload
    mount -t iso9660 -o ro,nodev,nosuid,noexec /dev/disk/by-id/virtio-enzimos-lab-patch /patches
    (cd /patches && sha256sum --strict -c SHA256SUMS)
    mount --bind /payload /base-payload
    mount --make-private /base-payload
    mount -t tmpfs -o nodev,nosuid,noexec tmpfs /payload
    for item in /base-payload/*; do ln -s "$item" "/payload/${item##*/}"; done
    for item in /patches/*; do ln -sf "$item" "/payload/${item##*/}"; done
fi
install_recovery() {
    cp /base-payload/recovery.img /target/boot/enzimos-recovery/initrd.img
    local image=/target/boot/enzimos-recovery/initrd.img size padding expected
    size=$(stat -c %s "$image");padding=$(( (4-size%4)%4 ))
    head -c "$padding" /dev/zero >> "$image"
    cat /patches/recovery.patch >> "$image"
    expected=$(< /patches/recovery-composed.sha256)
    printf '%s  %s\n' "$expected" "$image" | sha256sum --strict -c -
}
cryptsetup open --key-file /payload/fixture-primary /dev/disk/by-id/virtio-enzimos-lab-target-part3 lab-root-crypt
mount -t btrfs -o subvolid=5,nodiscard /dev/mapper/lab-root-crypt /mnt
modprobe qemu_fw_cfg
operation=''
read -r -d '' operation < /sys/firmware/qemu_fw_cfg/by_name/opt/enzimos/case/raw || [[ -n $operation ]]
if [[ $operation == refresh ]]; then
    [[ -d /mnt/fdn-root && -d /mnt/fdn-control && -d /mnt/fdn-authority ]]
    mount -t btrfs -o subvol=fdn-root,nodiscard /dev/mapper/lab-root-crypt /target
    mount -t vfat /dev/disk/by-id/virtio-enzimos-lab-target-part2 /target/boot
    mount -t btrfs -o subvol=fdn-authority,nodiscard /dev/mapper/lab-root-crypt /target/etc/pacman.d/gnupg
    mount -t btrfs -o subvol=fdn-control,nodiscard /dev/mapper/lab-root-crypt /target/var/lib/enzimos-control
    mount --rbind /dev /target/dev;mount --make-rslave /target/dev
    mount -t proc proc /target/proc;mount -t sysfs sysfs /target/sys;mount -t tmpfs tmpfs /target/run
    mkdir -m700 /run/lab-signing
    GNUPGHOME=/run/lab-signing gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'enzimOS DISPOSABLE refreshed lab policy' ed25519 sign 1d
    GNUPGHOME=/run/lab-signing gpg --batch --yes --detach-sign --output /run/native-policy.pkg.tar.zst.sig /payload/native-policy.pkg.tar.zst
    GNUPGHOME=/run/lab-signing gpg --batch --export > /run/lab-signing-public.gpg
    fingerprint=$(GNUPGHOME=/run/lab-signing gpg --with-colons --list-keys | awk -F: '$1=="fpr" {print $10;exit}')
    # Earlier sanitized public-certificate copies retained UID1000. This is a
    # guest-only fixture repair; preserve trust bytes and restore root ownership.
    chown -R root:root /target/etc/pacman.d/gnupg
    gpg --homedir /target/etc/pacman.d/gnupg --batch --no-autostart --import /run/lab-signing-public.gpg
    printf '%s:5:\n' "$fingerprint" | gpg --homedir /target/etc/pacman.d/gnupg --batch --no-autostart --import-ownertrust
    cp /payload/native-policy.pkg.tar.zst /run/native-policy.pkg.tar.zst
    pacman --root /target --config /payload/pacman-install.conf --gpgdir /target/etc/pacman.d/gnupg --noconfirm -U /run/native-policy.pkg.tar.zst
    cp /run/native-policy.pkg.tar.zst /run/native-policy.pkg.tar.zst.sig /mnt/fdn-control/
    # Apply revised image defaults only in this explicit fixture refresh.
    chroot /target systemctl preset snapper-timeline.timer fstrim.timer
    mkdir -p /target/etc/systemd/system.conf.d
    printf '[Manager]\nDefaultDeviceTimeoutSec=300s\nDefaultTimeoutStartSec=300s\n' > /target/etc/systemd/system.conf.d/90-enzimos-lab.conf
    cp /payload/foundation_test.py /target/usr/lib/enzimos-lab/foundation_test.py
    cp /payload/test_rebind.py /target/usr/lib/enzimos-lab/test_rebind.py
    cp /payload/test_ownership.py /target/usr/lib/enzimos-lab/test_ownership.py
    cp /payload/test_recovery_publication.py /target/usr/lib/enzimos-lab/test_recovery_publication.py
    cp /payload/foundation-test.service /target/etc/systemd/system/foundation-test.service
    if [[ -f /patches/recovery.patch ]]; then install_recovery; else cp /payload/recovery.img /target/boot/enzimos-recovery/initrd.img; fi
    cp /payload/recovery.kernel /target/boot/enzimos-recovery/kernel
    python - <<'PY'
import json
from pathlib import Path
p=Path('/target/etc/enzimos/storage.json');d=json.loads(p.read_text())
d['control_subvol']='fdn-control'
d['legacy_boot_entries']={'uefi':['linux.conf','linux-lts.conf'],'bios':['enzimOS encrypted lab linux','enzimOS encrypted lab linux-lts']}
p.write_text(json.dumps(d,indent=2)+'\n')
PY
    if ! grep -q 'lsm=' /target/boot/loader/entries/recovery.conf; then
        sed -i 's/systemd.log_color=no/systemd.log_color=no lsm=landlock,lockdown,yama,integrity,apparmor,bpf/' /target/boot/loader/entries/recovery.conf
    fi
    for f in /target/boot/loader/entries/linux.conf /target/boot/loader/entries/linux-lts.conf /target/boot/limine/limine.conf; do
        sed -i 's/ rd.luks.options=[^ ]*//g;s/subvol=fdn-root /subvol=fdn-root,nodiscard /g;s/rd.luks.name=\([^= ]*\)=lab-root-crypt /rd.luks.name=\1=lab-root-crypt rd.luks.options=\1=discard /g' "$f"
    done
    sync
    printf '\nENZIMOS_FOUNDATION_SETUP_PASS refreshed-fixture-only\n'
    unset SYSTEMD_OFFLINE
    systemctl --no-block poweroff
    exit 0
fi
[[ $operation == setup && ! -e /mnt/fdn-root && -d /mnt/lab-restored ]]
btrfs subvolume snapshot /mnt/lab-restored /mnt/fdn-root
btrfs subvolume create /mnt/fdn-control
btrfs subvolume create /mnt/fdn-authority
mount -t btrfs -o subvol=fdn-root,nodiscard /dev/mapper/lab-root-crypt /target
mount -t vfat /dev/disk/by-id/virtio-enzimos-lab-target-part2 /target/boot
mount -t btrfs -o subvol=lab-home,nodiscard /dev/mapper/lab-root-crypt /target/home
mount --rbind /dev /target/dev;mount --make-rslave /target/dev
mount -t proc proc /target/proc;mount -t sysfs sysfs /target/sys;mount -t tmpfs tmpfs /target/run
cp -a /payload/public-keys/. /run/keys/
chmod 700 /run/keys
mapfile -t old_archives < /payload/old-package-files.txt
pacman --root /target --config /payload/pacman-install.conf --gpgdir /run/keys --noconfirm --needed -U "${old_archives[@]}"
# Generate ONLY a disposable package-signing fixture key inside the guest RAM.
mkdir -m700 /run/lab-signing
GNUPGHOME=/run/lab-signing gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'enzimOS DISPOSABLE lab signing key' ed25519 sign 1d
GNUPGHOME=/run/lab-signing gpg --batch --yes --detach-sign --output /run/native-policy.sig /payload/native-policy.pkg.tar.zst
GNUPGHOME=/run/lab-signing gpg --batch --export > /run/lab-signing-public.gpg
fingerprint=$(GNUPGHOME=/run/lab-signing gpg --with-colons --list-keys | awk -F: '$1=="fpr" {print $10;exit}')
gpg --homedir /run/keys --batch --no-autostart --import /run/lab-signing-public.gpg
printf '%s:5:\n' "$fingerprint" | gpg --homedir /run/keys --batch --no-autostart --import-ownertrust
cp /payload/native-policy.pkg.tar.zst /run/native-policy.pkg.tar.zst
cp /run/native-policy.sig /run/native-policy.pkg.tar.zst.sig
pacman --root /target --config /payload/pacman-install.conf --gpgdir /run/keys --noconfirm -U /run/native-policy.pkg.tar.zst
cp -a --no-preserve=ownership /run/keys/. /mnt/fdn-authority/
chown root:root /mnt/fdn-authority
cp /run/lab-signing-public.gpg /mnt/fdn-control/lab-signing-public.gpg
cp /run/lab-signing/openpgp-revocs.d/*.rev /mnt/fdn-control/lab-signing-revocation.txt
printf '%s\n' "$fingerprint" > /mnt/fdn-control/lab-signing-fingerprint
cp /run/native-policy.pkg.tar.zst /run/native-policy.pkg.tar.zst.sig /mnt/fdn-control/
chmod 700 /mnt/fdn-authority /mnt/fdn-control
mkdir -p /target/var/lib/enzimos-control
mount -t btrfs -o subvol=fdn-control /dev/mapper/lab-root-crypt /target/var/lib/enzimos-control
# Replace the previous lab cache with the mandatory independent current authority mount.
mount -t btrfs -o subvol=fdn-authority /dev/mapper/lab-root-crypt /target/etc/pacman.d/gnupg
uuid=$(blkid -s UUID -o value /dev/mapper/lab-root-crypt)
esp_uuid=$(blkid -s UUID -o value /dev/disk/by-id/virtio-enzimos-lab-target-part2)
printf 'UUID=%s / btrfs subvol=fdn-root,compress=zstd,nodiscard 0 0\nUUID=%s /home btrfs subvol=lab-home,compress=zstd,nodiscard 0 0\nUUID=%s /var/lib/enzimos-control btrfs subvol=fdn-control,nodiscard 0 0\nUUID=%s /etc/pacman.d/gnupg btrfs subvol=fdn-authority,nodiscard 0 0\nUUID=%s /boot vfat umask=0077 0 2\n' "$uuid" "$uuid" "$uuid" "$uuid" "$esp_uuid" > /target/etc/fstab
printf '{"filesystem_uuid":"%s","root_subvol":"fdn-root","home_subvol":"lab-home","authority_subvol":"fdn-authority","control_subvol":"fdn-control","legacy_boot_entries":{"uefi":["linux.conf","linux-lts.conf"],"bios":["enzimOS encrypted lab linux","enzimOS encrypted lab linux-lts"]}}\n' "$uuid" > /target/etc/enzimos/storage.json
ln -sf /run/systemd/resolve/stub-resolv.conf /target/etc/resolv.conf
chroot /target snapper --no-dbus -c root create-config /
chroot /target snapper --no-dbus -c home create-config /home
chroot /target snapper --no-dbus -c root set-config 'TIMELINE_CREATE=no' 'NUMBER_LIMIT=4' 'NUMBER_LIMIT_IMPORTANT=4' 'NUMBER_MIN_AGE=0'
chroot /target snapper --no-dbus -c home set-config 'TIMELINE_CREATE=no' 'TIMELINE_LIMIT_HOURLY=3' 'TIMELINE_LIMIT_DAILY=2' 'TIMELINE_LIMIT_WEEKLY=0' 'TIMELINE_LIMIT_MONTHLY=0' 'TIMELINE_LIMIT_YEARLY=0' 'TIMELINE_MIN_AGE=0'
cp /target/usr/share/enzimos/snap-pac.ini /target/etc/snap-pac.ini
# This test identity is not a shipped user account or credential.
chroot /target useradd -m -u 1000 -G wheel -s /bin/bash enzimos-admin
chroot /target useradd -m -u 1001 -s /bin/bash enzimos-user
chroot /target chpasswd < /payload/fixture-accounts
chroot /target passwd -l root
# Explicit independent backup disk, never a host device.
backup=/dev/disk/by-id/virtio-enzimos-lab-backup
[[ -b $backup && $(blockdev --getsize64 "$backup") == 2147483648 && -z $(wipefs --noheadings --output TYPE "$backup") ]]
mkfs.btrfs -f "$backup"
backup_uuid=$(blkid -s UUID -o value "$backup")
mkdir -p /target/backup-repository
mount -t btrfs -o nodiscard "$backup" /target/backup-repository
printf 'UUID=%s /backup-repository btrfs noauto,nodiscard 0 0\n' "$backup_uuid" >> /target/etc/fstab
cp /payload/fixture-backup-password /target/etc/enzimos/backup.password
chmod 600 /target/etc/enzimos/backup.password
printf '{"repository":"/backup-repository/restic","destination_uuid":"%s","password_file":"/etc/enzimos/backup.password","minimum_free_bytes":67108864,"keep_last":3}\n' "$backup_uuid" > /target/etc/enzimos/backup.json
# Test harness is not the production package; normal operations import installed code.
cp /payload/foundation_test.py /target/usr/lib/enzimos-lab/foundation_test.py
cp /payload/test_rebind.py /target/usr/lib/enzimos-lab/test_rebind.py
cp /payload/test_ownership.py /target/usr/lib/enzimos-lab/test_ownership.py
cp /payload/foundation-test.service /target/etc/systemd/system/foundation-test.service
mkdir -p /target/etc/systemd/system.conf.d
printf '[Manager]\nDefaultDeviceTimeoutSec=300s\nDefaultTimeoutStartSec=300s\n' > /target/etc/systemd/system.conf.d/90-enzimos-lab.conf
chroot /target systemctl disable enzimos-root-smoke.service
chroot /target systemctl enable foundation-test.service
cp /payload/old-packages.txt /payload/new-packages.txt /payload/kernels.env /target/var/lib/enzimos-control/
cp /payload/pacman-update.conf /target/etc/pacman-foundation.conf
# Explicitly enable LUKS discard, already accepted for weekly owned-filesystem TRIM.
sed -i 's/none luks,x-initrd.attach/none luks,discard,x-initrd.attach/' /target/etc/crypttab
chroot /target mkinitcpio -P
if [[ -f /patches/recovery.patch ]]; then install_recovery; else cp /payload/recovery.img /target/boot/enzimos-recovery/initrd.img; fi
cp /payload/recovery.kernel /target/boot/enzimos-recovery/kernel
for flavor in linux linux-lts; do
  sed -i 's/subvol=lab-restored/subvol=fdn-root,nodiscard/g;s/rd.luks.name=\([^= ]*\)=lab-root-crypt /rd.luks.name=\1=lab-root-crypt rd.luks.options=\1=discard /g;s/systemd.log_color=no/systemd.log_color=no lsm=landlock,lockdown,yama,integrity,apparmor,bpf/' "/target/boot/loader/entries/$flavor.conf"
done
sed -i 's/subvol=lab-restored/subvol=fdn-root,nodiscard/g;s/rd.luks.name=\([^= ]*\)=lab-root-crypt /rd.luks.name=\1=lab-root-crypt rd.luks.options=\1=discard /g;s/systemd.log_color=no/systemd.log_color=no lsm=landlock,lockdown,yama,integrity,apparmor,bpf/g' /target/boot/limine/limine.conf
sed -i 's/systemd.log_color=no/systemd.log_color=no lsm=landlock,lockdown,yama,integrity,apparmor,bpf/' /target/boot/loader/entries/recovery.conf
printf 'default linux.conf\ntimeout 0\neditor no\n' > /target/boot/loader/loader.conf
sed -i 's/^default_entry: .*/default_entry: 1/' /target/boot/limine/limine.conf
(cd /target/boot && sha256sum vmlinuz-* initramfs-*.img enzimos-recovery/*) > /mnt/fdn-control/initial-boot.sha256
sync
printf '\nENZIMOS_FOUNDATION_SETUP_PASS expanded-packages signed-policy accounts storage\n'
unset SYSTEMD_OFFLINE
systemctl --no-block poweroff
