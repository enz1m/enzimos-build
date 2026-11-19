#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Fixed disposable VM fixture. Never expose host block devices to this guest.
set -euo pipefail
export PATH=/usr/bin LC_ALL=C SYSTEMD_OFFLINE=1
trap 'printf "\nENZIMOS_TARGET_FAILURE line=%s\n" "$LINENO" > /dev/console' ERR
exec > /dev/console 2>&1
printf '\nENZIMOS_TARGET_PROVISION_START\n'
udevadm settle --timeout=20
target=$(readlink -f /dev/disk/by-id/virtio-enzimos-lab-target)
payload=$(readlink -f /dev/disk/by-id/virtio-enzimos-lab-payload)
[[ $target != "$payload" && -b $target && -b $payload ]]
[[ $(blockdev --getsize64 "$target") == 8589934592 ]]
[[ $(blockdev --getro "$payload") == 1 ]]
[[ -z $(wipefs --noheadings --output TYPE "$target") ]]
mkdir -p /payload /target /run/lab-public-keys
mount -t iso9660 -o ro,nosuid,nodev,noexec "$payload" /payload
(cd /payload && sha256sum --strict -c SHA256SUMS)
cp -a /payload/public-keys/. /run/lab-public-keys/
chmod 700 /run/lab-public-keys
# GPT fixture: 1 MiB Limine embedding, 512 MiB ESP, remaining Btrfs.
# Sizes/names here are NOT selected installer defaults.
sfdisk "$target" <<'LAYOUT'
label: gpt
start=2048, size=2048, type=21686148-6449-6e6f-744e-656564454649, name="enzimos-lab-bios"
size=1048576, type=c12a7328-f81f-11d2-ba4b-00a0c93ec93b, name="enzimos-lab-esp"
type=0fc63daf-8483-4772-8e79-3d69d8477de4, name="enzimos-lab-root"
LAYOUT
udevadm settle --timeout=20
esp=/dev/disk/by-partlabel/enzimos-lab-esp
root=/dev/disk/by-partlabel/enzimos-lab-root
[[ -b $esp && -b $root ]]
mkfs.fat -F 32 "$esp"
mkfs.btrfs -f "$root"
mount -t btrfs "$root" /target
btrfs subvolume create /target/lab-root
btrfs subvolume create /target/lab-home
umount /target
mount -t btrfs -o subvol=lab-root,compress=zstd "$root" /target
mkdir -p /target/{boot,home,dev,proc,sys,run,etc,var/lib/pacman}
mount -t vfat "$esp" /target/boot
mount -t btrfs -o subvol=lab-home,compress=zstd "$root" /target/home
mount --rbind /dev /target/dev
mount --make-rslave /target/dev
mount -t proc proc /target/proc
mount -t sysfs sysfs /target/sys
mount -t tmpfs tmpfs /target/run
# Target keyring remains empty during package scriptlets; upstream keyring's
# conditional population then does not request a local private signing key.
pacman --root /target --config /payload/pacman-install.conf --gpgdir /run/lab-public-keys \
    --noconfirm -U /payload/packages/*.pkg.tar.zst
pacman --root /target --config /payload/pacman-install.conf -Q | sort > /run/installed-packages.txt
diff -u /payload/expected-packages.txt /run/installed-packages.txt
printf '\nENZIMOS_TARGET_PACKAGES=146\n'
cp /payload/target-mkinitcpio.conf /target/etc/mkinitcpio.conf
chroot /target mkinitcpio -P
root_uuid=$(blkid -s UUID -o value "$root")
esp_uuid=$(blkid -s UUID -o value "$esp")
printf 'UUID=%s / btrfs subvol=lab-root,compress=zstd 0 0\nUUID=%s /home btrfs subvol=lab-home,compress=zstd 0 0\nUUID=%s /boot vfat umask=0077 0 2\n' \
    "$root_uuid" "$root_uuid" "$esp_uuid" > /target/etc/fstab
printf 'enzimos-disposable-lab\n' > /target/etc/hostname
# The public direct-trust cache contains only quorum-approved packagers. This
# fixed-snapshot fixture is NOT a qualified rolling-update keyring lifecycle.
mkdir -p /target/etc/pacman.d/gnupg
cp -a /payload/public-keys/. /target/etc/pacman.d/gnupg/
chmod 700 /target/etc/pacman.d/gnupg
cp /payload/pacman-target.conf /target/etc/pacman.conf
mkdir -p /target/usr/lib/enzimos-lab /target/var/lib/enzimos-lab
cp /payload/root-smoke.sh /target/usr/lib/enzimos-lab/root-smoke.sh
cp /payload/expected-packages.txt /target/var/lib/enzimos-lab/expected-packages.txt
cp /payload/enzimos-root-smoke.service /target/etc/systemd/system/
chroot /target systemctl enable enzimos-root-smoke.service
printf '0\n' > /target/var/lib/enzimos-lab/phase
printf 'persistent-metadata\n' > /target/var/lib/enzimos-lab/metadata
chroot /target chown 12345:12346 /var/lib/enzimos-lab/metadata
chroot /target chmod 640 /var/lib/enzimos-lab/metadata
chroot /target setfacl -m u:12347:r-- /var/lib/enzimos-lab/metadata
chroot /target setfattr -n user.enzimos-lab -v persisted /var/lib/enzimos-lab/metadata
cp /target/usr/bin/true /target/var/lib/enzimos-lab/capability-probe
chroot /target setcap cap_net_bind_service=ep /var/lib/enzimos-lab/capability-probe
# bootctl must not touch firmware variables, even virtual ones, during assembly.
chroot /target bootctl --esp-path=/boot --no-variables install
mkdir -p /target/boot/loader/entries /target/boot/limine
printf 'default linux.conf\ntimeout 0\neditor no\n' > /target/boot/loader/loader.conf
printf 'timeout: 0\ndefault_entry: 1\nserial: yes\n' > /target/boot/limine/limine.conf
for flavor in linux linux-lts; do
    module_dir=$(find /target/usr/lib/modules -mindepth 1 -maxdepth 1 -type d | while read -r dir; do
        [[ $(< "$dir/pkgbase") != "$flavor" ]] || printf '%s\n' "$dir"
    done)
    [[ -f $module_dir/vmlinuz && -s /target/boot/initramfs-$flavor.img ]]
    cp "$module_dir/vmlinuz" "/target/boot/vmlinuz-$flavor"
    printf '%s\n' "${module_dir##*/}" > "/target/var/lib/enzimos-lab/uname-$flavor"
    options="root=UUID=$root_uuid rootflags=subvol=lab-root rw console=ttyS0,115200 systemd.log_color=no panic=5"
    printf 'title enzimOS disposable %s\nlinux /vmlinuz-%s\ninitrd /initramfs-%s.img\noptions %s enzimos.lab.loader=systemd-boot\n' \
        "$flavor" "$flavor" "$flavor" "$options" > "/target/boot/loader/entries/$flavor.conf"
    printf '/enzimOS disposable %s\n    protocol: linux\n    path: boot():/vmlinuz-%s\n    module_path: boot():/initramfs-%s.img\n    cmdline: %s enzimos.lab.loader=limine-bios\n' \
        "$flavor" "$flavor" "$flavor" "$options" >> /target/boot/limine/limine.conf
done
cp /target/usr/share/limine/limine-bios.sys /target/boot/limine/
chroot /target limine bios-install "$target" 1
# Record exact on-disk kernel/initrd/loader bytes for later in-guest checking.
(cd /target/boot && sha256sum vmlinuz-* initramfs-*.img EFI/BOOT/BOOTX64.EFI limine/limine-bios.sys) > /target/var/lib/enzimos-lab/boot.sha256
chroot /target stat -c '%u:%g:%a %n' /usr/bin/passwd /usr/bin/su /var/lib/enzimos-lab/metadata
chroot /target getcap /var/lib/enzimos-lab/capability-probe
sync
printf '\nENZIMOS_TARGET_PROVISION_PASS packages metadata boot-files\n'
unset SYSTEMD_OFFLINE
systemctl --no-block poweroff
