#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Runs only inside the explicitly launched diskless diagnostic VM.
set -euo pipefail
trap 'printf "ENZIMOS_INITRD_FAILURE line=%s status=%s\\n" "$LINENO" "$?"' ERR
printf 'ENZIMOS_INITRD_KERNEL=%s\n' "$(uname -r)"
[[ -f /etc/initrd-release ]]
[[ $(< /proc/1/comm) == systemd ]]
modprobe virtio_blk
modprobe btrfs
[[ -d /sys/module/virtio_blk ]]
grep -qw btrfs /proc/filesystems
modprobe dm_crypt
grep -q '^dm_crypt ' /proc/modules
printf 'ENZIMOS_INITRD_PASS systemd-pid1 btrfs-virtio matching-dm-crypt\n'
systemctl --no-block poweroff
