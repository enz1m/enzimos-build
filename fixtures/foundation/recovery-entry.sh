#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -euo pipefail
exec > /dev/console 2>&1
trap 'printf "\nENZIMOS_FOUNDATION_FAILURE recovery-entry\n"' ERR
# mkinitcpio's RAM root defaults to 1777. Restrict this private recovery root
# before reading credentials; never relax the packaged safe-parent checks.
case $(findmnt -n -o FSTYPE --mountpoint /) in tmpfs|rootfs) ;; *) exit 1 ;; esac
[[ $(stat -c %u /) == 0 && ! -e /dev/mapper/lab-root-crypt ]]
chmod 0755 /
udevadm settle --timeout=30
modprobe qemu_fw_cfg
exec /usr/bin/python /usr/lib/enzimos-lab/foundation_recovery.py
