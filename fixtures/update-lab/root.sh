#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Runs a genuine full pacman transaction in the live HEADLESS guest, never the host.
set -euo pipefail
export PATH=/usr/bin LC_ALL=C
exec > /dev/console 2>&1
trap 'printf "\nENZIMOS_UPDATE_FAILURE root-line=%s\n" "$LINENO"' ERR
# Installed guest helper is linted separately, never sourced from host /usr/lib.
# shellcheck source=/dev/null
source /usr/lib/enzimos-update-lab/common.sh
state_dir=/var/lib/enzimos-update-lab
# Generated exclusively from validated kernel release identifiers.
# shellcheck source=/dev/null
source "$state_dir/kernels.env"
state=$(< "$state_dir/state")
scenario=$(< "$state_dir/scenario")
[[ $(cat /proc/1/comm) == systemd && $(findmnt -n -o FSROOT /etc/pacman.d/gnupg) == /upd-authority ]]
[[ $(findmnt -n -o FSTYPE /) == btrfs ]]
authority_check /etc/pacman.d/gnupg "$state_dir"
cryptsetup status lab-root-crypt
(cd /boot && sha256sum --strict -c "$state_dir/retained.sha256")
if [[ $state == update ]]; then
    [[ $(uname -r) == "$OLD_REGULAR" && $(findmnt -n -o FSROOT /) == /upd-live ]]
    package_check "$state_dir/old-packages.txt"
    [[ ! -d /sys/module/overlay ]]
    modinfo -k "$OLD_REGULAR" overlay
    mkdir -p /payload /run/update-top
    mount -t iso9660 -o ro,nodev,nosuid,noexec /dev/disk/by-id/virtio-enzimos-lab-payload /payload
    (cd /payload && sha256sum --strict -c SHA256SUMS)
    mount -t btrfs -o subvolid=5 /dev/mapper/lab-root-crypt /run/update-top
    [[ ! -e /run/update-top/upd-pre ]]
    sync
    btrfs subvolume snapshot -r / /run/update-top/upd-pre
    printf 'home-created-after-update-snapshot\n' > /home/update-lab-marker
    select_entry recovery 3
    sync
    : > /var/log/pacman-update-lab.log
    printf '\nENZIMOS_UPDATE_BEGIN scenario=%s running=%s\n' "$scenario" "$(uname -r)"
    if [[ $scenario == interrupt ]]; then
        setsid pacman --config /etc/pacman-update-lab.conf -Syu --noconfirm > /var/log/pacman-update-transcript.log 2>&1 &
        tx_pid=$!
        while kill -0 "$tx_pid" 2>/dev/null; do
            if grep -q '\[ALPM\] upgraded linux (' /var/log/pacman-update-lab.log; then
                kill -STOP -- "-$tx_pid"
                cat /var/log/pacman-update-lab.log
                pacman -Q linux | grep -Fx "$(grep '^linux ' "$state_dir/new-packages.txt")"
                [[ -f /var/lib/pacman/db.lck ]]
                if grep -q '\[ALPM\] transaction completed' /var/log/pacman-update-lab.log; then
                    printf 'ENZIMOS_UPDATE_FAILURE cut-too-late\n'; exit 1
                fi
                sync
                printf '\nENZIMOS_UPDATE_CUT_READY upgraded-linux transaction-incomplete\n'
                while :; do sleep 1; done
            fi
            sleep 0.1
        done
        wait "$tx_pid"
        printf 'ENZIMOS_UPDATE_FAILURE missed-cut-checkpoint\n'; exit 1
    fi
    [[ $scenario == success ]]
    pacman --config /etc/pacman-update-lab.conf -Syu --noconfirm
    package_check "$state_dir/new-packages.txt"
    [[ ! -e /var/lib/pacman/db.lck && $(uname -r) == "$OLD_REGULAR" ]]
    cat /var/log/pacman-update-lab.log
    if modinfo -k "$OLD_REGULAR" overlay > /run/default-module-path.txt 2>&1; then
        printf '\nENZIMOS_RUNNING_MODULE_PATH=present\n'
    else
        printf '\nENZIMOS_RUNNING_MODULE_PATH=missing\n'
        cat /run/default-module-path.txt
    fi
    # Explicit retained-root loading proves bytes survive, NOT ordinary autoload support.
    modprobe --dirname /run/update-top/upd-pre --set-version "$OLD_REGULAR" overlay
    [[ -d /sys/module/overlay ]]
    printf '\nENZIMOS_RETAINED_MODULE_LOAD_PASS explicit-snapshot-path\n'
    (cd /boot && sha256sum vmlinuz-* initramfs-*.img) > "$state_dir/new-boot.sha256"
    cat "$state_dir/new-boot.sha256"
    (cd /boot && sha256sum --strict -c "$state_dir/retained.sha256")
    authority_check /etc/pacman.d/gnupg "$state_dir"
    printf 'boot-0\n' > "$state_dir/state"
    select_entry linux 1
    printf '\nENZIMOS_UPDATE_TRANSACTION_PASS full-system-five-upgrades\n'
else
    case "$state" in
        boot-0) expected=$NEW_REGULAR; mode=uefi; next=boot-1; entry=linux-lts; number=2 ;;
        boot-1) expected=$NEW_LTS; mode=uefi; next=boot-2; entry=linux; number=1 ;;
        boot-2) expected=$NEW_REGULAR; mode=bios; next=boot-3; entry=linux-lts; number=2 ;;
        boot-3) expected=$NEW_LTS; mode=bios; next=complete; entry=linux; number=1 ;;
        rollback) expected=$OLD_LTS; mode=bios; next=rollback-complete; entry=linux-lts; number=2 ;;
        *) exit 1 ;;
    esac
    [[ $(uname -r) == "$expected" ]]
    if [[ $mode == uefi ]]; then [[ -d /sys/firmware/efi ]]; else [[ ! -d /sys/firmware/efi ]]; fi
    if [[ $state == rollback ]]; then
        [[ $(findmnt -n -o FSROOT /) == /upd-recovered ]]
        package_check "$state_dir/old-packages.txt"
    else
        [[ $(findmnt -n -o FSROOT /) == /upd-live ]]
        package_check "$state_dir/new-packages.txt"
        (cd /boot && sha256sum --strict -c "$state_dir/new-boot.sha256")
    fi
    [[ $(< /home/update-lab-marker) == home-created-after-update-snapshot ]]
    [[ $(stat -c %u:%g:%a /var/lib/enzimos-lab/metadata) == 12345:12346:640 ]]
    getcap /var/lib/enzimos-lab/capability-probe | grep -q 'cap_net_bind_service=ep$'
    modprobe overlay
    [[ -d /sys/module/overlay ]]
    printf '\nENZIMOS_UPDATE_BOOT_PASS state=%s kernel=%s mode=%s\n' "$state" "$expected" "$mode"
    printf '%s\n' "$next" > "$state_dir/state"
    select_entry "$entry" "$number"
fi
sync
systemctl --no-block poweroff
