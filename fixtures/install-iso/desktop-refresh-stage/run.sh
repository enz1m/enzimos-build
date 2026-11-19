#!/usr/bin/bash
set -euo pipefail
systemctl stop greetd
# Disposable private installed-disk clone only; no credential/home files in the stage.
tar --no-same-owner --no-overwrite-dir -C / -I zstd -xf /run/enzimos-testpayload/desktop-stage.tar.zst
systemd-tmpfiles --create /usr/lib/tmpfiles.d/enzui-greeter.conf
printf '\nENZIMOS_DESKTOP_REFRESH_STAGED\n'
sync
systemctl --no-block reboot
