#!/bin/bash
# Private VM fixture only. Production files are checked before review setup.
set -euo pipefail
exec >/dev/ttyS0 2>&1
systemctl disable enzimos-firstboot-check.service
install -m0755 /run/enzimos-testpayload/check.sh /usr/local/bin/enzimos-console-check
cat >/etc/systemd/system/enzimos-console-check.service <<'EOF'
[Unit]
Description=Private console recovery review assertions
After=multi-user.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/enzimos-console-check
[Install]
WantedBy=graphical.target
EOF
systemctl enable enzimos-console-check.service
python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0,'/usr/lib/enzimos')
import native,root_ownership as birth
with native.operation_lock():
 created=birth.create_fallback('console-review')
 native.publish_boot('/boot','console-review',native.installed_kernels(),native.root_options(Path('/proc/cmdline').read_text().strip(),created['subvolume']))
# Disable the timeout only in this disposable review VM.
p=Path('/boot/EFI/enzimos/refind.conf');p.write_text(p.read_text().replace('timeout 5','timeout 0'))
PY
printf 'ENZIMOS_CONSOLE_REVIEW_READY\n'
systemctl reboot
