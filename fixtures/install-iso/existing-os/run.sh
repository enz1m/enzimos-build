#!/bin/bash
set -euo pipefail
cryptsetup status enzimos-crypt | grep -Eq 'device:[[:space:]]*/dev/vda3$'
grep -qx 'Original system and personal data must survive alongside installation.' /home/admin/alongside-preservation.txt
printf 'ENZIMOS_EXISTING_OS_PASS root=/dev/vda3 personal-data-preserved\n'
systemctl --no-block poweroff
