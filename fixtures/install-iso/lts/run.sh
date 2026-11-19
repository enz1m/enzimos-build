#!/bin/bash
set -euo pipefail
[[ $(uname -r) == *-lts ]]
printf 'ENZIMOS_LTS_PASS kernel=%s\n' "$(uname -r)"
systemctl --no-block poweroff
