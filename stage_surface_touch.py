#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Add the IPTS userspace daemon to a private installer desktop stage."""
import argparse
from pathlib import Path
import shutil

from contract import Invalid

SYSTEMD = 'usr/lib/systemd/system'
UDEV = 'usr/lib/udev/rules.d'
MAX_FILE_BYTES = 8 * 1024**2
DAEMON = (
    'usr/bin/iptsd',
    'usr/bin/iptsd-check-device',
    f'{SYSTEMD}/iptsd@.service',
    f'{UDEV}/50-iptsd.rules',
    'usr/share/iptsd/surface-laptop-1+2.conf',
)


def stage(destination, daemon):
    inputs = {name: daemon/name for name in DAEMON}
    destination = destination.resolve(strict=True)
    for name, source in inputs.items():
        if source.is_symlink() or not source.is_file() or not 0 < source.stat().st_size < MAX_FILE_BYTES:
            raise Invalid(f'missing or unsafe IPTS input {name}')
        target = destination/name
        if not target.resolve().is_relative_to(destination) or target.exists() or target.is_symlink():
            raise Invalid(f'IPTS stage would replace an existing or external path {name}')
    for name, source in inputs.items():
        target = destination/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o755 if name.startswith('usr/bin/') else 0o644)
    return DAEMON


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('desktop_stage', type=Path)
    parser.add_argument('--iptsd-stage', required=True, type=Path)
    args = parser.parse_args()
    for added in stage(args.desktop_stage, args.iptsd_stage):
        print(added)
