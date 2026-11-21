#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Add a reviewed IPTS driver and daemon to a private installer desktop stage."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess

from contract import Invalid

IPTS_UUID = '3e8d0870-271a-4208-8eb5-9acb9402ae04'
LIB = 'usr/lib/enzimos-surface-touch'
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
UNIT = '''[Unit]
Description=Intel Precise Touch and Stylus driver
ConditionPathExists=/usr/lib/enzimos-surface-touch/%v/ipts.ko
ConditionPathExists=!/sys/module/ipts

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/bin/modprobe hid
ExecStartPre=/usr/bin/modprobe uinput
ExecStart=/usr/bin/insmod /usr/lib/enzimos-surface-touch/%v/ipts.ko
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SYS_MODULE
'''


def stage(destination, module, daemon, kernel_release):
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){2}-(?:arch[0-9]+-[0-9]+|[0-9]+-lts)', kernel_release):
        raise Invalid('exact Arch kernel release required for IPTS')
    if module.is_symlink() or not module.is_file() or not 0 < module.stat().st_size < MAX_FILE_BYTES:
        raise Invalid('regular IPTS kernel module required')

    def modinfo(field):
        return subprocess.check_output(['modinfo', '-F', field, module], text=True, timeout=10).strip()

    if (modinfo('name') != 'ipts' or modinfo('vermagic').partition(' ')[0] != kernel_release
            or IPTS_UUID not in modinfo('alias').lower()):
        raise Invalid('IPTS module identity or ABI differs from this kernel')

    module_path = f'{LIB}/{kernel_release}/ipts.ko'
    inputs = {name: daemon/name for name in DAEMON}
    inputs[module_path] = module
    for name, source in inputs.items():
        if source.is_symlink() or not source.is_file() or not 0 < source.stat().st_size < MAX_FILE_BYTES:
            raise Invalid(f'missing or unsafe IPTS input {name}')

    rule = f'{UDEV}/70-enzimos-surface-touch.rules'
    unit = f'{SYSTEMD}/enzimos-surface-touch.service'
    generated = {
        rule: (
            f'ACTION=="add", SUBSYSTEM=="mei", ENV{{MEI_CL_UUID}}=="{IPTS_UUID}", '
            'TAG+="systemd", ENV{SYSTEMD_WANTS}+="enzimos-surface-touch.service"\n'
        ),
        unit: UNIT,
    }
    destination = destination.resolve(strict=True)
    for name in (*inputs, *generated):
        target = destination/name
        if not target.resolve().is_relative_to(destination) or target.exists() or target.is_symlink():
            raise Invalid(f'IPTS stage would replace an existing or external path {name}')
    for name, source in inputs.items():
        target = destination/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o755 if name.startswith('usr/bin/') else 0o644)
    for name, content in generated.items():
        target = destination/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        target.chmod(0o644)
    return (*inputs, *generated)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('desktop_stage', type=Path)
    parser.add_argument('--module', required=True, type=Path)
    parser.add_argument('--iptsd-stage', required=True, type=Path)
    parser.add_argument('--kernel-release', required=True)
    args = parser.parse_args()
    for added in stage(args.desktop_stage, args.module, args.iptsd_stage, args.kernel_release):
        print(added)
