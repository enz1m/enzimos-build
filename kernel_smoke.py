#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded diskless direct-kernel diagnostic, not an installed-system or bootloader test."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from contract import Invalid, digest, load
from signed_bootstrap import new_output

PASS = 'ENZIMOS_INITRD_PASS systemd-pid1 btrfs-virtio matching-dm-crypt'
CMDLINE = 'console=ttyS0,115200 rd.systemd.unit=enzimos-initrd-smoke.target rd.systemd.show_status=true panic=5'


def judge(log, code, expected_uname):
    if (code != 0 or 'Kernel panic - not syncing' in log or 'ENZIMOS_INITRD_FAILURE' in log
            or 'Failed to start enzimOS diagnostic' in log):
        raise Invalid('guest failed or panicked')
    lines = {line.strip() for line in log.splitlines()}
    if f'ENZIMOS_INITRD_KERNEL={expected_uname}' not in lines or PASS not in lines:
        raise Invalid('expected kernel/systemd/module checks not observed')
    if 'reboot: Power down' not in log:
        raise Invalid('guest poweroff not observed')
    return {'kernel_initrd_smoke_passed': True, 'systemd_pid1_checked': True,
            'btrfs_virtio_available': True, 'matching_dm_crypt_module_loaded': True,
            'guest_poweroff_observed': True,
            'installed_os_qualified': False, 'bootloader_qualified': False,
            'secure_boot_enforcement_verified': False, 'release_authorized': False}


def command(kernel, initrd):
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib', '/lib64', '--dir', '/etc', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/tmp', '--dir', '/inputs', '--ro-bind', str(kernel), '/inputs/kernel',
            '--ro-bind', str(initrd), '/inputs/initrd', '--setenv', 'PATH', '/usr/bin', '--setenv', 'HOME', '/tmp',
            '--setenv', 'LANG', 'C.UTF-8', '--', '/usr/bin/prlimit', '--cpu=90:90',
            '--as=4294967296:4294967296', '--fsize=8388608:8388608', '--', '/usr/bin/qemu-system-x86_64',
            '-no-user-config', '-nodefaults', '-machine', 'q35', '-accel', 'tcg,thread=single,tb-size=32',
            '-cpu', 'max', '-m', '768M', '-smp', '1', '-nic', 'none', '-display', 'none',
            '-monitor', 'none', '-serial', 'stdio', '-no-reboot', '-kernel', '/inputs/kernel',
            '-initrd', '/inputs/initrd', '-append', CMDLINE]


def run(build_path, flavor, output):
    if os.geteuid() == 0:
        raise Invalid('run diagnostic unprivileged')
    build_path = Path(build_path).resolve(strict=True)
    report = load(build_path)
    if report.get('status') != 'PASS-diagnostic-initrds-built' or flavor not in ('linux', 'linux-lts'):
        raise Invalid('a reviewed diagnostic build and known kernel flavor are required')
    items = [entry for entry in report['kernels'] if entry['flavor'] == flavor]
    if len(items) != 1:
        raise Invalid('kernel flavor is missing or ambiguous')
    item = items[0]
    if not re.fullmatch('[A-Za-z0-9._+-]+', item['uname']):
        raise Invalid('invalid expected kernel identity')
    paths = []
    for key, suffix in (('kernel', '.vmlinuz'), ('initrd', '.img')):
        if item[key] != flavor + suffix:
            raise Invalid('unexpected diagnostic artifact name')
        path = build_path.parent / 'artifacts' / item[key]
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024**2 or digest(path) != item[key + '_sha256']:
            raise Invalid('diagnostic artifact failed hash/type/size check')
        paths.append(path)
    output = new_output(output)
    argv = command(*paths)
    (output / 'command.json').write_text(json.dumps(argv, indent=2) + '\n')
    result = {'status': 'FAIL', 'flavor': flavor, 'uname': item['uname'], 'release_authorized': False,
              'installed_os_qualified': False, 'bootloader_qualified': False, 'secure_boot_enforcement_verified': False}
    started = time.monotonic()
    try:
        with (output / 'serial.log').open('wb') as log, (output / 'stderr.log').open('wb') as errors:
            process = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=errors,
                                     timeout=95, env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
        transcript = (output / 'serial.log').read_text(errors='replace')
        result.update(judge(transcript, process.returncode, item['uname']), status='PASS-direct-kernel-initrd-only',
                      checked_at=datetime.now(timezone.utc).isoformat(), elapsed_seconds=round(time.monotonic() - started, 3),
                      kernel_sha256=item['kernel_sha256'], initrd_sha256=item['initrd_sha256'],
                      serial_sha256=digest(output / 'serial.log'), guest_ram_mib=768, vcpus=1,
                      commandline=CMDLINE, networking=False, disks_attached=False)
        return result
    except BaseException as exc:
        result['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise
    finally:
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--flavor', choices=('linux', 'linux-lts'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.build, args.flavor, args.output), indent=2))
    except (Invalid, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
