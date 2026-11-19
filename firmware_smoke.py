#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit, bounded firmware-only QEMU smoke. No OS, host disks or key enrollment."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import time

from contract import Invalid, digest

CODE = Path('/usr/share/edk2/x64/OVMF_CODE.4m.fd')
SECURE_CODE = Path('/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd')
VARS = Path('/usr/share/edk2/x64/OVMF_VARS.4m.fd')
BIOS = Path('/usr/share/qemu/bios-256k.bin')
MODES = ('bios', 'uefi', 'uefi-secure-capable')
MAX_SECONDS = 20


def qemu_argv(mode):
    if mode not in MODES:
        raise Invalid('unsupported firmware smoke mode')
    argv = ['/usr/bin/qemu-system-x86_64', '-no-user-config', '-nodefaults',
            '-machine', 'q35,smm=on', '-accel', 'tcg,thread=single,tb-size=32',
            '-m', '256M', '-smp', '1', '-nic', 'none', '-display', 'none',
            '-serial', 'file:/work/serial.log', '-qmp', 'stdio',
            '-chardev', 'file,id=debug,path=/work/firmware.log',
            '-device', 'isa-debugcon,iobase=0x402,chardev=debug', '-no-reboot']
    if mode == 'bios':
        argv += ['-bios', str(BIOS)]
    else:
        code = SECURE_CODE if mode == 'uefi-secure-capable' else CODE
        argv += ['-drive', f'if=pflash,format=raw,unit=0,readonly=on,file={code}',
                 '-drive', 'if=pflash,format=raw,unit=1,file=/work/vars.fd']
    return argv


def sandbox_argv(mode, output):
    # Only packaged executables/public firmware enter the namespace; no /home,
    # host /dev, environment credentials, KVM, networking or shared directories.
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
            '--clearenv', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib', '/lib64',
            '--dir', '/etc', '--dir', '/home', '--dir', '/home/smoke',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--bind', str(output), '/work', '--chdir', '/work',
            '--setenv', 'HOME', '/home/smoke', '--setenv', 'PATH', '/usr/bin',
            '--setenv', 'LANG', 'C.UTF-8', '--', '/usr/bin/prlimit',
            '--cpu=20:20', '--as=4294967296:4294967296', '--fsize=8388608:8388608', '--',
            *qemu_argv(mode)]


class QMP:
    def __init__(self, process, deadline):
        self.process = process
        self.deadline = deadline
        self.buffer = b''
        self.sequence = 0

    def receive(self):
        while b'\n' not in self.buffer:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise Invalid('QMP response deadline exceeded')
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                raise Invalid('QEMU closed QMP unexpectedly; inspect private stderr log')
            self.buffer += chunk
            if len(self.buffer) > 1024 * 1024:
                raise Invalid('QMP message exceeds bound')
        line, self.buffer = self.buffer.split(b'\n', 1)
        try:
            value = json.loads(line)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise Invalid('invalid QMP JSON') from exc
        if type(value) is not dict:
            raise Invalid('unexpected QMP message')
        return value

    def command(self, name):
        if name not in ('qmp_capabilities', 'query-status', 'quit'):
            raise Invalid('QMP command is outside the smoke allowlist')
        self.sequence += 1
        self.process.stdin.write((json.dumps({'execute': name, 'id': self.sequence}) + '\n').encode())
        self.process.stdin.flush()
        while True:
            value = self.receive()
            if value.get('id') == self.sequence:
                if 'error' in value or 'return' not in value:
                    raise Invalid('QMP command failed')
                return value['return']


def new_output(path):
    path = Path(path).absolute()
    if '..' in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise Invalid('output traversal/symlinks forbidden')
    path = path.resolve(strict=False)
    if path.is_relative_to(Path(__file__).resolve().parent):
        raise Invalid('scratch output must be outside this source repository')
    path.mkdir(mode=0o700, exist_ok=False)
    return path


def run(mode, output):
    if os.geteuid() == 0:
        raise Invalid('run firmware smoke as an unprivileged user, not root')
    if mode not in MODES:
        raise Invalid('unsupported firmware smoke mode')
    inputs = [BIOS] if mode == 'bios' else [SECURE_CODE if mode == 'uefi-secure-capable' else CODE, VARS]
    for path in [Path('/usr/bin/bwrap'), Path('/usr/bin/qemu-system-x86_64'), Path('/usr/bin/prlimit'), *inputs]:
        if not path.is_file() or not path.resolve().is_relative_to('/usr'):
            raise Invalid('required packaged tool/firmware unavailable; nothing installed automatically')
    hashes = {str(path): digest(path.resolve()) for path in inputs}
    output = new_output(output)
    if mode != 'bios':
        shutil.copyfile(VARS, output / 'vars.fd')
        (output / 'vars.fd').chmod(0o600)
    argv = sandbox_argv(mode, output)
    (output / 'command.json').write_text(json.dumps(argv, indent=2) + '\n')
    started = time.monotonic()
    process = None
    result = {'kind': 'firmware-only-emulator-smoke', 'mode': mode, 'status': 'FAIL',
              'started_at': datetime.now(timezone.utc).isoformat(),
              'guest_os_booted': False, 'secure_boot_enforcement_verified': False,
              'factory_trust_verified': False, 'release_qualified': False,
              'hardware_hibernation_verified': False, 'input_sha256': hashes,
              'tooling_source_sha256': {name: digest(Path(__file__).resolve().parent / name)
                                       for name in ('firmware_smoke.py', 'contract.py')}}
    try:
        with (output / 'stderr.log').open('wb') as stderr:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=stderr, start_new_session=True,
                                       env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
            protocol = QMP(process, started + MAX_SECONDS)
            greeting = protocol.receive()
            if type(greeting.get('QMP')) is not dict:
                raise Invalid('missing QMP greeting')
            protocol.command('qmp_capabilities')
            first = protocol.command('query-status')
            if started + MAX_SECONDS - time.monotonic() < 3:
                raise Invalid('insufficient time left for the observation interval')
            time.sleep(3)
            last = protocol.command('query-status')
            if (type(first) is not dict or type(last) is not dict
                    or first.get('running') is not True or last.get('running') is not True):
                raise Invalid('emulator did not remain running')
            protocol.command('quit')
            if process.wait(timeout=max(0.1, started + MAX_SECONDS - time.monotonic())) != 0:
                raise Invalid('emulator did not exit cleanly')
            result['qemu_version'] = greeting['QMP'].get('version')
        if any(digest(Path(path).resolve()) != value for path, value in hashes.items()):
            raise Invalid('packaged firmware input changed during smoke')
        result.update(status='PASS', qmp_responsive=True, clean_exit=True,
                      elapsed_seconds=round(time.monotonic() - started, 3),
                      firmware_console_observed=any((output / name).stat().st_size > 0
                                                    for name in ('serial.log', 'firmware.log')),
                      log_bytes={name: (output / name).stat().st_size for name in ('serial.log', 'firmware.log', 'stderr.log')},
                      limits={'guest_ram_mib': 256, 'vcpus': 1, 'acceleration': 'tcg-single-thread',
                              'cpu_seconds': 20, 'wall_deadline_seconds': MAX_SECONDS,
                              'address_space_bytes': 4294967296, 'per_file_bytes': 8388608},
                      limitations=['no-OS-or-Limine-or-systemd-boot-payload',
                                   'secure-capable-firmware-is-not-enrolled-or-enforcing-firmware',
                                   'no-GPU-no-TPM-no-host-storage-no-network'])
        return result
    except BaseException as exc:
        result['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for pipe in (process.stdin, process.stdout):
                if pipe is not None:
                    pipe.close()
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', required=True, choices=MODES)
    parser.add_argument('--output', required=True, type=Path, help='NEW scratch directory; parent must exist')
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.mode, args.output), indent=2))
    except (Invalid, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__,
                          'release_qualified': False}), file=sys.stderr)
        raise SystemExit(2)
