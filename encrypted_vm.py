#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed offline LUKS2/recovery VM sequence with public fixture console responses."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

from contract import Invalid, digest, load
from encrypted_inputs import PRIMARY, RECOVERY, SOURCE_HASH
from signed_bootstrap import FREE_FLOOR, new_output
from target_vm import command as base_command, disk_info, sandbox, DISK_SIZE, MAX_LOG

SEQUENCE = [('uefi', 'linux'), ('uefi', 'linux-lts'), ('bios', 'linux'), ('bios', 'linux-lts'),
            ('uefi', 'recovery'), ('bios', 'recovery'), ('uefi', 'linux'), ('bios', 'linux-lts')]
PROVISION_PASS = 'ENZIMOS_CRYPT_PROVISION_PASS luks2 argon2id two-keyslots migrated-146'
ROOT_PASS = 'ENZIMOS_CRYPT_ROOT_PASS mapped-root packages metadata home boot-files'
RECOVERY_PASS = 'ENZIMOS_RECOVERY_PASS broken-root snapshot-restored home-preserved header-unchanged'


def read_log(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_LOG + 1)
    if len(data) > MAX_LOG:
        raise Invalid('VM log exceeded bound')
    return data.decode(errors='replace')


class ConsoleResponse:
    def __init__(self, recovery=False):
        self.recovery = recovery
        self.sent = False

    def next(self, text):
        pattern = 'ENZIMOS recovery passphrase:' if self.recovery else r'Please enter passphrase for disk'
        if not self.sent and re.search(pattern, text, re.IGNORECASE):
            self.sent = True
            return (RECOVERY if self.recovery else PRIMARY).encode() + b'\n'
        return None


def judge(text, code, phase, uname=None, response_sent=False):
    if type(phase) is not int or phase not in range(-1, 8):
        raise Invalid('invalid encrypted lab phase')
    if code != 0 or 'ENZIMOS_CRYPT_FAILURE' in text or 'Kernel panic - not syncing' in text:
        raise Invalid('encrypted guest failed or panicked')
    lines = {s.strip() for s in text.splitlines()}
    if phase == -1:
        required = {PROVISION_PASS, 'ENZIMOS_CRYPT_KEYS_PASS wrong-rejected recovery-accepted'}
    else:
        if not response_sent:
            raise Invalid('no observed console passphrase interaction')
        required = {f'ENZIMOS_CRYPT_MODE={SEQUENCE[phase][0]}', f'ENZIMOS_CRYPT_PHASE={phase}'}
        if phase in (4, 5):
            required |= {RECOVERY_PASS, 'ENZIMOS_RECOVERY_RAM_STARTED root-still-locked'}
        else:
            required |= {ROOT_PASS, f'ENZIMOS_CRYPT_KERNEL={uname}'}
    if not required <= lines or 'reboot: Power down' not in text:
        raise Invalid('required exact encryption/recovery markers or poweroff missing')


def command(output, mode, inputs, source=None):
    args = base_command(output, mode, inputs)
    if source is not None:
        if mode != 'provision':
            raise Invalid('read-only source belongs only to provisioning')
        index = args.index('--')
        args[index:index] = ['--ro-bind', str(source), '/inputs/source.qcow2']
        args += ['-drive', 'if=none,id=source,format=qcow2,readonly=on,file=/inputs/source.qcow2',
                 '-device', 'virtio-blk-pci,drive=source,serial=enzimos-lab-source']
    # LUKS calibration and full root startup are bounded, not disabled for speed.
    cpu = 1200 if mode == 'provision' else 600
    args = [f'--cpu={cpu}:{cpu}' if a.startswith('--cpu=') else a for a in args]
    return args


def run(inputs_path, output, previous=None):
    if os.geteuid() == 0:
        raise Invalid('run unprivileged')
    inputs_path = Path(inputs_path).resolve(strict=True); inputs = inputs_path.parent
    manifest = load(inputs_path); manifest_hash = digest(inputs_path)
    if manifest.get('status') != 'PASS-encrypted-lab-inputs' or manifest.get('source_image_sha256') != SOURCE_HASH:
        raise Invalid('pinned encrypted experiment inputs required')
    for name in ('kernel', 'provision.img', 'recovery.img', 'payload.iso'):
        path = inputs / name; item = manifest['inputs'][name]
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 1024**3 or path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
            raise Invalid('input artifact changed')
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR + DISK_SIZE:
        raise Invalid('insufficient disposable disk headroom')
    output = new_output(output)
    report = {'status': 'FAIL', 'release_authorized': False, 'secure_boot_qualified': False,
              'real_package_update_tested': False, 'ui_qualified': False, 'hibernation': 'deferred-for-now',
              'guest_ram_mib': 2048, 'vcpus': 1, 'networking': False,
              'credential_scope': 'public-fixture-only; guest-volume-keys-not-production-signing'}
    process = None; started = time.monotonic()
    try:
        source = None
        if previous is None:
            phase = -1; mode = 'provision'; flavor = None; uname = None
            source = Path(manifest['source_image'])
            if source.is_symlink() or not source.is_file() or digest(source) != SOURCE_HASH:
                raise Invalid('pinned read-only source image changed')
            subprocess.run(sandbox(output) + ['--', '/usr/bin/qemu-img', 'create', '-f', 'qcow2', '/work/target.qcow2', str(DISK_SIZE)], check=True, timeout=15, stdout=subprocess.DEVNULL)
        else:
            previous = Path(previous).resolve(strict=True); prior = load(previous)
            if prior.get('status') != 'PASS-encrypted-lab-phase' or prior['inputs_manifest_sha256'] != manifest_hash or type(prior['phase']) is not int:
                raise Invalid('valid previous phase with same inputs required')
            phase = prior['phase'] + 1
            if phase not in range(8):
                raise Invalid('encrypted sequence complete or invalid')
            mode, flavor = SEQUENCE[phase]
            uname = None if flavor == 'recovery' else next(k['uname'] for k in manifest['kernels'] if k['flavor'] == flavor)
            disk = previous.parent / 'target.qcow2'
            if disk.is_symlink() or not disk.is_file() or disk.stat().st_size > DISK_SIZE or digest(disk) != prior['disk_sha256']:
                raise Invalid('prior private disk changed')
            shutil.copyfile(disk, output / 'target.qcow2')
            if digest(output / 'target.qcow2') != prior['disk_sha256']:
                raise Invalid('copy does not match source disk')
            report['previous_result_sha256'] = digest(previous)
        disk_info(output)
        if mode == 'uefi':
            template = Path('/usr/share/edk2/x64/OVMF_VARS.4m.fd')
            shutil.copyfile(template, output / 'vars.fd')
            report['initial_vars_sha256'] = digest(template)
        args = command(output, mode, inputs, source)
        (output / 'command.json').write_text(json.dumps(args, indent=2) + '\n')
        report.update(phase=phase, mode=mode, flavor=flavor, uname=uname, inputs_manifest_sha256=manifest_hash)
        response = ConsoleResponse(flavor == 'recovery')
        with (output / 'serial.log').open('wb') as serial, (output / 'stderr.log').open('wb') as errors:
            process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=serial, stderr=errors, env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
            deadline = time.monotonic() + (1250 if phase == -1 else 650)
            while process.poll() is None:
                if time.monotonic() > deadline or any((output / name).stat().st_size > MAX_LOG for name in ('serial.log', 'stderr.log')):
                    raise Invalid('VM time/log bound reached')
                if shutil.disk_usage(output).free < FREE_FLOOR:
                    raise Invalid('free-space floor reached')
                if phase >= 0:
                    value = response.next(read_log(output / 'serial.log'))
                    if value is not None:
                        process.stdin.write(value); process.stdin.flush()
                time.sleep(0.25)
        if (output / 'stderr.log').stat().st_size > MAX_LOG:
            raise Invalid('VM stderr exceeded bound')
        text = read_log(output / 'serial.log')
        judge(text, process.returncode, phase, uname, response.sent)
        if digest(inputs_path) != manifest_hash or (source and digest(source) != SOURCE_HASH):
            raise Invalid('input manifest or read-only source changed')
        disk_info(output)
        report.update(status='PASS-encrypted-lab-phase', checked_at=datetime.now(timezone.utc).isoformat(),
                      console_response_sent=response.sent, disk_sha256=digest(output / 'target.qcow2'),
                      disk_bytes=(output / 'target.qcow2').stat().st_size, serial_sha256=digest(output / 'serial.log'))
        return report
    except BaseException as exc:
        report['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=3)
        if process is not None:
            report['process_returncode'] = process.returncode
            try:
                process.stdin.close()
            except OSError:
                pass
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--previous', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.inputs, args.output, args.previous), indent=2))
    except (Invalid, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
