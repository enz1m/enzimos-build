#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Provision or boot a private fixed-size virtual disk, never host block devices."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import resource
import subprocess
import sys
import time

from contract import Invalid, digest, load
from signed_bootstrap import FREE_FLOOR, new_output

DISK_SIZE = 8 * 1024**3
MAX_LOG = 8 * 1024**2
PROVISION_PASS = 'ENZIMOS_TARGET_PROVISION_PASS packages metadata boot-files'
ROOT_PASS = 'ENZIMOS_ROOT_PASS btrfs packages owners acl xattr capability boot-files dm-crypt'
SEQUENCE = [('uefi', 'linux'), ('uefi', 'linux-lts'), ('bios', 'linux'), ('bios', 'linux-lts')]


def read_log(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_LOG + 1)
    if len(data) > MAX_LOG:
        raise Invalid('VM log exceeded bound')
    return data.decode(errors='replace')


def judge(log, code, phase, uname=None):
    if code != 0 or any(s in log for s in ('Kernel panic - not syncing', 'ENZIMOS_TARGET_FAILURE', 'ENZIMOS_ROOT_FAILURE', 'error: command failed to execute correctly', 'error: failed to commit transaction')):
        raise Invalid('virtual target failed, panicked or had a failed package scriptlet')
    lines = {s.strip() for s in log.splitlines()}
    if phase == -1:
        required = {PROVISION_PASS, 'ENZIMOS_TARGET_PACKAGES=146'}
    elif type(phase) is int and 0 <= phase < len(SEQUENCE):
        required = {ROOT_PASS, f'ENZIMOS_ROOT_KERNEL={uname}', f'ENZIMOS_ROOT_MODE={SEQUENCE[phase][0]}', f'ENZIMOS_ROOT_PHASE={phase}'}
    else:
        raise Invalid('invalid VM test phase')
    if not required <= lines or 'reboot: Power down' not in log:
        raise Invalid('required exact markers and guest poweroff were not observed')


def kvm_available():
    """User-approved 2026-09-27: KVM acceleration when /dev/kvm is usable (nested KVM on this
    host); same 1 vCPU/2 GiB/prlimit/nice/idle-I/O/one-at-a-time limits. TCG otherwise."""
    import os,stat as st
    try:info=os.stat('/dev/kvm')
    except OSError:return False
    return st.S_ISCHR(info.st_mode) and os.access('/dev/kvm',os.R_OK|os.W_OK)


def accel():
    return ['-accel','kvm'] if kvm_available() else ['-accel','tcg,thread=single,tb-size=32']


def sandbox(output):
    kvm=['--dev-bind','/dev/kvm','/dev/kvm'] if kvm_available() else []
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib', '/lib64', '--dir', '/etc', '--proc', '/proc', '--dev', '/dev', *kvm,
            '--tmpfs', '/tmp', '--bind', str(output), '/work', '--setenv', 'PATH', '/usr/bin',
            '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'HOME', '/tmp']


def command(output, mode, inputs=None):
    if mode not in ('provision', 'uefi', 'bios'):
        raise Invalid('unknown fixed VM mode')
    argv = sandbox(output)
    if mode == 'provision':
        for name in ('kernel', 'provision.img', 'payload.iso'):
            argv += ['--ro-bind', str(inputs / name), '/inputs/' + name]
    cpu = 1200 if mode == 'provision' else 420
    argv += ['--', '/usr/bin/prlimit', f'--cpu={cpu}:{cpu}', '--as=6442450944:6442450944',
             f'--fsize={DISK_SIZE}:{DISK_SIZE}', '--', '/usr/bin/qemu-system-x86_64',
             '-no-user-config', '-nodefaults', '-machine', 'q35', *accel(),
             '-cpu', 'max', '-smp', '1', '-m', '2048M', '-nic', 'none', '-display', 'none', '-device', 'VGA',
             '-monitor', 'none', '-serial', 'stdio', '-no-reboot', '-boot', 'order=c,strict=on',
             '-drive', 'if=none,id=target,format=qcow2,file=/work/target.qcow2',
             '-device', 'virtio-blk-pci,drive=target,serial=enzimos-lab-target']
    if mode == 'uefi':
        argv += ['-drive', 'if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd',
                 '-drive', 'if=pflash,unit=1,format=raw,file=/work/vars.fd']
    else:
        argv += ['-bios', '/usr/share/qemu/bios-256k.bin']
    if mode == 'provision':
        argv += ['-drive', 'if=none,id=payload,format=raw,readonly=on,file=/inputs/payload.iso',
                 '-device', 'virtio-blk-pci,drive=payload,serial=enzimos-lab-payload',
                 '-kernel', '/inputs/kernel', '-initrd', '/inputs/provision.img', '-append',
                 'console=ttyS0,115200 rd.systemd.unit=enzimos-target-provision.target systemd.log_color=no panic=5']
    return argv


def disk_info(output):
    args = sandbox(output) + ['--', '/usr/bin/prlimit', '--cpu=10:10', '--as=1073741824:1073741824', '--',
                             '/usr/bin/qemu-img', 'info', '-f', 'qcow2', '--output=json', '/work/target.qcow2']
    raw = subprocess.run(args, check=True, capture_output=True, timeout=15).stdout
    info = json.loads(raw)
    if info.get('format') != 'qcow2' or info.get('virtual-size') != DISK_SIZE or info.get('backing-filename') or info.get('encrypted'):
        raise Invalid('only fixed-size self-contained unencrypted disposable qcow2 is allowed')
    (output / 'disk-info.json').write_bytes(raw)


def run(inputs_path, output, previous=None):
    if os.geteuid() == 0:
        raise Invalid('run unprivileged')
    inputs_path = Path(inputs_path).resolve(strict=True)
    manifest = load(inputs_path); inputs = inputs_path.parent
    if manifest.get('status') != 'PASS-offline-target-inputs' or manifest.get('package_count') != 146:
        raise Invalid('reviewed offline inputs required')
    for name, maximum in (('payload.iso', 1024**3), ('kernel', 128 * 1024**2), ('provision.img', 192 * 1024**2)):
        p = inputs / name; item = manifest['inputs'][name]
        if p.is_symlink() or not p.is_file() or not 0 < p.stat().st_size <= maximum or p.stat().st_size != item['bytes'] or digest(p) != item['sha256']:
            raise Invalid('input size/type/hash mismatch')
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR + DISK_SIZE:
        raise Invalid('insufficient free space for one bounded virtual disk')
    output = new_output(output)
    result = {'status': 'FAIL', 'release_authorized': False, 'secure_boot_qualified': False,
              'hibernation': 'deferred-for-now', 'product_installation_qualified': False,
              'networking': False, 'private_keys_created': False, 'guest_ram_mib': 2048, 'vcpus': 1}
    process = None
    cpu_start = None
    started = time.monotonic()
    try:
        if previous is None:
            phase = -1; mode = 'provision'; uname = None
            argv = sandbox(output) + ['--', '/usr/bin/qemu-img', 'create', '-f', 'qcow2', '/work/target.qcow2', str(DISK_SIZE)]
            subprocess.run(argv, check=True, stdout=subprocess.DEVNULL, timeout=15)
        else:
            previous = Path(previous).resolve(strict=True)
            prior = load(previous)
            if prior.get('status') != 'PASS-disposable-target-phase' or prior['inputs_manifest_sha256'] != digest(inputs_path):
                raise Invalid('successful phase with unchanged inputs required')
            phase = prior['phase'] + 1
            if type(phase) is not int or not 0 <= phase < len(SEQUENCE):
                raise Invalid('four-boot sequence is complete or invalid')
            mode, flavor = SEQUENCE[phase]
            uname = next(k['uname'] for k in manifest['kernels'] if k['flavor'] == flavor)
            source = previous.parent / 'target.qcow2'
            if source.is_symlink() or not source.is_file() or source.stat().st_size > DISK_SIZE or digest(source) != prior['disk_sha256']:
                raise Invalid('source disk changed or is not a bounded regular file')
            shutil.copyfile(source, output / 'target.qcow2')
            result['previous_result_sha256'] = digest(previous)
        disk_info(output)
        if mode == 'uefi':
            template = Path('/usr/share/edk2/x64/OVMF_VARS.4m.fd')
            shutil.copyfile(template, output / 'vars.fd')
            result['initial_vars_sha256'] = digest(template)
        argv = command(output, mode, inputs)
        (output / 'command.json').write_text(json.dumps(argv, indent=2) + '\n')
        result.update(phase=phase, mode=mode, uname=uname, inputs_manifest_sha256=digest(inputs_path))
        with (output / 'serial.log').open('wb') as log, (output / 'stderr.log').open('wb') as errors:
            cpu_start = resource.getrusage(resource.RUSAGE_CHILDREN)
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=errors,
                                       env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
            deadline = time.monotonic() + (1250 if mode == 'provision' else 450)
            while process.poll() is None:
                if time.monotonic() > deadline or any((output / n).stat().st_size > MAX_LOG for n in ('serial.log', 'stderr.log')):
                    raise Invalid('VM time/log bound reached')
                if shutil.disk_usage(output).free < FREE_FLOOR:
                    raise Invalid('free-space floor reached; stopping disposable VM')
                time.sleep(0.25)
        result['process_returncode'] = process.returncode
        if (output / 'stderr.log').stat().st_size > MAX_LOG:
            raise Invalid('VM stderr exceeded bound')
        transcript = read_log(output / 'serial.log')
        judge(transcript, process.returncode, phase, uname)
        disk_info(output)
        result.update(status='PASS-disposable-target-phase', checked_at=datetime.now(timezone.utc).isoformat(),
                      elapsed_seconds=round(time.monotonic() - started, 3), disk_sha256=digest(output / 'target.qcow2'),
                      serial_sha256=digest(output / 'serial.log'), disk_bytes=(output / 'target.qcow2').stat().st_size,
                      package_install_in_guest=(phase == -1), persistent_root_boot_observed=(phase >= 0))
        return result
    except BaseException as exc:
        result['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=3)
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
        if process is not None:
            result['process_returncode'] = process.returncode
        if cpu_start is not None:
            usage = resource.getrusage(resource.RUSAGE_CHILDREN)
            result['child_cpu_seconds'] = round(usage.ru_utime + usage.ru_stime - cpu_start.ru_utime - cpu_start.ru_stime, 3)
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--previous', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.inputs, args.output, args.previous), indent=2))
    except (Invalid, OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
