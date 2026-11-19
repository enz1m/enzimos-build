#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed headless full-update and deliberate guest-interruption experiment."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

from contract import Invalid, digest, load
from encrypted_vm import ConsoleResponse
from signed_bootstrap import FREE_FLOOR, new_output
from target_vm import command as base_command, disk_info, read_log, MAX_LOG
from update_inputs import SOURCE_HASH

FILE_CAP = 2 * 1024**3
CUT = 'ENZIMOS_UPDATE_CUT_READY upgraded-linux transaction-incomplete'
RECOVER = 'ENZIMOS_UPDATE_RECOVERY_PASS interrupted-transaction old-root-and-boot current-authority newer-home header-bytes'
NEXT = {'setup': 'update', 'update': 'boot-0', 'boot-0': 'boot-1', 'boot-1': 'boot-2', 'boot-2': 'boot-3'}


def next_action(previous, scenario):
    if scenario not in ('success', 'interrupt'):
        raise Invalid('unknown fixed scenario')
    if previous is None:
        return 'setup'
    if scenario == 'interrupt':
        transitions = {'setup': 'update', 'update': 'recovery', 'recovery': 'rollback'}
    elif scenario == 'success':
        transitions = NEXT
    else:
        raise Invalid('unknown fixed scenario')
    if previous not in transitions:
        raise Invalid('scenario complete or invalid transition')
    return transitions[previous]


def command(output, inputs, action, scenario):
    if scenario not in ('success', 'interrupt') or action not in ('setup', 'update', 'boot-0', 'boot-1', 'boot-2', 'boot-3', 'recovery', 'rollback'):
        raise Invalid('unknown fixed update action/scenario')
    mode = 'provision' if action == 'setup' else ('bios' if action in ('boot-2', 'boot-3', 'rollback') else 'uefi')
    args = base_command(output, mode, inputs)
    cpu = 1500 if action == 'update' else 600
    args = [f'--cpu={cpu}:{cpu}' if a.startswith('--cpu=') else f'--fsize={FILE_CAP}:{FILE_CAP}' if a.startswith('--fsize=') else str(inputs / 'setup.img') if a == str(inputs / 'provision.img') else a for a in args]
    if action == 'setup':
        args[-1] += ' enzimos.scenario=' + scenario
    if action == 'update':
        args[args.index('--'):args.index('--')] = ['--ro-bind', str(inputs / 'payload.iso'), '/inputs/payload.iso']
        args += ['-drive', 'if=none,id=payload,format=raw,readonly=on,file=/inputs/payload.iso',
                 '-device', 'virtio-blk-pci,drive=payload,serial=enzimos-lab-payload']
        if scenario == 'interrupt':
            args += ['-qmp', 'unix:/work/qmp.sock,server=on,wait=off']
    return args, mode


def qmp_quit(path):
    events = []
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5); sock.connect(str(path))
        stream = sock.makefile('rwb', buffering=0)
        def receive():
            line = stream.readline(8193)
            if not line or len(line) > 8192:
                raise Invalid('missing or oversized QMP reply')
            return json.loads(line)
        greeting = receive()
        if 'QMP' not in greeting:
            raise Invalid('invalid QMP greeting')
        for command_name in ('qmp_capabilities', 'quit'):
            stream.write((json.dumps({'execute': command_name, 'id': command_name}) + '\n').encode())
            for _ in range(20):
                reply = receive()
                if 'event' in reply:
                    events.append(reply)
                if reply.get('id') == command_name:
                    if 'error' in reply or 'return' not in reply:
                        raise Invalid('QMP command failed')
                    break
            else:
                raise Invalid('QMP response budget exceeded')
    return {'greeting': greeting, 'events': events, 'commands': ['qmp_capabilities', 'quit'],
            'meaning': 'emulator exit without guest shutdown, after explicit sync; not physical power loss'}


def judge(text, code, action, scenario, kernels, response_sent, cut_requested=False):
    if scenario not in ('success', 'interrupt') or action not in ('setup', 'update', 'boot-0', 'boot-1', 'boot-2', 'boot-3', 'recovery', 'rollback'):
        raise Invalid('unknown fixed update action/scenario')
    if code != 0 or 'ENZIMOS_UPDATE_FAILURE' in text or 'Kernel panic - not syncing' in text:
        raise Invalid('guest update experiment failed')
    lines = {line.strip() for line in text.splitlines()}
    if action == 'setup':
        required = {'ENZIMOS_UPDATE_SETUP_PASS scenario=' + scenario}
    else:
        if not response_sent:
            raise Invalid('console unlock was not observed')
        if action == 'update' and scenario == 'interrupt':
            if CUT not in lines or not cut_requested or 'reboot: Power down' in text or '[ALPM] transaction completed' in text:
                raise Invalid('not the intended in-transaction guest interruption')
            return
        if action == 'update':
            required = {'ENZIMOS_UPDATE_TRANSACTION_PASS full-system-five-upgrades', 'ENZIMOS_RETAINED_MODULE_LOAD_PASS explicit-snapshot-path'}
        elif action == 'recovery':
            required = {RECOVER, 'ENZIMOS_UPDATE_RECOVERY_RAM_STARTED root-locked'}
        else:
            which = 'linux-lts' if action in ('boot-1', 'boot-3', 'rollback') else 'linux'
            mode = 'bios' if action in ('boot-2', 'boot-3', 'rollback') else 'uefi'
            version = kernels['old' if action == 'rollback' else 'new'][which]
            required = {f'ENZIMOS_UPDATE_BOOT_PASS state={action} kernel={version} mode={mode}'}
    if not required <= lines or 'reboot: Power down' not in text:
        raise Invalid('required exact phase markers or poweroff missing')


def run(inputs_path, scenario, output, previous=None):
    if os.geteuid() == 0 or scenario not in ('success', 'interrupt'):
        raise Invalid('unprivileged fixed scenario required')
    inputs_path = Path(inputs_path).resolve(strict=True); inputs = inputs_path.parent
    manifest = load(inputs_path); manifest_hash = digest(inputs_path)
    if manifest['status'] != 'PASS-full-update-inputs' or manifest['source_image_sha256'] != SOURCE_HASH:
        raise Invalid('current reviewed update inputs required')
    for name in ('kernel', 'setup.img', 'recovery.img', 'payload.iso'):
        p = inputs / name; item = manifest['inputs'][name]
        if p.is_symlink() or not p.is_file() or not 0 < p.stat().st_size <= 1024**3 or p.stat().st_size != item['bytes'] or digest(p) != item['sha256']:
            raise Invalid('input artifact changed')
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR + FILE_CAP + 64 * 1024**2:
        raise Invalid('insufficient bounded copy/write headroom')
    output = new_output(output); process = None; started = time.monotonic()
    result = {'status': 'FAIL', 'scenario': scenario, 'release_authorized': False,
              'secure_boot_qualified': False, 'physical_power_loss_qualified': False,
              'ui_qualified': False, 'hibernation': 'deferred-for-now',
              'disk_file_cap_bytes': FILE_CAP, 'virtual_disk_bytes': 8 * 1024**3,
              'guest_ram_mib': 2048, 'vcpus': 1, 'networking': False}
    try:
        if previous is None:
            action = 'setup'; source = Path(manifest['source_image']); expected = SOURCE_HASH
        else:
            previous = Path(previous).resolve(strict=True); prior = load(previous)
            if prior['status'] != 'PASS-update-lab-phase' or prior['scenario'] != scenario or prior['inputs_manifest_sha256'] != manifest_hash:
                raise Invalid('incompatible or failed previous phase')
            action = next_action(prior['action'], scenario)
            source = previous.parent / 'target.qcow2'; expected = prior['disk_sha256']
            result['previous_result_sha256'] = digest(previous)
        if source.is_symlink() or not source.is_file() or source.stat().st_size > FILE_CAP or digest(source) != expected:
            raise Invalid('source disk changed or exceeds file budget')
        shutil.copyfile(source, output / 'target.qcow2')
        if digest(output / 'target.qcow2') != expected:
            raise Invalid('image copy mismatch')
        disk_info(output)
        args, mode = command(output, inputs, action, scenario)
        if mode == 'uefi':
            template = Path('/usr/share/edk2/x64/OVMF_VARS.4m.fd')
            shutil.copyfile(template, output / 'vars.fd')
            result['initial_vars_sha256'] = digest(template)
        (output / 'command.json').write_text(json.dumps(args, indent=2) + '\n')
        result.update(action=action, mode=mode, inputs_manifest_sha256=manifest_hash)
        response = ConsoleResponse(action == 'recovery'); cut_requested = False
        with (output / 'serial.log').open('wb') as serial, (output / 'stderr.log').open('wb') as errors:
            process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=serial, stderr=errors, env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
            deadline = time.monotonic() + (1550 if action == 'update' else 650)
            while process.poll() is None:
                if time.monotonic() > deadline or (output / 'stderr.log').stat().st_size > MAX_LOG:
                    raise Invalid('VM time/log bound reached')
                if shutil.disk_usage(output).free < FREE_FLOOR:
                    raise Invalid('free-space floor reached')
                text = read_log(output / 'serial.log')
                if action != 'setup':
                    value = response.next(text)
                    if value is not None:
                        process.stdin.write(value); process.stdin.flush()
                if action == 'update' and scenario == 'interrupt' and CUT in {line.strip() for line in text.splitlines()} and not cut_requested:
                    qmp = qmp_quit(output / 'qmp.sock')
                    (output / 'qmp.json').write_text(json.dumps(qmp, indent=2) + '\n')
                    cut_requested = True
                time.sleep(0.25)
        if (output / 'stderr.log').stat().st_size > MAX_LOG:
            raise Invalid('VM stderr exceeded bound')
        text = read_log(output / 'serial.log')
        judge(text, process.returncode, action, scenario, {'old': manifest['old_kernels'], 'new': manifest['new_kernels']}, response.sent, cut_requested)
        disk_info(output)
        if digest(inputs_path) != manifest_hash or digest(source) != expected:
            raise Invalid('input/parent changed during VM execution')
        result.update(status='PASS-update-lab-phase', checked_at=datetime.now(timezone.utc).isoformat(),
                      console_response_sent=response.sent, cut_requested=cut_requested,
                      disk_sha256=digest(output / 'target.qcow2'), disk_bytes=(output / 'target.qcow2').stat().st_size,
                      serial_sha256=digest(output / 'serial.log'),
                      ordinary_running_module_path_missing=('ENZIMOS_RUNNING_MODULE_PATH=missing' in text) if 'ENZIMOS_RUNNING_MODULE_PATH=' in text else None)
        return result
    except BaseException as exc:
        result['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=3)
        if process is not None:
            result['process_returncode'] = process.returncode
            try: process.stdin.close()
            except OSError: pass
        result['elapsed_seconds'] = round(time.monotonic() - started, 3)
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inputs', type=Path, required=True)
    p.add_argument('--scenario', choices=('success', 'interrupt'), required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--previous', type=Path)
    a = p.parse_args()
    try:
        print(json.dumps(run(a.inputs, a.scenario, a.output, a.previous), indent=2))
    except (Invalid, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
