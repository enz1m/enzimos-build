#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit new scratch checkpoint of a verified lab chain; never edit old images."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from contract import Invalid, digest, load
from foundation_overlay_vm import ancestry_bindings, clone_file, inspect, pinned_file
from foundation_vm import backup_info
from lab_resources import constrain_job
from signed_bootstrap import FREE_FLOOR, new_output
from target_vm import sandbox

CAP = 3*1024**3
RESERVE = CAP+128*1024**2
LOG_CAP = 1024**2


def command_guard(output):
    if shutil.disk_usage(output).free < FREE_FLOOR+32*1024**2:
        raise Invalid('checkpoint runtime free-space floor')
    for path in Path(output).iterdir():
        if path.suffix in ('.stdout', '.stderr') and path.stat().st_size >= LOG_CAP:
            raise Invalid('checkpoint runtime log bound')
    image = Path(output)/'target.qcow2'
    if image.exists() and image.stat().st_size >= CAP:raise Invalid('checkpoint root cap reached')


def run_command(args, output, label, timeout):
    # These are fixed qemu-img/bubblewrap children, never caller-selected process
    # IDs. Stopping the launcher tears down its private PID namespace as well.
    command_guard(output)
    child = None;deadline = time.monotonic()+timeout
    try:
        with (output/(label+'.stdout')).open('wb') as stdout, (output/(label+'.stderr')).open('wb') as stderr:
            child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                     env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
            while child.poll() is None:
                command_guard(output)
                if time.monotonic() >= deadline:raise Invalid('checkpoint command deadline')
                time.sleep(0.05)
            command_guard(output)
            if child.returncode:raise Invalid('checkpoint '+label+' failed')
        return (output/(label+'.stdout')).read_bytes()
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:child.wait(timeout=3)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)


def sources(previous):
    previous = Path(previous).resolve(strict=True);report = load(previous)
    if report.get('status') != 'PASS-foundation-overlay-phase':raise Invalid('successful overlay required for checkpoint')
    rows = list(report['parents'])
    if not 1 <= len(rows) <= 12:raise Invalid('checkpoint ancestry bound')
    rows.append({'path': str(previous.parent/'target.qcow2'), 'sha256': report['disk_sha256'], 'bytes': report['disk_bytes']})
    for row in rows:
        path = pinned_file(row['path'], row['sha256'], CAP)
        if path.stat().st_size != row['bytes']:raise Invalid('checkpoint source byte count changed')
    return previous, report, rows


def checkpoint(previous, inputs, output):
    if os.geteuid() == 0:raise Invalid('unprivileged checkpoint required')
    resources = constrain_job(cpu_limit=8)
    inputs = Path(inputs).resolve(strict=True);manifest = load(inputs)
    previous, prior, rows = sources(previous)
    if (manifest.get('status') != 'PASS-foundation-inputs' or
        prior['inputs_manifest_sha256'] != digest(inputs)):
        raise Invalid('same unexpired checkpoint inputs required')
    parent_hash = digest(previous);input_hash = digest(inputs)
    output = Path(output).absolute()
    if shutil.disk_usage(output.parent).free < FREE_FLOOR+RESERVE:raise Invalid('checkpoint headroom')
    backup = pinned_file(previous.parent/'backup.qcow2', prior['backup_sha256'], 2112*1024**2)
    out = new_output(output)
    report = {'status': 'FAIL', 'case': 'checkpoint', 'checkpoint_source_result_sha256': parent_hash,
              'inputs_manifest_sha256': input_hash, 'checkpoint_parents': rows,
              'host_resource_policy': resources, 'release_authorized': False, 'vm_launched': False,
              'guest_filesystem_modified': False, 'root_file_cap': CAP, 'new_write_admission_bytes': RESERVE}
    def command(arguments, label, timeout):
        args = sandbox(out)+ancestry_bindings(rows)+['--', '/usr/bin/prlimit', '--core=0:0',
                '--cpu=600:600', '--as=2147483648:2147483648', f'--fsize={CAP}:{CAP}', '--', '/usr/bin/qemu-img', *arguments]
        (out/(label+'-command.json')).write_text(json.dumps(args, indent=2)+'\n')
        return run_command(args, out, label, timeout)
    try:
        inspect(out, rows, False)
        source = f'/lineage/layer-{len(rows)-1}.qcow2'
        command(['convert', '-f', 'qcow2', '-O', 'qcow2', source, '/work/target.qcow2'], 'convert', 650)
        if (out/'target.qcow2').stat().st_size >= CAP:raise Invalid('checkpoint root cap reached')
        # Strict allocation comparison would differ intentionally: compare visible
        # disk bytes, not allocation layout, compressed size or backing metadata.
        command(['compare', '-f', 'qcow2', '-F', 'qcow2', source, '/work/target.qcow2'], 'compare', 650)
        info = json.loads(command(['info', '-f', 'qcow2', '--output=json', '/work/target.qcow2'], 'info', 15))
        if info.get('format') != 'qcow2' or info.get('virtual-size') != 8*1024**3 or info.get('backing-filename') or info.get('encrypted'):
            raise Invalid('checkpoint is not standalone fixed geometry')
        command_guard(out)
        clone_file(backup, out/'backup.qcow2');backup_info(out)
        if digest(out/'backup.qcow2') != prior['backup_sha256']:raise Invalid('checkpoint backup clone changed')
        for row in rows:pinned_file(row['path'], row['sha256'], CAP)
        pinned_file(backup, prior['backup_sha256'], 2112*1024**2)
        if digest(previous) != parent_hash or digest(inputs) != input_hash:raise Invalid('checkpoint receipts changed')
        if shutil.disk_usage(out).free < FREE_FLOOR:raise Invalid('checkpoint space floor')
        report.update(status='PASS-foundation-checkpoint', checked_at=datetime.now(timezone.utc).isoformat(),
                      disk_sha256=digest(out/'target.qcow2'), disk_bytes=(out/'target.qcow2').stat().st_size,
                      backup_sha256=digest(out/'backup.qcow2'), backup_bytes=(out/'backup.qcow2').stat().st_size,
                      guest_visible_bytes_equal=True, source_files_unchanged=True, standalone=True)
        return report
    except BaseException as exc:
        report['failure'] = str(exc);raise
    finally:(out/'result.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('previous', 'inputs', 'output'):parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(checkpoint(args.previous, args.inputs, args.output), indent=2))
