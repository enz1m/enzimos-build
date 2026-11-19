#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare a pinned disposable LUKS/recovery experiment; no host disk operations."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys

from build_initrd_lab import builder_argv, run_command
from contract import Invalid, digest, load
from package_trust import verify_plan
from prepare_target_lab import iso_command
from signed_bootstrap import FREE_FLOOR, new_output

FIXTURES = Path(__file__).resolve().parent / 'fixtures/encrypted-lab'
SOURCE_HASH = '9d3dc2c5004b3992fb08b948ef6b6dc70d34555a745152c65eefd5c693646c56'
# PUBLIC TEST DATA, not user credentials or suitable passwords for real storage.
PRIMARY = 'ENZIMOS-PUBLIC-DISPOSABLE-PRIMARY-ONLY'
RECOVERY = 'ENZIMOS-PUBLIC-DISPOSABLE-RECOVERY-ONLY'
WRONG = 'ENZIMOS-INTENTIONALLY-WRONG'


def checked_source(record):
    record = Path(record).resolve(strict=True)
    report = load(record)
    image = record.parent / 'target.qcow2'
    if report.get('status') != 'PASS-disposable-target-phase' or report.get('phase') != -1 or report.get('disk_sha256') != SOURCE_HASH:
        raise Invalid('only the recorded initial unencrypted lab image is accepted')
    if image.is_symlink() or not image.is_file() or image.stat().st_size > 8 * 1024**3 or digest(image) != SOURCE_HASH:
        raise Invalid('source image type/size/provenance mismatch')
    return record, image


def build_initrd(assembly, output, uname, script, filename, fixtures=FIXTURES):
    root = assembly / 'root'
    overrides = {'provision.sh': ('usr/lib/enzimos-lab/provision.sh', script),
                 'mkinitcpio.conf': ('etc/mkinitcpio-target-provision.conf', 'mkinitcpio.conf'),
                 'service': ('usr/lib/systemd/system/enzimos-target-provision.service', 'enzimos-target-provision.service'),
                 'target': ('usr/lib/systemd/system/enzimos-target-provision.target', 'enzimos-target-provision.target')}
    argv = builder_argv(root, output, ['/usr/bin/mkinitcpio', '-k', uname, '-c', '/etc/mkinitcpio-target-provision.conf', '-g', '/tmp/artifacts/' + filename])
    argv[argv.index('--bind')] = '--ro-bind'
    mounts = []
    for destination, source in overrides.values():
        if not (root / destination).is_file():
            raise Invalid('trusted assembly lacks fixed fixture mountpoints')
        mounts += ['--ro-bind', str(fixtures / source), '/' + destination]
    argv[argv.index('--'):argv.index('--')] = mounts
    run_command(argv, output, filename, 120)


def prepare(plan, keyring, packages, trust_lock, assembly, source_result, output):
    if os.geteuid() == 0:
        raise Invalid('run unprivileged')
    source_result, image = checked_source(source_result)
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR + 8 * 1024**3:
        raise Invalid('insufficient virtual-disk headroom')
    output = new_output(output)
    result = {'status': 'FAIL', 'release_authorized': False, 'hibernation': 'deferred-for-now'}
    try:
        verified = verify_plan(plan, keyring, packages, output / 'verification', trust_lock)
        assembly = Path(assembly).resolve(strict=True)
        built = load(assembly / 'build.json')
        if built['status'] != 'PASS-diagnostic-initrds-built' or built['package_count'] != 146:
            raise Invalid('explicit trusted assembly required')
        kernel = next(k for k in built['kernels'] if k['flavor'] == 'linux')
        source_kernel = assembly / 'artifacts/linux.vmlinuz'
        if digest(source_kernel) != kernel['kernel_sha256']:
            raise Invalid('assembly kernel changed')
        shutil.copyfile(source_kernel, output / 'kernel')
        build_initrd(assembly, output, kernel['uname'], 'provision.sh', 'provision.img')
        build_initrd(assembly, output, kernel['uname'], 'recovery.sh', 'recovery.img')
        stage = output / 'iso-stage'; stage.mkdir(mode=0o700)
        for name in ('root-smoke.sh', 'target-mkinitcpio.conf'):
            shutil.copyfile(FIXTURES / name, stage / name)
        shutil.copyfile(output / 'recovery.img', stage / 'recovery.img')
        shutil.copyfile(output / 'kernel', stage / 'recovery.kernel')
        (stage / 'fixture-primary').write_bytes(PRIMARY.encode())
        (stage / 'fixture-recovery').write_bytes(RECOVERY.encode())
        (stage / 'expected-packages.txt').write_text(''.join(f"{p['name']} {p['version']}\n" for p in sorted(verified['packages'], key=lambda p: p['name'])))
        (stage / 'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.name}\n' for p in sorted(stage.iterdir())))
        run_command(iso_command(stage, output), output, 'iso', 100)
        result.update(status='PASS-encrypted-lab-inputs', checked_at=datetime.now(timezone.utc).isoformat(),
                      source_image=str(image), source_image_sha256=SOURCE_HASH,
                      source_result_sha256=digest(source_result), trusted_assembly=str(assembly),
                      assembly_receipt_sha256=digest(assembly / 'build.json'),
                      trust_lock_sha256=digest(Path(trust_lock)), review_before=load(Path(trust_lock))['review_before'],
                      inputs={name: {'bytes': (output / name).stat().st_size, 'sha256': digest(output / name)} for name in ('kernel', 'provision.img', 'recovery.img', 'payload.iso')},
                      kernels=built['kernels'], package_count=len(verified['packages']),
                      fixture_hashes={p.name: digest(p) for p in FIXTURES.iterdir()},
                      credential_scope='public-test-passphrases-only; guest-volume-keys-not-production-or-signing',
                      real_package_update_tested=False, enforcing_secure_boot_tested=False)
        return result
    except BaseException as exc:
        result['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise
    finally:
        (output / 'inputs.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'keyring', 'packages', 'trust-lock', 'assembly', 'source-result', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**3, 1024**3))
    try:
        print(json.dumps(prepare(args.plan, args.keyring, args.packages, args.trust_lock, args.assembly, args.source_result, args.output), indent=2))
    except (Invalid, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
