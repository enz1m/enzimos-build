#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare authenticated full-update experiments against a pinned encrypted lab image."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
import tarfile

from build_initrd_lab import audit_packages, run_command
from contract import Invalid, digest, load
from encrypted_inputs import build_initrd, PRIMARY
from package_closure import check as closure_check
from package_trust import verify_plan
from prepare_target_lab import public_cache, GPG_CONFIG, iso_command
from signed_bootstrap import new_output, FREE_FLOOR
from update_catalogue import changes

FIXTURES = Path(__file__).resolve().parent / 'fixtures/update-lab'
SOURCE_HASH = 'dce8daec4f998c2984b52d9b45c8a0235cf7e57fc74bbb02042deaf627c04b95'
EXPECTED_CHANGES = {'libpcap', 'libtirpc', 'linux', 'linux-lts', 'tzdata'}


def kernel_names(packages, records):
    result = {}
    for item in records:
        if item['name'] not in ('linux', 'linux-lts'):
            continue
        path = packages / item['url'].rsplit('/', 1)[-1]
        with tarfile.open(path, 'r|zst') as archive:
            for member in archive:
                match = re.fullmatch(r'usr/lib/modules/([A-Za-z0-9._+-]+)/pkgbase', member.name)
                if match:
                    if not member.isfile() or member.size > 64 or item['name'] in result or archive.extractfile(member).read().decode().strip() != item['name']:
                        raise Invalid('unexpected kernel identity metadata')
                    result[item['name']] = match[1]
    if set(result) != {'linux', 'linux-lts'}:
        raise Invalid('both kernel identities required')
    return result


def prepare(catalogue, old_plan, old_packages, keyring, trust_lock, assembly, source_result, output):
    if os.geteuid() == 0:
        raise Invalid('run unprivileged')
    source_result = Path(source_result).resolve(strict=True)
    source = source_result.parent / 'target.qcow2'; prior = load(source_result)
    if prior.get('status') != 'PASS-encrypted-lab-phase' or prior.get('phase') != 7 or prior.get('disk_sha256') != SOURCE_HASH or source.is_symlink() or not source.is_file() or digest(source) != SOURCE_HASH:
        raise Invalid('pinned final encrypted baseline required')
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR + 8 * 1024**3:
        raise Invalid('insufficient image headroom')
    catalogue = Path(catalogue).resolve(strict=True); cat = load(catalogue / 'catalogue.json')
    new_plan = catalogue / 'resolution/resolution.json'; packages = catalogue / 'packages'
    if cat['status'] != 'PASS-authenticated-update-catalogue' or digest(new_plan) != cat['plan_sha256']:
        raise Invalid('reviewed full catalogue required')
    delta = changes(load(old_plan), load(new_plan))
    if delta['added'] or delta['removed'] or {p['name'] for p in delta['changed']} != EXPECTED_CHANGES:
        raise Invalid('this fixed experiment requires the reviewed five-package transition')
    output = new_output(output)
    report = {'status': 'FAIL', 'release_authorized': False}
    try:
        old = verify_plan(old_plan, keyring, old_packages, output / 'verify-old', trust_lock)
        new = verify_plan(new_plan, keyring, packages, output / 'verify-new', trust_lock)
        if old['package_count'] != 146 or new['package_count'] != 146:
            raise Invalid('unexpected package inventory')
        audit_packages(packages, new['packages'])
        assembly = Path(assembly).resolve(strict=True)
        closure_check(assembly / 'root', packages, new_plan, catalogue / 'seed.json', output / 'closure')
        old_kernels = kernel_names(Path(old_packages), old['packages']); new_kernels = kernel_names(packages, new['packages'])
        built = load(assembly / 'build.json')
        kernel = next(k for k in built['kernels'] if k['flavor'] == 'linux')
        if kernel['uname'] != old_kernels['linux'] or digest(assembly / 'artifacts/linux.vmlinuz') != kernel['kernel_sha256']:
            raise Invalid('trusted assembly kernel changed')
        shutil.copyfile(assembly / 'artifacts/linux.vmlinuz', output / 'kernel')
        build_initrd(assembly, output, kernel['uname'], 'setup.sh', 'setup.img', fixtures=FIXTURES)
        build_initrd(assembly, output, kernel['uname'], 'recovery.sh', 'recovery.img', fixtures=FIXTURES)
        # Both generations must remain authorized by CURRENT policy, not old snapshot trust.
        combined = output / 'combined-packages'; combined.mkdir()
        for directory, records in [(Path(old_packages), old['packages']), (packages, new['packages'])]:
            for record in records:
                name = record['url'].rsplit('/', 1)[-1]
                for suffix in ('', '.sig'):
                    destination = combined / (name + suffix)
                    if not destination.exists():
                        os.link(directory / (name + suffix), destination)
        public_cache(output / 'admission', Path(keyring).resolve(strict=True), combined, old['packages'] + new['packages'])
        stage = output / 'iso-stage'; stage.mkdir(mode=0o700)
        (stage / 'packages').mkdir(); (stage / 'public-keys').mkdir(mode=0o700)
        for record in new['packages']:
            name = record['url'].rsplit('/', 1)[-1]
            for suffix in ('', '.sig'):
                os.link(packages / (name + suffix), stage / 'packages' / (name + suffix))
        shutil.copyfile(output / 'closure/db/sync/verified.db.tar.gz', stage / 'packages/verified.db')
        for name in ('pubring.gpg', 'trustdb.gpg'):
            shutil.copyfile(output / 'admission/public' / name, stage / 'public-keys' / name)
        shutil.copyfile(output / 'admission/approved.trust', stage / 'public-keys/approved.trust')
        (stage / 'public-keys/gpg.conf').write_text(GPG_CONFIG)
        (stage / 'authority.sha256').write_text(''.join(f'{digest(stage / "public-keys" / n)}  {n}\n' for n in ('pubring.gpg', 'gpg.conf', 'approved.trust')))
        for filename in ('root.sh', 'common.sh'):
            shutil.copyfile(FIXTURES / filename, stage / filename)
        shutil.copyfile(output / 'kernel', stage / 'recovery.kernel')
        shutil.copyfile(output / 'recovery.img', stage / 'recovery.img')
        (stage / 'fixture-primary').write_bytes(PRIMARY.encode())
        for label, records in [('old', old['packages']), ('new', new['packages'])]:
            (stage / (label + '-packages.txt')).write_text(''.join(f"{p['name']} {p['version']}\n" for p in sorted(records, key=lambda p: p['name'])))
        (stage / 'kernels.env').write_text(f"OLD_REGULAR={old_kernels['linux']}\nOLD_LTS={old_kernels['linux-lts']}\nNEW_REGULAR={new_kernels['linux']}\nNEW_LTS={new_kernels['linux-lts']}\n")
        (stage / 'pacman.conf').write_text('[options]\nArchitecture = x86_64\nCacheDir = /payload/packages\nLogFile = /var/log/pacman-update-lab.log\nSigLevel = Required TrustedOnly DatabaseOptional\nLocalFileSigLevel = Required TrustedOnly\nCheckSpace\n[verified]\nServer = file:///payload/packages\n')
        (stage / 'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.relative_to(stage)}\n' for p in sorted(stage.rglob('*')) if p.is_file()))
        run_command(iso_command(stage, output), output, 'iso', 100)
        report.update(status='PASS-full-update-inputs', checked_at=datetime.now(timezone.utc).isoformat(),
                      source_image=str(source), source_image_sha256=SOURCE_HASH, source_result_sha256=digest(source_result),
                      old_kernels=old_kernels, new_kernels=new_kernels, changes=delta,
                      current_policy_reverified_both_generations=True,
                      inputs={name: {'bytes': (output / name).stat().st_size, 'sha256': digest(output / name)} for name in ('kernel', 'setup.img', 'recovery.img', 'payload.iso')},
                      fixture_hashes={p.name: digest(p) for p in FIXTURES.iterdir()},
                      review_before=load(Path(trust_lock))['review_before'], trust_lock_sha256=digest(Path(trust_lock)),
                      hibernation='deferred-for-now', private_production_signing_keys_used=False)
        return report
    except BaseException as exc:
        report['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise
    finally:
        (output / 'inputs.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('catalogue', 'old-plan', 'old-packages', 'keyring', 'trust-lock', 'assembly', 'source-result', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**3, 1024**3))
    try:
        print(json.dumps(prepare(a.catalogue, a.old_plan, a.old_packages, a.keyring, a.trust_lock, a.assembly, a.source_result, a.output), indent=2))
    except (Invalid, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
