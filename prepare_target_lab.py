#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare authenticated, offline inputs for a fixed disposable target VM."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys

from build_initrd_lab import build, builder_argv, run_command
from contract import Invalid, digest, load
from package_trust import gpg_base, execute, verify_plan
from signed_bootstrap import FREE_FLOOR, new_output

FIXTURES = Path(__file__).resolve().parent / 'fixtures/target-lab'
GPG_CONFIG = 'trust-model direct\nno-auto-key-retrieve\nauto-key-locate clear\nno-autostart\n'
PACMAN_CONFIG = '[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nCheckSpace\n'


def public_cache(output, keyring, packages, records):
    """Compile ONLY previously quorum-approved signers into a fixed-snapshot cache."""
    output.mkdir(mode=0o700)
    (output / 'public').mkdir(mode=0o700)
    representatives = {}
    for item in records:
        sig = item['signature']
        if not sig['signature_valid'] or not sig['certifications'] or any(len(set(c['masters'])) < 3 for c in sig['certifications']):
            raise Invalid('public cache requires completed quorum verification')
        representatives.setdefault(sig['primary_fingerprint'], item)
    (output / 'approved.trust').write_text(''.join(f'{fp}:5:\n' for fp in sorted(representatives)))

    def base(filename=None):
        args = gpg_base(output, keyring, packages, 'public', filename)
        args[args.index('--trust-model') + 1] = 'direct'
        return args

    for label, args in [('import', ['--import', '/keyring/archlinux.gpg']),
                        ('trust', ['--import-ownertrust', '/work/approved.trust']),
                        ('secret-check', ['--with-colons', '--list-secret-keys'])]:
        result = execute(base() + args, output, label)
        if result.returncode or (label == 'secret-check' and result.stdout.strip()):
            raise Invalid('public-only admission cache setup failed')
    exported = execute(base() + ['--export'], output, 'public-export')
    if exported.returncode or not exported.stdout:
        raise Invalid('public key export failed')
    (output / 'public/pubring.gpg').write_bytes(exported.stdout)
    (output / 'public/pubring.kbx').rename(output / 'original-public.kbx')
    if (output / 'public/pubring.kbx~').exists():
        (output / 'public/pubring.kbx~').rename(output / 'original-public.kbx~')
    for fp, item in representatives.items():
        filename = item['url'].rsplit('/', 1)[-1]
        result = execute(base(filename) + ['--status-fd', '1', '--verify', '/packages/' + filename + '.sig', '/packages/' + filename], output, fp)
        if result.returncode or b'[GNUPG:] TRUST_FULLY ' not in result.stdout:
            raise Invalid('direct admission-cache control failed')
    return sorted(representatives)


def iso_command(stage, output):
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib', '/lib64',
            '--proc', '/proc', '--dev', '/dev', '--dir', '/etc', '--tmpfs', '/tmp',
            '--ro-bind', str(stage), '/source', '--bind', str(output), '/output',
            '--setenv', 'PATH', '/usr/bin', '--', '/usr/bin/prlimit', '--cpu=90:90',
            '--as=2147483648:2147483648', '--fsize=1073741824:1073741824', '--',
            '/usr/bin/xorriso', '-as', 'mkisofs', '-quiet', '-R', '-V', 'ENZIMOS_LAB_INPUT',
            '-o', '/output/payload.iso', '/source']


def prepare(plan, keyring, packages, trust_lock, output, assembly=None):
    if os.geteuid() == 0:
        raise Invalid('prepare as an unprivileged user')
    output = new_output(output)
    result = {'status': 'FAIL', 'release_authorized': False, 'installed_target': False}
    try:
        if assembly is None:
            assembly = output / 'assembly'
            built = build(plan, keyring, packages, trust_lock, assembly)
            records = load(assembly / 'verification/verification.json')['packages']
        else:
            assembly = Path(assembly).resolve(strict=True)
            built = load(assembly / 'build.json')
            if built.get('status') != 'PASS-diagnostic-initrds-built' or built.get('package_count') != 146:
                raise Invalid('explicit trusted assembly must be a reviewed lab build')
            records = verify_plan(plan, keyring, packages, output / 'verification', trust_lock)['packages']
        root = assembly / 'root'
        result['trusted_assembly_input'] = str(assembly)
        result['assembly_receipt_sha256'] = digest(assembly / 'build.json')
        packages = Path(packages).resolve(strict=True); keyring = Path(keyring).resolve(strict=True)
        admitted = public_cache(output / 'admission', keyring, packages, records)
        stage = output / 'iso-stage'; stage.mkdir(mode=0o700)
        (stage / 'packages').mkdir(); (stage / 'public-keys').mkdir(mode=0o700)
        for item in records:
            name = item['url'].rsplit('/', 1)[-1]
            if digest(packages / name) != item['sha256_from_metadata']:
                raise Invalid('package changed before ISO staging')
            for filename in (name, name + '.sig'):
                os.link(packages / filename, stage / 'packages' / filename)
        for name in ('pubring.gpg', 'trustdb.gpg'):
            shutil.copyfile(output / 'admission/public' / name, stage / 'public-keys' / name)
        (stage / 'public-keys/gpg.conf').write_text(GPG_CONFIG)
        for name in ('target-mkinitcpio.conf', 'root-smoke.sh', 'enzimos-root-smoke.service'):
            shutil.copyfile(FIXTURES / name, stage / name)
        (stage / 'expected-packages.txt').write_text(''.join(f"{p['name']} {p['version']}\n" for p in sorted(records, key=lambda p: p['name'])))
        for name in ('pacman-install.conf', 'pacman-target.conf'):
            (stage / name).write_text(PACMAN_CONFIG)
        (stage / 'SHA256SUMS').write_text(''.join(f'{digest(path)}  {path.relative_to(stage)}\n' for path in sorted(stage.rglob('*')) if path.is_file()))
        run_command(iso_command(stage, output), output, 'iso', 100)
        destinations = {'provision.sh': 'usr/lib/enzimos-lab/provision.sh',
                        'enzimos-target-provision.service': 'usr/lib/systemd/system/enzimos-target-provision.service',
                        'enzimos-target-provision.target': 'usr/lib/systemd/system/enzimos-target-provision.target',
                        'mkinitcpio.conf': 'etc/mkinitcpio-target-provision.conf'}
        for source, destination in destinations.items():
            if assembly == output / 'assembly':
                shutil.copyfile(FIXTURES / source, root / destination)
            elif not (root / destination).is_file():
                raise Invalid('reused assembly lacks expected fixed fixture mountpoint')
        kernel = next(k for k in built['kernels'] if k['flavor'] == 'linux')
        argv = builder_argv(root, output, ['/usr/bin/mkinitcpio', '-k', kernel['uname'], '-c', '/etc/mkinitcpio-target-provision.conf', '-g', '/tmp/artifacts/provision.img'])
        argv[argv.index('--bind')] = '--ro-bind'
        overrides = [arg for source, destination in destinations.items() for arg in ('--ro-bind', str(FIXTURES / source), '/' + destination)]
        argv[argv.index('--'):argv.index('--')] = overrides
        run_command(argv, output, 'provision-initrd', 100)
        source_kernel = assembly / 'artifacts/linux.vmlinuz'
        if digest(source_kernel) != kernel['kernel_sha256']:
            raise Invalid('assembly kernel changed')
        shutil.copyfile(source_kernel, output / 'kernel')
        if shutil.disk_usage(output).free < FREE_FLOOR + 8 * 1024**3:
            raise Invalid('insufficient headroom for a disposable 8 GiB disk')
        result.update(status='PASS-offline-target-inputs', checked_at=datetime.now(timezone.utc).isoformat(),
                      inputs={name: {'sha256': digest(output / name), 'bytes': (output / name).stat().st_size} for name in ('payload.iso', 'kernel', 'provision.img')},
                      kernels=built['kernels'], package_count=len(records), admitted_public_signers=admitted,
                      fixture_hashes={p.name: digest(p) for p in FIXTURES.iterdir() if p.is_file()},
                      trust_lock_sha256=digest(Path(trust_lock)), review_before=load(Path(trust_lock))['review_before'],
                      hibernation='deferred-for-now', private_keys_created=False, production_keyring_lifecycle=False)
        return result
    except BaseException as exc:
        result['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise
    finally:
        (output / 'inputs.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'keyring', 'packages', 'trust-lock', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--assembly', type=Path, help='explicit trusted/stable previous assembly; mounted read-only, packages reverified')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
    try:
        print(json.dumps(prepare(args.plan, args.keyring, args.packages, args.trust_lock, args.output, args.assembly), indent=2))
    except (Invalid, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
