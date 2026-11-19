#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build diagnostic mkinitcpio/systemd initrds; the assembly root is NOT deployable."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import subprocess
import sys
import tarfile

from contract import Invalid, digest
from package_trust import verify_plan
from prepare_bootstrap import strip_privileged_modes
from signed_bootstrap import new_output, FREE_FLOOR

SKIP = {'.PKGINFO', '.BUILDINFO', '.MTREE', '.INSTALL'}
MAX_UNPACKED = 2 * 1024**3


def audit_packages(packages, records, *, max_unpacked=None):
    limit = MAX_UNPACKED if max_unpacked is None else max_unpacked
    if type(limit) is not int or not 1 <= limit <= 4 * 1024**3:
        raise Invalid('package audit requires a bounded unpacked-byte limit')
    total = 0; entries = 0; kinds = {}; identities = []
    for item in records:
        path = packages / item['url'].rsplit('/', 1)[-1]
        if digest(path) != item['sha256_from_metadata']:
            raise Invalid('package changed after verification')
        info = None
        with tarfile.open(path, 'r|zst') as archive:
            for member in archive:
                name = member.name.rstrip('/')
                if name in SKIP:
                    if name == '.PKGINFO':
                        if info is not None or not member.isfile() or member.size > 1024**2:
                            raise Invalid('invalid package identity metadata')
                        info = {}
                        for line in archive.extractfile(member).read().decode().splitlines():
                            if not line or line.startswith('#'):
                                continue
                            key, separator, value = line.partition(' = ')
                            if not separator:
                                raise Invalid('invalid PKGINFO line')
                            info.setdefault(key, []).append(value)
                    continue
                if not name or name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/')) or any(ord(c) < 32 for c in name):
                    raise Invalid('unsafe package member path')
                if not (member.isfile() or member.isdir() or member.issym() or member.islnk()) or member.sparse is not None:
                    raise Invalid('special/sparse package members are outside lab scope')
                kind = 'dir' if member.isdir() else 'other'
                if name in kinds and kinds[name] != kind:
                    raise Invalid('incompatible cross-package path types')
                kinds[name] = kind; entries += 1; total += member.size
                if entries > 100000 or total > limit:
                    raise Invalid('package assembly budget exceeded')
        if info is None or info.get('pkgname') != [item['name']] or info.get('pkgver') != [item['version']] or info.get('arch') != [item['architecture']]:
            raise Invalid('signed package identity disagrees with the reviewed plan')
        identities.append({'name': item['name'], 'version': item['version'], 'architecture': item['architecture']})
    for name in kinds:
        parent = name.rpartition('/')[0]
        while parent:
            if parent in kinds and kinds[parent] != 'dir':
                raise Invalid('package member is nested under a symlink or non-directory')
            parent = parent.rpartition('/')[0]
    return {'members': entries, 'regular_and_metadata_bytes': total, 'identities': identities}


def extract_argv(package, destination):
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib', '/lib64', '--dir', '/etc', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/tmp', '--ro-bind', str(package), '/tmp/input.pkg.tar.zst', '--bind', str(destination), '/tmp/root',
            '--setenv', 'PATH', '/usr/bin', '--setenv', 'LANG', 'C.UTF-8', '--', '/usr/bin/bsdtar',
            '-xf', '/tmp/input.pkg.tar.zst', '-C', '/tmp/root', '--no-same-owner', '--no-same-permissions',
            '--no-xattrs', '--no-acls', '--no-fflags', *['--exclude=' + name for name in sorted(SKIP)]]


def builder_argv(root, artifacts, args):
    # Namespace UID 0 maps to the unprivileged caller, not to host root.
    return ['/usr/bin/bwrap', '--unshare-all', '--uid', '0', '--gid', '0', '--die-with-parent', '--new-session',
            '--clearenv', '--bind', str(root), '/', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--tmpfs', '/run', '--tmpfs', '/root', '--tmpfs', '/home', '--bind', str(artifacts), '/tmp/artifacts',
            '--chdir', '/', '--setenv', 'PATH', '/usr/bin', '--setenv', 'HOME', '/tmp', '--setenv', 'LANG', 'C.UTF-8',
            '--setenv', 'SOURCE_DATE_EPOCH', '1789344000', '--', *args]


def run_command(args, output, label, timeout=90):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                            env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
    if len(result.stdout) + len(result.stderr) > 8 * 1024**2:
        raise Invalid('build log exceeded bound')
    (output / (label + '.stdout')).write_bytes(result.stdout)
    (output / (label + '.stderr')).write_bytes(result.stderr)
    if result.returncode:
        raise Invalid('isolated initrd build command failed; logs retained')


def build(plan, keyring, packages, trust_lock, output):
    if os.geteuid() == 0 or sys.version_info < (3, 14):
        raise Invalid('unprivileged Python 3.14+ required')
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR + 4 * 1024**3:
        raise Invalid('insufficient scratch headroom')
    packages = Path(packages).resolve(strict=True)
    output = new_output(output)
    result = {'status': 'FAIL', 'deployable_root': False, 'release_authorized': False, 'guest_os_booted': False}
    try:
        verification = verify_plan(plan, keyring, packages, output / 'verification', trust_lock)
        audit = audit_packages(packages, verification['packages'])
        (output / 'archive-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
        root = output / 'root'; root.mkdir(mode=0o700)
        for item in verification['packages']:
            run_command(extract_argv(packages / item['url'].rsplit('/', 1)[-1], root), output, 'extract-' + item['name'], 30)
            if shutil.disk_usage(output).free < FREE_FLOOR:
                raise Invalid('free-space floor reached')
        result['sanitization'] = strip_privileged_modes(root)
        fixtures = Path(__file__).resolve().parent / 'fixtures/initrd'
        destinations = {'mkinitcpio.conf': 'etc/mkinitcpio-lab.conf',
                        'initrd-smoke.sh': 'usr/lib/enzimos-lab/initrd-smoke.sh',
                        'enzimos-initrd-smoke.service': 'usr/lib/systemd/system/enzimos-initrd-smoke.service',
                        'enzimos-initrd-smoke.target': 'usr/lib/systemd/system/enzimos-initrd-smoke.target'}
        for source, destination in destinations.items():
            target = root / destination; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(fixtures / source, target)
        artifacts = output / 'artifacts'; artifacts.mkdir(mode=0o700)
        kernels = []
        for directory in sorted((root / 'usr/lib/modules').iterdir()):
            if not directory.is_dir() or directory.is_symlink() or not re.fullmatch('[A-Za-z0-9._+-]+', directory.name):
                raise Invalid('unexpected modules directory')
            flavor = (directory / 'pkgbase').read_text().strip()
            if flavor not in ('linux', 'linux-lts'):
                raise Invalid('unexpected kernel flavor')
            run_command(builder_argv(root, artifacts, ['/usr/bin/depmod', '-a', directory.name]), output, 'depmod-' + flavor)
            run_command(builder_argv(root, artifacts, ['/usr/bin/mkinitcpio', '-k', directory.name, '-c', '/etc/mkinitcpio-lab.conf', '-g', '/tmp/artifacts/' + flavor + '.img']), output, 'mkinitcpio-' + flavor)
            shutil.copyfile(directory / 'vmlinuz', artifacts / (flavor + '.vmlinuz'))
            kernels.append({'flavor': flavor, 'uname': directory.name, 'kernel': flavor + '.vmlinuz', 'initrd': flavor + '.img',
                            'kernel_sha256': digest(artifacts / (flavor + '.vmlinuz')), 'initrd_sha256': digest(artifacts / (flavor + '.img'))})
        if {k['flavor'] for k in kernels} != {'linux', 'linux-lts'} or len(kernels) != 2:
            raise Invalid('both kernel flavors required')
        result.update(status='PASS-diagnostic-initrds-built', checked_at=datetime.now(timezone.utc).isoformat(), kernels=kernels,
                      generator='mkinitcpio', early_userspace='systemd', package_count=len(verification['packages']),
                      metadata_preserved_for_target=False, bootloader_or_secure_boot_qualified=False,
                      fixture_sha256={name: digest(fixtures / name) for name in destinations})
        return result
    except BaseException as exc:
        result['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise
    finally:
        (output / 'build.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'keyring', 'packages', 'trust-lock', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**3, 1024**3))
    try:
        print(json.dumps(build(args.plan, args.keyring, args.packages, args.trust_lock, args.output), indent=2))
    except (Invalid, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
