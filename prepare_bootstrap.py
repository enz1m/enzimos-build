#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare an authenticated, non-deployable Arch toolroot in NEW private scratch space."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import resource
import shutil
import stat
import subprocess
import sys

from bootstrap_archive import audit_archive, MAX_UNPACKED
from headless_plan import resolve
from contract import Invalid, digest
from signed_bootstrap import verify, read_lock, check_input_files, new_output, FREE_FLOOR


def extractor_argv(archive, destination):
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib', '/lib64', '--dir', '/etc', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/tmp', '--dir', '/inputs', '--ro-bind', str(archive), '/inputs/bootstrap.tar.zst',
            '--bind', str(destination), '/out', '--chdir', '/out', '--setenv', 'HOME', '/tmp',
            '--setenv', 'PATH', '/usr/bin', '--setenv', 'LANG', 'C.UTF-8', '--',
            '/usr/bin/prlimit', '--cpu=60:60', '--as=1073741824:1073741824', '--fsize=1073741824:1073741824',
            '--', '/usr/bin/bsdtar', '--extract', '--file', '/inputs/bootstrap.tar.zst', '--directory', '/out',
            '--no-same-owner', '--no-same-permissions', '--no-acls', '--no-xattrs', '--no-fflags']


def toolroot_argv(root, operation):
    commands = {'version': ['--version'], 'packages': ['--query']}
    if operation not in commands:
        raise Invalid('only readonly pacman version/query operations are supported')
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', str(root), '/', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--tmpfs', '/run', '--tmpfs', '/root', '--tmpfs', '/home', '--chdir', '/',
            '--setenv', 'HOME', '/tmp', '--setenv', 'PATH', '/usr/bin', '--setenv', 'LANG', 'C.UTF-8',
            '--', '/usr/bin/pacman', *commands[operation]]


def strip_privileged_modes(root):
    stripped = 0
    repaired = 0
    entries = 0

    def walk_error(_error):
        raise Invalid('cannot inspect the complete extracted tree')

    for parent, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        for name in dirs + files:
            path = Path(parent) / name
            info = path.lstat()
            entries += 1
            if stat.S_ISLNK(info.st_mode):
                continue
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise Invalid('unexpected nonregular entry after extraction')
            mode = stat.S_IMODE(info.st_mode) & ~0o6000
            if stat.S_ISDIR(info.st_mode) and mode & 0o700 != 0o700:
                mode |= 0o700
                repaired += 1
            if info.st_mode & 0o6000:
                stripped += 1
            if mode != stat.S_IMODE(info.st_mode):
                os.chmod(path, mode, follow_symlinks=False)
    return {'entries_checked': entries, 'remaining_special_modes_removed': stripped,
            'private_directory_owner_access_repairs': repaired}


def command(argv, output, name, timeout=70):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                            env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
    if len(result.stdout) + len(result.stderr) > 8 * 1024**2:
        raise Invalid('subprocess output exceeds bound')
    (output / f'{name}.stdout').write_bytes(result.stdout)
    (output / f'{name}.stderr').write_bytes(result.stderr)
    if result.returncode != 0:
        raise Invalid('isolated preparation command failed; private logs retained')
    return result.stdout.decode('utf-8')


def prepare(lock, inputs, output, seed=None, databases=None):
    if os.geteuid() == 0:
        raise Invalid('toolroot preparation must be unprivileged')
    if (seed is None) != (databases is None):
        raise Invalid('seed and repository databases must be supplied together')
    if sys.version_info < (3, 14):
        raise Invalid('Python 3.14+ is required for the bounded zstd archive audit')
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR + 2 * MAX_UNPACKED:
        raise Invalid('insufficient headroom for the bounded toolroot; nothing cleaned automatically')
    output = new_output(output)
    report = {'status': 'FAIL', 'release_authorized': False, 'deployable_root': False,
              'guest_os_booted': False, 'package_closure_verified': False}
    try:
        # A caller-supplied receipt cannot bypass verification: redo it in this operation.
        verification = verify(lock, inputs, output / 'verification')
        policy = read_lock(lock)
        if digest(Path(lock)) != verification['lock_sha256'] or policy['inputs'] != verification['inputs']:
            raise Invalid('reviewed lock changed after signature verification')
        inputs = check_input_files(inputs, policy)
        archive = inputs / 'bootstrap.tar.zst'
        audit = audit_archive(archive)
        (output / 'archive-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
        if shutil.disk_usage(output).free < FREE_FLOOR + 2 * MAX_UNPACKED:
            raise Invalid('free-space headroom changed before extraction')
        destination = output / 'unpacked'
        destination.mkdir(mode=0o700)
        argv = extractor_argv(archive, destination)
        (output / 'extract-command.json').write_text(json.dumps(argv, indent=2) + '\n')
        command(argv, output, 'extract')
        modes = strip_privileged_modes(destination)
        if shutil.disk_usage(output).free < FREE_FLOOR:
            raise Invalid('free-space floor reached; partial private output retained')
        check_input_files(inputs, policy)
        root = destination / 'root.x86_64'
        for name in ('version', 'pkglist.x86_64.txt'):
            if not stat.S_ISREG((destination / name).lstat().st_mode):
                raise Invalid('extracted metadata is not a regular file')
        if (destination / 'version').read_text().strip() != policy['release']:
            raise Invalid('archive release identity mismatch')
        version = command(toolroot_argv(root, 'version'), output, 'pacman-version', timeout=20)
        packages = command(toolroot_argv(root, 'packages'), output, 'pacman-packages', timeout=20)
        expected = (destination / 'pkglist.x86_64.txt').read_text().splitlines()
        actual = packages.splitlines()
        if len(actual) != len(set(actual)) or sorted(actual) != sorted(expected):
            raise Invalid('toolroot package database does not match its signed archive inventory')
        parsed = []
        for line in actual:
            fields = line.split()
            if len(fields) != 2:
                raise Invalid('unexpected package inventory line')
            parsed.append({'name': fields[0], 'version': fields[1]})
        report.update(status='PASS-development-toolroot-only', checked_at=datetime.now(timezone.utc).isoformat(),
                      archive_sha256=verification['inputs']['artifact']['sha256'],
                      signature_primary_fingerprint=verification['primary_fingerprint'],
                      archive_audit=audit, privilege_sanitization=modes, package_inventory=parsed,
                      packages=len(parsed), pacman_version_output=version.strip(),
                      source_sha256={name: digest(Path(__file__).resolve().parent / name)
                                     for name in ('prepare_bootstrap.py', 'signed_bootstrap.py', 'bootstrap_archive.py', 'headless_plan.py', 'contract.py')},
                      host_kernel_shared=True, host_usr_or_package_database_bound_into_toolroot=False,
                      target_root_ownership_preserved=False, network_enabled=False,
                      limitation='unprivileged sanitized userspace toolroot, not a VM/installed OS or target image')
        if seed is not None:
            resolution = resolve(root, seed, databases, output / 'headless')
            report['headless_resolution'] = {key: resolution[key] for key in
                                             ('status', 'package_count', 'download_bytes_from_metadata',
                                              'package_signatures_verified', 'release_authorized')}
        return report
    except BaseException as exc:
        report['status'] = 'FAIL'
        report['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise
    finally:
        (output / 'preparation.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', required=True, type=Path)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='NEW private output; parent must exist')
    parser.add_argument('--seed', type=Path, help='optional reviewed headless experiment seed')
    parser.add_argument('--databases', type=Path, help='matching local database snapshot; no download')
    args = parser.parse_args()
    # Process-local limits also bound the stdlib archive parser and descendants.
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024**2, 1536 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_UNPACKED, MAX_UNPACKED))
    try:
        print(json.dumps(prepare(args.lock, args.inputs, args.output, args.seed, args.databases), indent=2))
    except (Invalid, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status': 'FAIL', 'release_authorized': False,
                          'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
