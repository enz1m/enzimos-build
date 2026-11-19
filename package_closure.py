#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Re-resolve dependency metadata from exact package bytes; signature authorization is separate."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from contract import Invalid, digest, load
from signed_bootstrap import new_output
from headless_plan import read_seed, check_empty_target


def compare_resolution(text, packages):
    rows = [tuple(line.split('\t')) for line in text.splitlines()]
    expected = {(p['name'], p['version'], p['architecture'], p['sha256_from_metadata']) for p in packages}
    if any(len(row) != 4 for row in rows) or len(rows) != len(set(rows)) or set(rows) != expected:
        raise Invalid('package-byte dependency resolution differs from the supplied manifest')
    return len(rows)


def check(toolroot, package_dir, manifest_path, seed_path, output):
    if os.geteuid() == 0:
        raise Invalid('run closure check unprivileged')
    toolroot = Path(toolroot).resolve(strict=True); package_dir = Path(package_dir).resolve(strict=True)
    if toolroot == Path('/') or not (toolroot / 'usr/bin/repo-add').is_file():
        raise Invalid('an explicit prepared Arch toolroot is required; never use host root')
    manifest = load(manifest_path); seed = read_seed(seed_path)
    records = manifest['packages']
    if type(records) is not list or not 0 < len(records) <= 1024:
        raise Invalid('invalid package count')
    names = []
    for record in records:
        name = record['url'].rsplit('/', 1)[-1]
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+:-]*\.pkg\.tar\.(zst|xz)', name) or name in names:
            raise Invalid('invalid package filename')
        path = package_dir / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != record['download_bytes_from_metadata'] or digest(path) != record['sha256_from_metadata']:
            raise Invalid('package byte/hash mismatch')
        names.append(name)
    output = new_output(output)
    for directory in ('db/local', 'db/sync', 'cache', 'gpg'):
        (output / directory).mkdir(parents=True, exist_ok=True)
    base = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', str(toolroot), '/', '--dev', '/dev', '--proc', '/proc', '--tmpfs', '/tmp',
            '--tmpfs', '/run', '--tmpfs', '/root', '--tmpfs', '/home', '--dir', '/tmp/target',
            '--bind', str(output), '/tmp/plan', '--ro-bind', str(package_dir), '/tmp/pkgs', '--chdir', '/tmp/plan',
            '--setenv', 'HOME', '/tmp', '--setenv', 'PATH', '/usr/bin', '--setenv', 'LANG', 'C.UTF-8', '--']
    commands = [('repo-add', base + ['/usr/bin/repo-add', '--quiet', '/tmp/plan/db/sync/verified.db.tar.gz'] + ['/tmp/pkgs/' + name for name in names])]
    (output / 'pacman.conf').write_text('[options]\nArchitecture = x86_64\nRootDir = /tmp/target\nDBPath = /tmp/plan/db\nCacheDir = /tmp/plan/cache\nGPGDir = /tmp/plan/gpg\nLogFile = /tmp/plan/pacman.log\nSigLevel = Required DatabaseOptional\n[verified]\nServer = file:///tmp/pkgs\n')
    commands.append(('resolution', base + ['/usr/bin/pacman', '--config', '/tmp/plan/pacman.conf', '--sync', '--print', '--noconfirm', '--print-format', '%n\t%v\t%a\t%h'] + seed['requested_packages']))
    report = {'status': 'FAIL', 'release_authorized': False, 'signature_check_performed_by_this_tool': False}
    try:
        for label, command in commands:
            (output / (label + '.command.json')).write_text(json.dumps(command, indent=2) + '\n')
            result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=180,
                                    env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
            if len(result.stdout) + len(result.stderr) > 8 * 1024**2:
                raise Invalid('closure tool output exceeds bound')
            (output / (label + '.stdout')).write_bytes(result.stdout)
            (output / (label + '.stderr')).write_bytes(result.stderr)
            if result.returncode:
                raise Invalid('isolated metadata reconstruction/resolution failed')
        count = compare_resolution(result.stdout.decode(), records)
        check_empty_target(output)
        report.update(status='PASS-package-byte-dependency-closure', package_count=count,
                      manifest_sha256=digest(Path(manifest_path)), seed_sha256=digest(Path(seed_path)),
                      target_installed=False, source='repo-add reads PKGINFO from exact package files; pacman resolves an empty target')
        return report
    finally:
        (output / 'closure.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('toolroot', 'packages', 'manifest', 'seed', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.toolroot, args.packages, args.manifest, args.seed, args.output), indent=2))
    except (Invalid, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
