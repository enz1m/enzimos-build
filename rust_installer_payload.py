# SPDX-License-Identifier: MIT
"""Admit the paired native installer payload before live-image assembly."""
import hashlib
import json
from pathlib import Path
import shutil
import tarfile

from contract import Invalid, runtime_archive

PREFIX = 'usr/lib/enzimos-installer/'
BINARIES = {'enzimos-installer': PREFIX + 'enzimos-installer-native',
            'enzimos-installer-package-worker': PREFIX + 'enzimos-installer-package-worker'}
WRAPPERS = {PREFIX + 'ui-' + name + '.sh' for name in ('install', 'network', 'partition')}
MANIFEST = 'usr/share/enzimos/rust-candidates/installer/build.json'
LICENSE = 'usr/share/licenses/enzimos-rust-installer/LICENSE'


def stage(summary_path, output, installer):
    summary = json.loads(Path(summary_path).read_text())
    record = summary.get('packages', {}).get('installer', {})
    if (summary.get('result') != 'PASS' or record.get('package_name') != 'enzimos-rust-installer'
            or record.get('automatic_activation') is not False or record.get('elf_count') != 2
            or record.get('resource_count') != 3):
        raise Invalid('reviewed paired native installer package required')
    package = runtime_archive(summary_path, record['package'])
    if package.is_symlink() or not package.is_file() or not 0 < package.stat().st_size <= 64 * 1024**2:
        raise Invalid('bounded native installer package required')
    with package.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != record['sha256']:
            raise Invalid('native installer package digest mismatch')
    expected = set(BINARIES.values()) | WRAPPERS | {MANIFEST, LICENSE}
    files = {}; seen = set(); total = 0; info = None
    with tarfile.open(package, 'r|zst') as archive:
        for member in archive:
            path = Path(member.name); total += member.size
            if (path.is_absolute() or '..' in path.parts or member.name in seen or member.uid or member.gid
                    or not (member.isfile() or member.isdir()) or total > 64 * 1024**2):
                raise Invalid('unsafe native installer archive member')
            seen.add(member.name)
            if member.isdir():
                if member.mode != 0o755 or not any(p.startswith(member.name.rstrip('/') + '/') for p in expected):
                    raise Invalid('unexpected native installer directory')
                continue
            if member.size > 32 * 1024**2:
                raise Invalid('native installer member size bound')
            data = archive.extractfile(member).read()
            if member.name == '.PKGINFO': info = data.decode()
            elif member.name in ('.MTREE', '.BUILDINFO'): pass
            elif member.name not in expected:
                raise Invalid('unexpected native installer payload')
            else: files[member.name] = (data, member.mode)
    if set(files) != expected or info is None:
        raise Invalid('incomplete native installer payload')
    for line in ('pkgname = enzimos-rust-installer', 'pkgver = ' + record['version'], 'arch = x86_64'):
        if info.splitlines().count(line) != 1:
            raise Invalid('native installer package identity mismatch')
    binding = json.loads(files[MANIFEST][0])
    if (binding.get('component') != 'installer' or binding.get('automatic_activation') is not False
            or binding.get('production_cutover') is not False):
        raise Invalid('native installer build binding required')
    for name, path in BINARIES.items():
        data, mode = files[path]
        artifact = binding['artifacts'][name]
        if mode != 0o755 or not data.startswith(b'\x7fELF') or len(data) != artifact['bytes'] or hashlib.sha256(data).hexdigest() != artifact['sha256']:
            raise Invalid('paired native installer ELF mismatch')
    for path in WRAPPERS:
        data, mode = files[path]
        resource = binding['resources'][path]
        if (mode != 0o755 or resource['mode'] != mode or hashlib.sha256(data).hexdigest() != resource['sha256']
                or data != (Path(installer).parent / 'packaging/rust/live' / Path(path).stem).read_bytes()):
            raise Invalid('live wrappers differ from admitted native installer package')
    if any(files[p][1] != 0o644 for p in (MANIFEST, LICENSE)):
        raise Invalid('native installer metadata permissions')
    destination = Path(output) / 'installer.pkg.tar.zst'
    if destination.exists(): raise Invalid('fresh native installer admission required')
    shutil.copyfile(package, destination)
    with destination.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != record['sha256']:
            raise Invalid('native installer staging digest mismatch')
    return {'package': str(destination), 'sha256': record['sha256'], 'version': record['version'],
            'binaries': binding['artifacts'], 'source_heads': binding['source_heads'],
            'production_cutover': False, 'release_authorized': False}
