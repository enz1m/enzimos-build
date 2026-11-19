# SPDX-License-Identifier: MIT
"""Bounded, extraction-free checks for the authored copy-only native policy package.

This verifies package bytes against build inputs, not upstream signatures, runtime
behavior, dependency closure, or the cleanliness of the host-derived toolchain.
"""
from compression import zstd
import contextlib
import gzip
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import tarfile

from contract import Invalid

MAX_BYTES = 4 * 1024**2
MAX_MEMBERS = 256
MAX_SOURCE_FILES = 128
EPOCH = 1789516800
LICENSE_PATH = 'usr/share/licenses/enzimos-native-policy/LICENSE'
METADATA = {'.PKGINFO', '.BUILDINFO', '.MTREE', '.INSTALL'}


def require(condition, message):
    if not condition:
        raise Invalid(message)


def bounded_bytes(path, maximum=MAX_BYTES):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'bounded regular build input required')
        body = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(body) == before.st_size and len(body) <= maximum and
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'build input changed while reading')
        return body


def member_name(value):
    require(isinstance(value, str) and value and len(value) <= 240, 'invalid package path')
    require(not value.startswith('/') and all(part not in ('', '.', '..') for part in value.split('/')),
            'noncanonical package path')
    require(re.fullmatch(r'[A-Za-z0-9._+/@-]+', value) is not None, 'unqualified package path characters')
    return value


def source_snapshot(tree):
    """Capture bounded file bytes once; never traverse symlinked directories."""
    tree = Path(tree)
    require(not tree.is_symlink() and tree.is_dir(), 'regular policy source directory required')
    entries = {}
    total = 0
    file_count = 0

    def visit(directory):
        nonlocal total, file_count
        with os.scandir(directory) as iterator:
            children = []
            for child in iterator:
                children.append(child)
                require(len(children) <= MAX_MEMBERS, 'source directory entry bound')
        for child in sorted(children, key=lambda item: item.name):
            path = Path(child.path)
            if child.name == '__pycache__' or path.suffix in ('.pyc', '.pyo'):
                continue
            name = member_name(path.relative_to(tree).as_posix())
            info = child.stat(follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), 'source links and special files are forbidden')
            mode = stat.S_IMODE(info.st_mode)
            require(not mode & 0o7022, 'privileged or writable-by-others source mode')
            directory_entry = stat.S_ISDIR(info.st_mode)
            body = None if directory_entry else bounded_bytes(path, 2 * 1024**2)
            total += len(body) if body is not None else 0
            file_count += body is not None
            require(file_count <= MAX_SOURCE_FILES, 'policy source file count bound')
            entries[name] = {'mode': mode, 'body': body}
            require(len(entries) <= MAX_MEMBERS and total <= 2 * 1024**2, 'policy source count/size bound')
            if directory_entry:
                visit(path)
    visit(tree)
    require(entries, 'empty source tree')
    return entries


def metadata_fields(body):
    require(len(body) <= 512 * 1024, 'package metadata size bound')
    try:
        lines = body.decode('utf-8').splitlines()
    except UnicodeError as exc:
        raise Invalid('package metadata must be UTF-8') from exc
    result = {}
    for line in lines:
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition(' = ')
        require(separator and re.fullmatch('[a-z][a-z0-9_]*', key) and (value or key == 'url') and not any(ord(c) < 32 for c in value),
                'malformed package metadata')
        result.setdefault(key, []).append(value)
    return result


@contextlib.contextmanager
def bounded_archive(stream):
    """Bound expanded reads including hidden PAX/longname headers before tar parsing."""
    magic = stream.read(4);stream.seek(0)
    if magic == b'\x28\xb5\x2f\xfd':
        decoded = zstd.ZstdFile(stream, options={zstd.DecompressionParameter.window_log_max: 23})
    elif magic[:2] == b'\x1f\x8b':
        decoded = gzip.GzipFile(fileobj=stream)
    else:
        decoded = stream
    class LimitedReader:
        remaining = MAX_BYTES + MAX_MEMBERS * 1024 + 10240
        def read(self, size):
            require(type(size) is int and size >= 0, 'bounded archive reads required')
            body = decoded.read(min(size, self.remaining + 1))
            self.remaining -= len(body)
            require(self.remaining >= 0, 'expanded archive stream bound')
            return body
    try:
        with tarfile.open(fileobj=LimitedReader(), mode='r|') as archive:
            yield archive
    finally:
        if decoded is not stream:
            decoded.close()


PACKAGE_RELATIONS = {
    'depends': 'depend',
    'provides': 'provides',
    'conflicts': 'conflict',
    'replaces': 'replaces',
}


def recipe_relations(recipe, version, release):
    """Read literal relation arrays from the rendered copy-only recipe."""
    expected = {}
    for variable, metadata_key in PACKAGE_RELATIONS.items():
        lines = re.findall(rf'^\s*{variable}\s*=([^\n]*)$', recipe, re.M)
        require(len(lines) <= 1, 'duplicate package relation array: ' + variable)
        expected[metadata_key] = []
        if not lines:
            continue
        array = re.fullmatch(r'\((.*)\)\s*', lines[0].strip())
        require(array is not None, 'invalid package relation array: ' + variable)
        try:
            items = shlex.split(array[1], comments=False)
        except ValueError as exc:
            raise Invalid('malformed package relation array: ' + variable) from exc
        items = [item.replace('$pkgver', version).replace('$pkgrel', str(release))
                 for item in items]
        require(all(re.fullmatch(r'[A-Za-z0-9@_.+-]+(?:[<>=]+[A-Za-z0-9_.+:-]+)?', item)
                    for item in items) and len(items) == len(set(items)),
                'invalid package relation: ' + variable)
        expected[metadata_key] = items
    return expected


def read_package_info(stream):
    """Read the single bounded .PKGINFO from a copy-only package."""
    fields = None
    with bounded_archive(stream) as archive:
        for member in archive:
            if member_name(member.name) != '.PKGINFO':
                continue
            require(fields is None and member.isfile() and 0 < member.size <= 512 * 1024,
                    'invalid .PKGINFO')
            fields = metadata_fields(archive.extractfile(member).read())
    require(fields is not None, 'missing .PKGINFO')
    return fields


def audit(package, entries, license_body, install_body, release, epoch=EPOCH, package_name='enzimos-native-policy', *, recipe):
    require(type(release) is int and release > 0 and type(epoch) is int, 'invalid build identity')
    require(package_name in ('enzimos-native-policy', 'enzimos-system-backend', 'enzimos-update-client'), 'unreviewed authored package name')
    license_path = f'usr/share/licenses/{package_name}/LICENSE'
    expected = {name: dict(value) for name, value in entries.items()}
    expected[license_path] = {'mode': 0o644, 'body': license_body}
    for parent in PurePosixPath(license_path).parents:
        if str(parent) != '.':
            expected.setdefault(str(parent), {'mode': 0o755, 'body': None})
    if package_name == 'enzimos-native-policy':
        require('etc/sudoers.d/20-enzimos-wheel' in expected, 'missing authored sudoers policy')
        expected['etc/sudoers.d/20-enzimos-wheel']['mode'] = 0o440
    seen = set()
    metadata = {}
    total = 0
    # The stream reader enforces the uncompressed budget before reading each body.
    with os.fdopen(os.open(package, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_BYTES, 'package compressed size/type bound')
        try:
            with bounded_archive(stream) as archive:
                for item in archive:
                    name = member_name(item.name)
                    require(name not in seen and len(seen) < MAX_MEMBERS, 'duplicate/excess package members')
                    seen.add(name)
                    require(item.isfile() or item.isdir(), 'package links and special files are forbidden')
                    require(item.uid == item.gid == 0 and item.mtime == epoch, 'package ownership/timestamp mismatch')
                    require(0 <= item.size <= MAX_BYTES and (item.isfile() or item.size == 0), 'invalid package member size')
                    total += item.size
                    require(total <= MAX_BYTES, 'package uncompressed byte bound')
                    body = archive.extractfile(item).read() if item.isfile() else None
                    if name in METADATA:
                        require(body is not None and item.mode == 0o644 and item.size <= 512 * 1024, 'invalid package metadata member')
                        metadata[name] = body
                    else:
                        require(name in expected and item.mode == expected[name]['mode'] and body == expected[name]['body'],
                                'package payload differs from authored input: ' + name)
        except (tarfile.TarError, EOFError, zstd.ZstdError) as exc:
            raise Invalid('invalid package archive') from exc
    require(seen == set(expected) | METADATA, 'missing or unexpected package members')
    require(metadata['.INSTALL'] == install_body, 'install script differs from authored input')
    fields = metadata_fields(metadata['.PKGINFO'])
    for key, value in {'pkgname': package_name, 'pkgver': f'0.1.0-{release}', 'arch': 'any',
                       'license': 'MIT', 'builddate': str(epoch)}.items():
        require(fields.get(key) == [value], 'package metadata identity mismatch: ' + key)
    for key, expected_values in recipe_relations(recipe, '0.1.0', release).items():
        require(sorted(fields.get(key, [])) == sorted(expected_values),
                'package metadata relation mismatch: ' + key)
    build = metadata_fields(metadata['.BUILDINFO'])
    require(build.get('builddate') == [str(epoch)] and build.get('pkgname') == [package_name] and
            build.get('pkgver') == [f'0.1.0-{release}'], 'build metadata identity mismatch')
    return {'status': 'PASS-exact-authored-package-payload', 'members': len(seen), 'uncompressed_bytes': total,
            'metadata_sha256': {name: hashlib.sha256(body).hexdigest() for name, body in metadata.items()},
            'source_date_epoch': epoch, 'release_authorized': False,
            'scope': 'exact payload, modes, ownership, timestamps and metadata identity; no installation or script execution'}
