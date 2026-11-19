# SPDX-License-Identifier: MIT
"""Bootstrap archive policy checks, not an extractor or a partition engine."""
from collections import Counter
import posixpath
import re
from pathlib import Path
import sys
import tarfile
from contract import Invalid

ROOT = 'root.x86_64'
TOP_FILES = {'version', 'pkglist.x86_64.txt'}
MAX_MEMBERS = 50000
MAX_UNPACKED = 1024**3


def invalid_text(value):
    if type(value) is not str or len(value) > 4096:
        return True
    # systemd unit filenames legitimately contain literal POSIX backslash-xHH escapes.
    remainder = re.sub(r'\\x[0-9a-fA-F]{2}', '', value)
    return '\\' in remainder or any(ord(c) < 32 or ord(c) == 127 for c in value)


def name_check(name):
    if invalid_text(name):
        raise Invalid('invalid archive path')
    name = name.rstrip('/')
    if not name or name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/')):
        raise Invalid('archive path escapes or is not canonical')
    if name not in TOP_FILES and name != ROOT and not name.startswith(ROOT + '/'):
        raise Invalid('unexpected top-level archive member')
    return name


def describe(member):
    name = name_check(member.name)
    if member.isdir():
        kind = 'directory'
    elif member.isfile():
        kind = 'file'
    elif member.issym():
        kind = 'symlink'
    elif member.islnk():
        kind = 'hardlink'
    else:
        raise Invalid('device/FIFO/socket/unknown archive entries are forbidden')
    if name in TOP_FILES and kind != 'file':
        raise Invalid('top-level metadata must be regular files')
    if name == ROOT and kind != 'directory':
        raise Invalid('toolroot must be a directory')
    if type(member.size) is not int or member.size < 0 or member.size > MAX_UNPACKED:
        raise Invalid('invalid archive entry size')
    if kind != 'file' and member.size != 0:
        raise Invalid('non-file archive entry has data')
    if getattr(member, 'sparse', None) is not None:
        raise Invalid('sparse entries are outside this bootstrap contract')
    target = None
    if kind in ('symlink', 'hardlink'):
        link = member.linkname
        if not link or invalid_text(link):
            raise Invalid('invalid link target')
        if kind == 'hardlink':
            target = name_check(link)
        elif link.startswith('/'):
            # Absolute symlinks are guest-root paths, not paths to follow on the host.
            target = posixpath.normpath(ROOT + '/' + link.lstrip('/'))
        else:
            target = posixpath.normpath(posixpath.join(posixpath.dirname(name), link))
        if target != ROOT and not target.startswith(ROOT + '/'):
            raise Invalid('link escapes guest-root namespace')
    return {'name': name, 'kind': kind, 'size': member.size, 'target': target,
            'mode': member.mode, 'uid': member.uid, 'gid': member.gid}


def validate_members(members):
    entries = {}
    total = 0
    modes_stripped = 0
    for member in members:
        row = describe(member)
        if row['name'] in entries:
            raise Invalid('duplicate archive path')
        entries[row['name']] = row
        total += row['size']
        modes_stripped += bool(row['mode'] & 0o6000)
        if len(entries) > MAX_MEMBERS or total > MAX_UNPACKED:
            raise Invalid('archive member/unpacked-size budget exceeded')
    if ROOT not in entries or not TOP_FILES.issubset(entries):
        raise Invalid('bootstrap root/version/package inventory missing')
    for name, row in entries.items():
        parent = posixpath.dirname(name)
        while parent:
            if parent not in entries or entries[parent]['kind'] != 'directory':
                raise Invalid('archive member has a missing or non-directory ancestor')
            parent = posixpath.dirname(parent)
        if row['kind'] == 'hardlink':
            target = row['target']
            visited = {name}
            while True:
                if target in visited or target not in entries:
                    raise Invalid('cyclic/missing hardlink target')
                visited.add(target)
                if entries[target]['kind'] == 'file':
                    break
                if entries[target]['kind'] != 'hardlink':
                    raise Invalid('hardlink target must resolve to a regular archive file')
                target = entries[target]['target']
    return {'archive_policy_valid': True, 'members': len(entries), 'regular_bytes': total,
            'entry_types': dict(Counter(row['kind'] for row in entries.values())),
            'privileged_mode_entries_to_strip': modes_stripped,
            'absolute_symlinks_are_guest_paths': True, 'deployable_root': False,
            'release_authorized': False}


def audit_archive(path):
    if sys.version_info < (3, 14):
        raise Invalid('bootstrap zstd audit requires Python 3.14+; no interpreter is installed automatically')
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 192 * 1024**2:
        raise Invalid('archive is not a bounded regular input')
    try:
        with tarfile.open(path, mode='r|zst') as archive:
            return validate_members(archive)
    except (tarfile.TarError, EOFError) as exc:
        raise Invalid('invalid bootstrap archive') from exc
