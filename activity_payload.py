# SPDX-License-Identifier: MIT
"""Audit the owned activity package before adding it to development install media."""
import hashlib
import json
from pathlib import Path
import shutil
import tarfile


def stage(report_path, media):
    report = json.loads(Path(report_path).read_text())
    package = Path(report['package']).resolve(strict=True)
    if report.get('status') != 'PASS-activity-service-package-built' or report.get('package_name') != 'enzimos-activity-service':
        raise ValueError('reviewed activity package required')
    if not package.is_file() or package.stat().st_size > 32 * 1024**2:
        raise ValueError('bounded activity package required')
    with package.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != report['sha256']:
            raise ValueError('activity package digest mismatch')
    expected = report['files']
    seen = set()
    total = 0
    metadata = {}
    with tarfile.open(package, 'r|zst') as archive:
        for member in archive:
            path = Path(member.name)
            total += member.size
            if path.is_absolute() or '..' in path.parts or member.uid != 0 or member.gid != 0 or not (member.isfile() or member.isdir()) or total > 64 * 1024**2 or member.size > 32 * 1024**2:
                raise ValueError('invalid activity archive member')
            if member.isdir():
                continue
            if member.name in seen:
                raise ValueError('duplicate activity member')
            seen.add(member.name)
            body = archive.extractfile(member).read()
            if member.name in ('.PKGINFO', '.BUILDINFO', '.MTREE'):
                metadata[member.name] = body
            elif member.name not in expected or hashlib.sha256(body).hexdigest() != expected[member.name]['sha256'] or member.mode != expected[member.name]['mode']:
                raise ValueError('activity inventory mismatch')
    if seen - set(metadata) != set(expected) or '.PKGINFO' not in metadata:
        raise ValueError('incomplete activity inventory')
    info = metadata['.PKGINFO'].decode()
    if '\npkgname = enzimos-activity-service\n' not in '\n' + info or '\narch = x86_64\n' not in '\n' + info or '\npkgver = 0.1.0-' + str(report['release']) + '\n' not in '\n' + info:
        raise ValueError('activity package identity mismatch')
    destination = Path(media) / 'activity-service.pkg.tar.zst'
    shutil.copyfile(package, destination)
    return {'release': report['release'], 'sha256': report['sha256'], 'package_name': report['package_name']}
