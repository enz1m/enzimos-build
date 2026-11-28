# SPDX-License-Identifier: MIT
"""Measure the target's offline payload before sealing the ISO manifest."""
from configparser import ConfigParser
from pathlib import Path
import struct
import subprocess
import tarfile

from contract import Invalid


def package_bytes(path):
    info = subprocess.check_output(['bsdtar', '-qxOf', path, '.PKGINFO'], text=True)
    sizes = [line.removeprefix('size = ') for line in info.splitlines() if line.startswith('size = ')]
    if len(sizes) != 1 or not sizes[0].isascii() or not sizes[0].isdecimal():
        raise Invalid(f'invalid installed package size in {path.name}')
    return int(sizes[0])


def flatpak_bytes(repositories):
    # The system OSTree store shares objects across remotes. In archive-z2
    # the uncompressed file length is the big-endian u64 at byte offset eight.
    seen = set()
    total = 0
    for repo in repositories:
        config = ConfigParser()
        config.read(repo/'config')
        if config.get('core', 'mode', fallback=None) not in ('archive', 'archive-z2'):
            raise Invalid(f'unsupported OSTree storage format in {repo}')
        for path in sorted((repo/'objects').glob('*/*')):
            checksum = path.parent.name + path.name
            if checksum in seen:
                continue
            seen.add(checksum)
            if path.suffix != '.filez':
                total += path.stat().st_size
                continue
            with path.open('rb') as stream:
                data = stream.read(16)
            if len(data) != 16:
                raise Invalid(f'truncated OSTree object {path}')
            header, padding, size = struct.unpack('>IIQ', data)
            if padding != 0 or not 8 <= header <= path.stat().st_size - 8 or size > 64 * 1024**3:
                raise Invalid(f'invalid OSTree archive header in {path}')
            total += size
    return total


def measure(media: Path):
    def arch_bytes(name):
        return sum(package_bytes(media/'packages'/line)
                   for line in (media/name).read_text().splitlines())

    models = media/'ai-ai-models.pkg.tar.zst'
    desktop = media/'desktop-preview.tar.zst'
    desktop_bytes = 0
    if desktop.is_file():
        with tarfile.open(desktop, 'r|zst') as archive:
            desktop_bytes = sum(member.size for member in archive if member.isfile())
    ipts = media/'ipts-dkms.pkg.tar.zst'
    return {
        'base_bytes': arch_bytes('package-files.txt') + sum(
            package_bytes(path) for path in sorted(media.glob('*.pkg.tar.zst')) if path not in (models, ipts)
        ),
        'nvidia_bytes': arch_bytes('nvidia-files.txt'),
        **({'surface_bytes': arch_bytes('surface-files.txt') + package_bytes(ipts)} if ipts.is_file() else {}),
        'models_bytes': package_bytes(models) if models.is_file() else 0,
        'desktop_bytes': desktop_bytes,
        'flatpak_bytes': flatpak_bytes(
            media/name/'repo' for name in ('flatpak', 'flatpak-enzimos') if (media/name).is_dir()
        ),
    }
