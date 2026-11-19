# SPDX-License-Identifier: MIT
"""Bind the live and installed desktop to the independently packaged Terminal."""
import json
import os
from pathlib import Path
import subprocess
import tarfile
from native_apps_payload import stage


def overlay(report_path, desktop, output):
    desktop = Path(desktop).resolve(strict=True)
    output = Path(output).absolute()
    if output.exists():
        raise ValueError('new Terminal desktop stage required')
    report = json.loads(Path(report_path).read_text())
    admission = output.parent / (output.name + '-admission')
    admission.mkdir(exist_ok=False)
    receipt = stage(report_path, admission, 'terminal')
    subprocess.run(['cp', '--reflink=always', '-a', str(desktop), str(output)], check=True)
    with tarfile.open(admission/'terminal.pkg.tar.zst', 'r|zst') as archive:
        for member in archive:
            if member.name not in report['files']:
                continue
            destination = output / member.name
            if not destination.parent.resolve().is_relative_to(output.resolve()):
                raise ValueError('Terminal destination escapes desktop')
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.is_symlink():
                destination.unlink()
            with archive.extractfile(member) as source, destination.open('wb') as target:
                while block := source.read(1024 * 1024):
                    target.write(block)
            destination.chmod(report['files'][member.name]['mode'])
            # Same bytes and time as the package, so pacman -Qkk stays clean.
            os.utime(destination, (member.mtime, member.mtime))
    binding = {'schema': 1, 'component': 'terminal', 'repository': 'enzimos-terminal',
               'revision': report['revision'], 'package': receipt,
               'producer_manifest_preserved': True, 'release_authorized': False}
    (output/'usr/share/enzui/terminal-ownership.json').write_text(json.dumps(binding, indent=2)+'\n')
    return output
