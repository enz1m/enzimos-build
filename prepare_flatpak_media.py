#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare signed default Flatpaks and their runtimes for offline installation."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.request import urlopen

from build_install_iso import (
    ENZIMOS_DESCRIPTOR_SHA256, OFFICIAL_FLATPAK_MEDIA, require_runtime_graphics,
)

HERE = Path(__file__).resolve().parent
ENZIMOS_DESCRIPTOR = 'https://flatpak.enzim.dev/enzimos.flatpakrepo'


def run(env, *args, capture=False):
    return subprocess.run(
        ['flatpak', *map(str, args)], env=env, check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
    ).stdout


def prepare(output, flathub_descriptor, sideloads):
    apps = (HERE / 'default-flatpaks.txt').read_text().splitlines()
    output.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(output):
        raise ValueError(f'Choose a new output directory: {output}')
    with tempfile.TemporaryDirectory(prefix='.flatpak-media-', dir=output.parent) as temporary:
        root = Path(temporary)
        env = os.environ | {
            'FLATPAK_SYSTEM_DIR': str(root / 'system'),
            'FLATPAK_CONFIG_DIR': str(root / 'etc'),
            'XDG_DATA_HOME': str(root / 'data'),
            'XDG_CACHE_HOME': str(root / 'cache'),
            'XDG_CONFIG_HOME': str(root / 'config'),
        }
        export = root / 'media'
        flathub, enzimos = export / 'flathub', export / 'enzimos'
        flathub.mkdir(parents=True)
        enzimos.mkdir()
        shutil.copyfile(flathub_descriptor, flathub / 'flathub.flatpakrepo')
        with urlopen(ENZIMOS_DESCRIPTOR, timeout=20) as response:
            descriptor = response.read(128 * 1024)
        if hashlib.sha256(descriptor).hexdigest() != ENZIMOS_DESCRIPTOR_SHA256:
            raise ValueError('The public enzimOS Flatpak descriptor has changed')
        (enzimos / 'enzimos.flatpakrepo').write_bytes(descriptor)

        for directory, name, collection in (
            (flathub, 'flathub', 'org.flathub.Stable'),
            (enzimos, 'enzimos', 'org.enzimos.Apps'),
        ):
            run(env, 'remote-add', '--user', '--from', '--no-follow_redirect',
                '--no-authenticator-install', name, directory / f'{name}.flatpakrepo')
            run(env, 'remote-modify', '--user', f'--collection-id={collection}', name)

        cached = [f'--sideload-repo={source.resolve(strict=True)}' for source in sideloads]
        install = ['install', '--user', '--noninteractive', '--arch=x86_64', *cached]
        refs = [f'app/{app}/x86_64/stable' for app in apps]
        run(env, *install, 'enzimos', *refs)
        runtimes = run(env, 'list', '--user', '--runtime', '--columns=ref,origin', capture=True)
        flathub_refs = [ref for ref, origin in (line.split('\t') for line in runtimes.splitlines())
                        if origin == 'flathub' and '.Locale/' not in ref]
        for ref in list(flathub_refs):
            if ref.startswith('org.freedesktop.Platform/x86_64/'):
                branch = ref.rsplit('/', 1)[-1]
                for suffix in ('', '-extra'):
                    gl = f'org.freedesktop.Platform.GL.default/x86_64/{branch}{suffix}'
                    if gl not in flathub_refs:
                        run(env, *install, 'flathub', 'runtime/' + gl)
                        flathub_refs.append(gl)

        # The enzimOS transaction needs a single complete mirror. Flathub’s
        # sibling mirror only needs the GL refs it can preinstall separately.
        graphics = ['runtime/' + ref for ref in flathub_refs
                    if ref.startswith('org.freedesktop.Platform.GL.default/')]
        for directory, selection in (
            (enzimos, [*refs, *graphics]),
            (flathub, graphics),
        ):
            usb = directory / 'usb'
            repo = usb / '.ostree/repo'
            repo.mkdir(parents=True)
            subprocess.run(['ostree', f'--repo={repo}', 'init', '--mode=archive'], check=True)
            subprocess.run(['ostree', f'--repo={repo}', 'config', 'set',
                            'core.min-free-space-size', '2GB'], check=True)
            run(env, 'create-usb', '--user', usb, *selection)
            subprocess.run(['ostree', f'--repo={repo}', 'config', 'unset',
                            'core.min-free-space-size'], check=True)
            require_runtime_graphics(repo)

        (flathub / 'apps.txt').touch()
        (enzimos / 'apps.txt').write_text(''.join(f'{app}\n' for app in apps))
        commits = {app: run(env, 'info', '--user', '--show-commit', app, capture=True).strip()
                   for app in apps}
        (enzimos / 'build.json').write_text(json.dumps({
            'status': 'PASS-enzimos-flatpaks-prepared', 'provenance': OFFICIAL_FLATPAK_MEDIA,
            'apps': apps, 'commits': commits, 'descriptor_sha256': ENZIMOS_DESCRIPTOR_SHA256,
        }, indent=2) + '\n')
        export.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--flathub-descriptor', type=Path, required=True)
    parser.add_argument('--sideload-repo', type=Path, action='append', default=[])
    args = parser.parse_args()
    prepare(args.output.resolve(), args.flathub_descriptor, args.sideload_repo)


if __name__ == '__main__':
    main()
