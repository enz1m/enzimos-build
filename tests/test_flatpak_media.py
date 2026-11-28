# SPDX-License-Identifier: MIT
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import build_install_iso
from contract import Invalid


FLATHUB_APP = 'org.example.Viewer'
BROWSER = 'org.enzim.Browser'


def source(root, name, remote, apps, status=None):
    directory = root / name
    repo = directory / 'usb/.ostree/repo'
    repo.mkdir(parents=True)
    (repo / 'config').write_text('[core]\n')
    (directory / remote).write_text('[Flatpak Repo]\n')
    (directory / 'apps.txt').write_text(''.join(app + '\n' for app in apps))
    if status:
        (directory / 'build.json').write_text(json.dumps({'status': status}))
    return directory


class FlatpakMediaTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_each_remote_gets_its_own_directory_and_declaration(self):
        flathub = source(self.root, 'fh', 'flathub.flatpakrepo', [FLATHUB_APP])
        ours = source(self.root, 'ez', 'enzimos.flatpakrepo', [BROWSER],
                      'PASS-enzimos-flatpaks-prepared')
        media = self.root / 'media'
        media.mkdir()
        declared = build_install_iso.stage_flatpaks(media, flathub, ours)
        self.assertEqual(declared, ([FLATHUB_APP], {'enzimos_flatpaks': [BROWSER]}))
        for name in ('flatpak/repo/config', 'flatpak/flathub.flatpakrepo',
                     'flatpak-enzimos/repo/config', 'flatpak-enzimos/enzimos.flatpakrepo',
                     'flatpak-enzimos/apps.txt'):
            self.assertTrue((media / name).is_file(), name)
        self.assertEqual(build_install_iso.stage_flatpaks(self.root / 'empty'), ([], {}))

        repo = media / 'flatpak-enzimos/repo'
        alias = repo / 'refs/browser'
        alias.parent.mkdir()
        alias.symlink_to('../config')
        build_install_iso.write_media_checksums(media)
        expected = hashlib.sha256((repo / 'config').read_bytes()).hexdigest()
        checksums = (media / 'SHA256SUMS').read_text().splitlines()
        self.assertIn(f'{expected}  flatpak-enzimos/repo/refs/browser', checksums)

        alias.unlink()
        alias.symlink_to('../../apps.txt')
        with self.assertRaises(Invalid):
            build_install_iso.write_media_checksums(media)

    def test_enzimos_source_needs_flathub_a_passed_export_and_distinct_apps(self):
        flathub = source(self.root, 'fh', 'flathub.flatpakrepo', [FLATHUB_APP])
        for name, apps, status, base in (
            ('alone', [BROWSER], 'PASS-enzimos-flatpaks-prepared', None),
            ('failed', [BROWSER], 'FAIL', flathub),
            ('overlap', [FLATHUB_APP], 'PASS-enzimos-flatpaks-prepared', flathub),
            ('duplicates', [BROWSER, BROWSER], 'PASS-enzimos-flatpaks-prepared', flathub),
        ):
            with self.subTest(name=name):
                ours = source(self.root, name, 'enzimos.flatpakrepo', apps, status)
                media = self.root / ('media-' + name)
                media.mkdir()
                with self.assertRaises(Invalid):
                    build_install_iso.stage_flatpaks(media, base, ours)
                self.assertEqual(list(media.iterdir()), [])

    def test_legacy_zen_export_supplies_runtimes_without_selecting_zen(self):
        zen = 'app.zen_browser.zen'
        flathub = source(self.root, 'fh', 'flathub.flatpakrepo', [zen])
        ours = source(self.root, 'ez', 'enzimos.flatpakrepo', [BROWSER],
                      'PASS-enzimos-flatpaks-prepared')
        media = self.root / 'media'
        media.mkdir()
        with self.assertRaisesRegex(Invalid, 'installer 0.2.0-3'):
            build_install_iso.stage_flatpaks(media, flathub, ours, installer_version=(0, 2, 0, 2))
        self.assertEqual(list(media.iterdir()), [])
        self.assertEqual(
            build_install_iso.stage_flatpaks(media, flathub, ours),
            ([], {'enzimos_flatpaks': [BROWSER]}),
        )
        self.assertTrue((media / 'flatpak/repo/config').is_file())
        self.assertEqual((media / 'flatpak/apps.txt').read_bytes(), b'')
        self.assertEqual((flathub / 'apps.txt').read_text().splitlines(), [zen])
        self.assertEqual(build_install_iso.stage_flatpaks(self.root / 'none', flathub), ([], {}))
        self.assertFalse((self.root / 'none').exists())

    def test_official_media_requires_the_signed_fleet_and_current_installer(self):
        apps = Path(build_install_iso.__file__).with_name('default-flatpaks.txt').read_text().splitlines()
        flathub = source(self.root, 'fh', 'flathub.flatpakrepo', [])
        ours = source(self.root, 'ez', 'enzimos.flatpakrepo', apps)
        commit = 'a' * 64
        (ours/'build.json').write_text(json.dumps({
            'status': 'PASS-enzimos-flatpaks-prepared',
            'provenance': build_install_iso.OFFICIAL_FLATPAK_MEDIA,
            'apps': apps,
            'commits': dict.fromkeys(apps, commit),
        }))
        repo = ours/'usb/.ostree/repo/refs/mirrors/org.enzimos.Apps'
        for name in [*(f'app/{app}/x86_64/stable' for app in apps),
                     'runtime/dev.enzim.WebKit.Platform/x86_64/26.08-1']:
            ref = repo/name
            ref.parent.mkdir(parents=True)
            ref.write_text(commit + '\n')
        expected = build_install_iso.digest(ours/'enzimos.flatpakrepo')
        with patch.object(build_install_iso, 'ENZIMOS_DESCRIPTOR_SHA256', expected):
            with self.assertRaisesRegex(Invalid, '0.2.0-4'):
                build_install_iso.stage_flatpaks(self.root/'old', flathub, ours)
            self.assertEqual(
                build_install_iso.stage_flatpaks(self.root/'current', flathub, ours, installer_version=(0, 2, 1, 1)),
                ([], {'enzimos_flatpaks': apps}),
            )
            (repo/f'app/{BROWSER}/x86_64/stable').write_text('b' * 64)
            with self.assertRaisesRegex(Invalid, f'stable deployment for {BROWSER}'):
                build_install_iso.stage_flatpaks(self.root/'changed', flathub, ours, installer_version=(0, 2, 0, 4))

    def test_each_sideload_carries_its_platform_graphics_extensions(self):
        def ref(directory, name, collection='org.flathub.Stable'):
            path = directory / 'usb/.ostree/repo/refs/mirrors' / collection / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('0' * 64 + '\n')
        platform = 'runtime/org.freedesktop.Platform/x86_64/26.08'
        gl = 'runtime/org.freedesktop.Platform.GL.default/x86_64/26.08'
        flathub = source(self.root, 'fh', 'flathub.flatpakrepo', [FLATHUB_APP])
        for name, refs, collection, accepted in (
            ('complete', [platform, gl, gl + '-extra'], 'org.flathub.Stable', True),
            ('apps-only', [], 'org.flathub.Stable', True),
            ('without-gl', [platform], 'org.flathub.Stable', False),
            ('without-extra', [platform, gl], 'org.flathub.Stable', False),
            ('wrong-collection', [platform, gl, gl + '-extra'], 'org.enzimos.Apps', False),
        ):
            with self.subTest(name=name):
                ours = source(self.root, name, 'enzimos.flatpakrepo', [BROWSER],
                              'PASS-enzimos-flatpaks-prepared')
                for value in refs:
                    ref(ours, value, collection if value != platform else 'org.flathub.Stable')
                media = self.root / ('media-' + name)
                media.mkdir()
                if accepted:
                    build_install_iso.stage_flatpaks(media, flathub, ours)
                else:
                    with self.assertRaises(Invalid):
                        build_install_iso.stage_flatpaks(media, flathub, ours)
                    self.assertEqual(list(media.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
