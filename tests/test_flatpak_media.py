# SPDX-License-Identifier: MIT
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

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


if __name__ == '__main__':
    unittest.main()
