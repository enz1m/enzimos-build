# SPDX-License-Identifier: MIT
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from contract import Invalid
from storage_payload import flatpak_bytes, package_bytes


class StoragePayloadTests(unittest.TestCase):
    def test_reads_installed_package_size(self):
        package = Path('example.pkg.tar.zst')
        with patch('storage_payload.subprocess.check_output', return_value='size = 987654\n'):
            self.assertEqual(package_bytes(package), 987654)
        with patch('storage_payload.subprocess.check_output', return_value='size = 1\nsize = 2\n'):
            with self.assertRaises(Invalid):
                package_bytes(package)

    def test_counts_unpacked_objects_once_across_remotes(self):
        with tempfile.TemporaryDirectory() as temporary:
            repos = [Path(temporary)/name for name in ('first', 'second')]
            for repo in repos:
                objects = repo/'objects'/'ab'
                objects.mkdir(parents=True)
                (repo/'config').write_text('[core]\nmode=archive-z2\n')
                (objects/'one.filez').write_bytes(struct.pack('>IIQ', 8, 0, 1024))
            (repos[1]/'objects/ab/two.dirtree').write_bytes(b'xyz')
            self.assertEqual(flatpak_bytes(repos), 1027)
            (repos[1]/'objects/ab/invalid.filez').write_bytes(b'x')
            with self.assertRaises(Invalid):
                flatpak_bytes(repos)
