# SPDX-License-Identifier: MIT
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract import Invalid
from build_initrd_lab import audit_packages, builder_argv, build
from package_closure import compare_resolution


class PackageBuildTests(unittest.TestCase):
    def test_closure_requires_exact_package_identity_and_hash_set(self):
        rows = [{'name': 'base', 'version': '1-1', 'architecture': 'any', 'sha256_from_metadata': 'a' * 64}]
        text = 'base\t1-1\tany\t' + 'a' * 64 + '\n'
        self.assertEqual(compare_resolution(text, rows), 1)
        for bad in (text + text, text.replace('1-1', '2-1'), text.replace('a' * 64, 'b' * 64), ''):
            with self.assertRaises(Invalid):
                compare_resolution(bad, rows)

    def test_builder_uid_zero_is_inside_user_namespace_not_host_root(self):
        args = builder_argv(Path('/private/root'), Path('/private/artifacts'), ['/usr/bin/depmod', '-a', 'fixture'])
        self.assertIn('--unshare-all', args)
        self.assertEqual(args[args.index('--uid') + 1], '0')
        self.assertNotIn('--dev-bind', args)
        self.assertNotIn('/dev/kvm', args)
        with patch('build_initrd_lab.os.geteuid', return_value=0):
            with self.assertRaises(Invalid):
                build(None, None, None, None, None)

    @unittest.skipIf(sys.version_info < (3, 14), 'zstd package audit requires Python 3.14')
    def test_package_identity_and_path_checks_before_assembly(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for path, declared in (('usr/file', 'base'), ('../escape', 'base'), ('usr/file', 'wrong')):
                archive = root / 'base.pkg.tar.zst'
                with tarfile.open(archive, 'w:zst') as tar:
                    data = f'pkgname = {declared}\npkgver = 1-1\narch = any\n'.encode()
                    info = tarfile.TarInfo('.PKGINFO'); info.size = len(data); tar.addfile(info, io.BytesIO(data))
                    info = tarfile.TarInfo(path); info.size = 4; tar.addfile(info, io.BytesIO(b'data'))
                row = {'name': 'base', 'version': '1-1', 'architecture': 'any', 'url': 'https://example.invalid/base.pkg.tar.zst',
                       'sha256_from_metadata': hashlib.sha256(archive.read_bytes()).hexdigest()}
                if path == 'usr/file' and declared == 'base':
                    self.assertEqual(len(audit_packages(root, [row])['identities']), 1)
                    with self.assertRaises(Invalid):
                        audit_packages(root, [row], max_unpacked=3)
                    self.assertEqual(audit_packages(root, [row], max_unpacked=4)['regular_and_metadata_bytes'], 4)
                else:
                    with self.assertRaises(Invalid):
                        audit_packages(root, [row])

    def test_explicit_compiler_budget_is_bounded_and_does_not_change_default(self):
        for invalid in (True, False, 0, -1, 4 * 1024**3 + 1, '4096', 1.5):
            with self.subTest(limit=invalid), self.assertRaises(Invalid):
                audit_packages(Path('/unused'), [], max_unpacked=invalid)
        self.assertEqual(audit_packages(Path('/unused'), [], max_unpacked=4 * 1024**3)['members'], 0)
        with patch('build_initrd_lab.MAX_UNPACKED', 0):
            with self.assertRaises(Invalid):
                audit_packages(Path('/unused'), [])
            self.assertEqual(audit_packages(Path('/unused'), [], max_unpacked=1)['members'], 0)


if __name__ == '__main__':
    unittest.main()
