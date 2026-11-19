# SPDX-License-Identifier: MIT
"""Pure archive/source-boundary tests. No makepkg, mounts, installation or VMs."""
import copy
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract import Invalid
import native_package_audit as audit
import reproduce_native_policy as reproduce

LICENSE = b'Authored license fixture\n'
INSTALL = b'# Test install-script bytes, never executed\n'


def fixture():
    entries = {name: {'mode': 0o755, 'body': None} for name in ('etc', 'etc/sudoers.d', 'usr', 'usr/share')}
    entries['etc/sudoers.d/20-enzimos-wheel'] = {'mode': 0o644, 'body': b'%wheel ALL=(ALL:ALL) ALL\n'}
    expected = copy.deepcopy(entries)
    expected['etc/sudoers.d/20-enzimos-wheel']['mode'] = 0o440
    for name in ('usr/share/licenses', 'usr/share/licenses/enzimos-native-policy'):
        expected[name] = {'mode': 0o755, 'body': None}
    expected[audit.LICENSE_PATH] = {'mode': 0o644, 'body': LICENSE}
    for name, body in {'.PKGINFO': f'pkgname = enzimos-native-policy\npkgver = 0.1.0-14\narch = any\nlicense = MIT\nbuilddate = {audit.EPOCH}\n'.encode(),
                       '.BUILDINFO': f'pkgname = enzimos-native-policy\npkgver = 0.1.0-14\nbuilddate = {audit.EPOCH}\n'.encode(),
                       '.INSTALL': INSTALL, '.MTREE': b'opaque metadata checked by hash, not interpreted'}.items():
        expected[name] = {'mode': 0o644, 'body': body}
    return entries, expected


def write_archive(path, items, mutate=lambda item: None):
    with tarfile.open(path, 'w') as archive:
        for name, value in items:
            member = tarfile.TarInfo(name)
            member.mode = value['mode'];member.mtime = audit.EPOCH
            body = value['body'];member.type = tarfile.DIRTYPE if body is None else tarfile.REGTYPE
            member.size = len(body) if body is not None else 0
            mutate(member)
            archive.addfile(member, io.BytesIO(body) if body is not None and member.isfile() else None)


class NativePackageAuditTests(unittest.TestCase):
    def check(self, entries, expected, mutate=lambda item: None):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'fixture.tar'
            write_archive(path, expected, mutate)
            return audit.audit(path, entries, LICENSE, INSTALL, 14, recipe='')

    def test_exact_payload_and_no_execution(self):
        entries, expected = fixture()
        with patch('subprocess.run', side_effect=AssertionError('must not execute')):
            result = self.check(entries, expected.items())
        self.assertEqual(result['status'], 'PASS-exact-authored-package-payload')
        self.assertFalse(result['release_authorized'])

    def test_backend_identity_has_distinct_license_and_no_sudoers_requirement(self):
        _, expected = fixture()
        expected = {name.replace('enzimos-native-policy', 'enzimos-system-backend'): value for name, value in expected.items()
                    if not name.startswith('etc')}
        for name in ('.PKGINFO', '.BUILDINFO'):
            expected[name]['body'] = expected[name]['body'].replace(b'enzimos-native-policy', b'enzimos-system-backend')
        entries = {name: value for name, value in expected.items() if name in ('usr', 'usr/share')}
        recipe = (
            "depends=('enzimos-native-policy=0.1.0-119' 'polkit')\n"
            'provides=("enzimos-backend-legacy=$pkgver-$pkgrel")\n'
            "conflicts=('enzimos-backend-legacy')\n"
            "replaces=('enzimos-backend-legacy')\n"
        )
        relations = (
            b'depend = polkit\n',
            b'depend = enzimos-native-policy=0.1.0-119\n',
            b'provides = enzimos-backend-legacy=0.1.0-14\n',
            b'conflict = enzimos-backend-legacy\n',
            b'replaces = enzimos-backend-legacy\n',
        )
        expected['.PKGINFO']['body'] += b''.join(relations)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'backend.tar'
            write_archive(path, expected.items())

            def check_backend():
                return audit.audit(path, entries, LICENSE, INSTALL, 14,
                                   package_name='enzimos-system-backend', recipe=recipe)

            self.assertEqual(check_backend()['status'], 'PASS-exact-authored-package-payload')
            with self.assertRaises(Invalid):
                audit.audit(path, entries, LICENSE, INSTALL, 14, recipe='')
            with self.assertRaisesRegex(Invalid, 'unreviewed'):
                audit.audit(path, entries, LICENSE, INSTALL, 14, package_name='arbitrary', recipe='')

            for relation in relations:
                for replacement in (b'', relation + relation):
                    with self.subTest(relation=relation, replacement=replacement):
                        changed = copy.deepcopy(expected)
                        changed['.PKGINFO']['body'] = changed['.PKGINFO']['body'].replace(relation, replacement)
                        write_archive(path, changed.items())
                        with self.assertRaisesRegex(Invalid, 'package metadata relation mismatch'):
                            check_backend()

    def test_missing_extra_duplicate_and_escaping_paths(self):
        entries, expected = fixture();items = list(expected.items())
        for invalid in (items[:-1], items+[('extra', {'mode': 0o644, 'body': b'x'})], items+[items[0]],
                        items+[('../escape', {'mode': 0o644, 'body': b'x'})]):
            with self.subTest(invalid=invalid[-1][0]), self.assertRaises(Invalid):
                self.check(entries, invalid)

    def test_payload_install_and_license_tampering(self):
        entries, expected = fixture()
        for name in ('etc/sudoers.d/20-enzimos-wheel', audit.LICENSE_PATH, '.INSTALL'):
            changed = copy.deepcopy(expected);changed[name]['body'] += b'changed'
            with self.subTest(name=name), self.assertRaises(Invalid):
                self.check(entries, changed.items())

    def test_metadata_duplicate_identity_wrong_version_and_build_time(self):
        entries, expected = fixture()
        for name, extra in (('.PKGINFO', b'pkgver = 0.1.0-99\n'), ('.BUILDINFO', b'builddate = 1\n')):
            changed = copy.deepcopy(expected);changed[name]['body'] += extra
            with self.assertRaises(Invalid):self.check(entries, changed.items())

    def test_optional_absent_project_url_is_not_an_empty_identity(self):
        entries, expected = fixture()
        expected['.PKGINFO']['body'] += b'url = \n'
        self.assertEqual(self.check(entries, expected.items())['status'], 'PASS-exact-authored-package-payload')
        expected['.PKGINFO']['body'] += b'pkgname = \n'
        with self.assertRaisesRegex(Invalid, 'malformed package metadata'):
            self.check(entries, expected.items())

    def test_owner_timestamp_mode_and_link_refusal(self):
        entries, expected = fixture()
        for attribute, value in (('uid', 1000), ('gid', 1000), ('mtime', 0), ('mode', 0o777), ('type', tarfile.SYMTYPE)):
            def mutate(member):
                if member.name == 'etc':setattr(member, attribute, value)
            with self.subTest(attribute=attribute), self.assertRaises(Invalid):
                self.check(entries, expected.items(), mutate)

    def test_uncompressed_size_and_member_budgets(self):
        entries, expected = fixture()
        with patch.object(audit, 'MAX_MEMBERS', 2), self.assertRaises(Invalid):
            self.check(entries, expected.items())
        # A small compressed stream must not evade the expanded-byte budget.
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'large.tar.gz'
            with tarfile.open(path, 'w:gz') as archive:
                member = tarfile.TarInfo('oversize');member.mtime = audit.EPOCH
                member.size = audit.MAX_BYTES+1
                archive.addfile(member, io.BytesIO(b'0'*member.size))
            with self.assertRaisesRegex(Invalid, 'member size'):
                audit.audit(path, entries, LICENSE, INSTALL, 14, recipe='')

    def test_hidden_pax_header_cannot_bypass_expanded_stream_budget(self):
        entries, _ = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'pax-bomb.tar.gz'
            with tarfile.open(path, 'w:gz') as archive:
                header = tarfile.TarInfo('pax-header');header.type = tarfile.XHDTYPE
                header.size = audit.MAX_BYTES + audit.MAX_MEMBERS*1024 + 32768
                archive.addfile(header, io.BytesIO(b'0'*header.size))
            with self.assertRaisesRegex(Invalid, 'expanded archive stream bound'):
                audit.audit(path, entries, LICENSE, INSTALL, 14, recipe='')

    def test_source_snapshot_captures_bytes_and_modes_ignores_bytecode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);(root/'dir').mkdir(mode=0o755)
            file = root/'dir/script';file.write_bytes(b'original');file.chmod(0o755)
            (root/'__pycache__').mkdir();(root/'__pycache__/ignored.pyc').write_bytes(b'cache')
            data = audit.source_snapshot(root);file.write_bytes(b'changed')
            self.assertEqual(data['dir/script'], {'body': b'original', 'mode': 0o755})
            self.assertNotIn('__pycache__', data)

    def test_symlink_directory_fifo_and_privileged_mode_source_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);bad = root/'bad'
            bad.symlink_to('/usr', target_is_directory=True)
            with self.assertRaises(Invalid):audit.source_snapshot(root)
            bad.unlink();os.mkfifo(bad)
            with self.assertRaises(Invalid):audit.source_snapshot(root)
            bad.unlink();bad.write_bytes(b'file');bad.chmod(0o4755)
            with self.assertRaises(Invalid):audit.source_snapshot(root)
            bad.chmod(0o666)
            with self.assertRaises(Invalid):audit.source_snapshot(root)

    def test_reproduction_rejects_input_drift_or_archive_difference(self):
        report = {key: {} for key in ('sources', 'source_modes', 'build_inputs', 'builder_sources', 'payload_audit')}
        report.update(release=14, source_date_epoch=audit.EPOCH, package='unused', sha256='a'*64)
        with patch.object(reproduce, 'digest', return_value='a'*64):
            result = reproduce.compare(report, copy.deepcopy(report))
            self.assertFalse(result['clean_arch_toolchain']);self.assertFalse(result['release_authorized'])
            with self.assertRaisesRegex(Invalid, 'identities differ'):
                reproduce.compare(report, dict(report, package_name='enzimos-system-backend'))
            changed = copy.deepcopy(report);changed['source_modes']['file'] = 0o755
            with self.assertRaisesRegex(Invalid, 'inputs differ'):reproduce.compare(report, changed)
        changed = dict(report, sha256='b'*64)
        with patch.object(reproduce, 'digest', side_effect=['a'*64, 'b'*64]), self.assertRaisesRegex(Invalid, 'archives differ'):
            reproduce.compare(report, changed)


if __name__ == '__main__':
    unittest.main()
