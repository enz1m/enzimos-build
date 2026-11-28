# SPDX-License-Identifier: MIT
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from build_install_iso import stage_recovery_env
import iso_reports
import native_apps_payload
from contract import Invalid


def package(path, name, version, members, relations=''):
    info = f'pkgname = {name}\npkgver = {version}\narch = x86_64\n{relations}'
    with tarfile.open(path, 'w:zst') as archive:
        for member, (data, mode) in {'.PKGINFO': (info.encode(), 0o644), **members}.items():
            item = tarfile.TarInfo(member)
            item.size, item.mode = len(data), mode
            archive.addfile(item, io.BytesIO(data))
    return path


class IsoReports(unittest.TestCase):
    def test_native_report_admits_published_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            members = {'usr/bin/greetd': (b'\x7fELF greetd', 0o755), 'usr/bin/agreety': (b'\x7fELF agreety', 0o755),
                       'etc/greetd/config.toml': (b'[terminal]\n', 0o644), 'etc/pam.d/greetd': (b'auth\n', 0o644),
                       'usr/lib/systemd/system/greetd.service': (b'[Unit]\n', 0o644),
                       'usr/lib/sysusers.d/greetd.conf': (b'u greeter\n', 0o644)}
            relations = ''.join(f'conflict = {n}\nreplaces = {n}\nprovides = {n}=0.10.3\n'
                                for n in ('greetd', 'greetd-agreety'))
            archive = package(root / 'enzimos-greetd-0.10.3.enzimos1-2-x86_64.pkg.tar.zst', 'enzimos-greetd',
                              '0.10.3.enzimos1-2', members, relations)
            report = iso_reports.native_report('greetd', archive)
            self.assertEqual((report['version'], report['release'], report['replaces']), ('0.10.3.enzimos1', 2, 'greetd'))
            self.assertEqual(report['files']['usr/bin/greetd'],
                             {'sha256': hashlib.sha256(b'\x7fELF greetd').hexdigest(), 'mode': 0o755})
            saved = root / 'greetd.json'
            saved.write_text(json.dumps(report))
            media = root / 'media'
            media.mkdir()
            self.assertEqual(native_apps_payload.stage(saved, media, 'greetd')['release'], 2)

    def test_wrong_package_name_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = package(Path(temporary) / 'other.pkg.tar.zst', 'enzimos-other', '1-1',
                              {'usr/bin/other': (b'x', 0o755)})
            with self.assertRaises(Invalid):
                iso_reports.native_report('mount', archive)

    def test_recovery_environment_declares_archive_package_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / 'recovery.json'
            archive = package(root / 'recovery.pkg.tar.zst', 'enzimos-recovery-env', '0.1.0-2', {})
            report.write_text(json.dumps({'status': 'PASS-recovery-env-built', 'package': str(archive)}))
            self.assertEqual(stage_recovery_env(report, root),
                             {'release': 2, 'sha256': iso_reports.sha256(archive)})

    def test_rust_summary_counts_bound_binaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = {}
            for component, name in iso_reports.RUST_COMPONENTS.items():
                binding = {'artifacts': {f'tool{i}': {} for i in range(2)}, 'resources': {'a': {}}}
                packages[name] = package(root / f'{name}.pkg.tar.zst', name, '0.2.0-3', {
                    f'usr/share/enzimos/rust-candidates/{component}/build.json': (json.dumps(binding).encode(), 0o644)})
            summary = iso_reports.rust_summary(packages)
            self.assertEqual(summary['elf_count'], 10)
            self.assertEqual(summary['packages']['installer']['version'], '0.2.0-3')
            self.assertEqual(summary['packages']['installer']['resource_count'], 1)


if __name__ == '__main__':
    unittest.main()
