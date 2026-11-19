# SPDX-License-Identifier: MIT
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from activity_payload import stage


class ActivityPayloadTests(unittest.TestCase):
    def build(self, root, wrong_name=False, duplicate=False, link=False):
        package = root / 'activity.pkg.tar.zst'
        body = b'fixture executable'
        info = b'pkgname = ' + (b'wrong-package' if wrong_name else b'enzimos-activity-service') + b'\npkgver = 0.1.0-1\narch = x86_64\n'
        with tarfile.open(package, 'w:zst') as archive:
            for name, data, mode in [('.PKGINFO', info, 0o644), ('usr/bin/enzimos-activityd', body, 0o755)]:
                member = tarfile.TarInfo(name)
                member.uid = member.gid = 0
                member.mode = mode
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
                if duplicate:
                    archive.addfile(member, io.BytesIO(data))
            if link:
                member = tarfile.TarInfo('usr/bin/evil')
                member.type = tarfile.SYMTYPE
                member.linkname = '/etc/passwd'
                archive.addfile(member)
        report = {'status': 'PASS-activity-service-package-built', 'package_name': 'enzimos-activity-service', 'release': 1,
                  'package': str(package), 'sha256': hashlib.sha256(package.read_bytes()).hexdigest(),
                  'files': {'usr/bin/enzimos-activityd': {'sha256': hashlib.sha256(body).hexdigest(), 'mode': 0o755}}}
        path = root / 'build.json'
        path.write_text(json.dumps(report))
        return path

    def test_valid_package_is_staged(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            media = root / 'media'
            media.mkdir()
            report = self.build(root)
            result = stage(report, media)
            self.assertEqual(result['package_name'], 'enzimos-activity-service')
            self.assertEqual((media / 'activity-service.pkg.tar.zst').read_bytes(), (root / 'activity.pkg.tar.zst').read_bytes())

    def test_refuses_tamper_identity_duplicate_and_links_before_mutation(self):
        for case in ('tamper', 'identity', 'duplicate', 'link'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                media = root / 'media'
                media.mkdir()
                report = self.build(root, wrong_name=case == 'identity', duplicate=case == 'duplicate', link=case == 'link')
                if case == 'tamper':
                    with (root / 'activity.pkg.tar.zst').open('ab') as stream:
                        stream.write(b'changed')
                with self.assertRaises(ValueError):
                    stage(report, media)
                self.assertEqual(list(media.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
