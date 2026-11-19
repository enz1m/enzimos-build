# SPDX-License-Identifier: MIT
"""A continued private review cannot become an installer qualification."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import install_iso_vm as vm


class ReviewContinuationTests(unittest.TestCase):
    def test_review_copies_current_owned_bytes_without_qualifying_or_changing_its_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'source';source.mkdir(mode=0o700)
            image = source/'target.qcow2';image.write_bytes(b'private review disk')
            (source/'vars.fd').write_bytes(b'private firmware')
            report = source/'result.json'
            record = dict(status='REVIEW-ENDED', mode='uefi', qualification=False,
                          review_display=True, iso_sha256='1'*64)
            report.write_text(json.dumps(record))
            output = root/'review';output.mkdir(mode=0o700)
            vm.clone_boot_source(report, 'uefi', output, review_only=True)
            self.assertEqual((output/'target.qcow2').read_bytes(), image.read_bytes())
            (output/'target.qcow2').write_bytes(b'new review changes')
            self.assertEqual(image.read_bytes(), b'private review disk')
            self.assertEqual(json.loads(report.read_text()), record)
            for mode, review in [('bios', True), ('uefi', False)]:
                with self.assertRaises(vm.Invalid):
                    vm.clone_boot_source(report, mode, output, review_only=review)
            for fields in [dict(expect='PASS'), dict(payload=root/'payload'), dict(vnc=None)]:
                options = dict(vnc=60, previous=report, resume_review=True)
                options.update(fields)
                with self.assertRaisesRegex(vm.Invalid, 'continued review'):
                    vm.run('boot', 'uefi', root/'must-not-exist', **options)
                self.assertFalse((root/'must-not-exist').exists())
            record.update(status='PASS-install-iso-phase', disk_sha256=vm.digest(image))
            report.write_text(json.dumps(record))
            normal = root/'qualified-source';normal.mkdir()
            vm.clone_boot_source(report, 'uefi', normal)
            image.write_bytes(b'changed since qualification')
            with self.assertRaisesRegex(vm.Invalid, 'installed disk changed'):
                vm.clone_boot_source(report, 'uefi', normal)
            image.unlink();image.symlink_to(output/'target.qcow2')
            record.update(status='REVIEW-ENDED');report.write_text(json.dumps(record))
            with self.assertRaises(vm.Invalid):
                vm.clone_boot_source(report, 'uefi', output, review_only=True)
