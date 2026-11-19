# SPDX-License-Identifier: MIT
"""Scratch checkpoint admission; no qemu execution in the default tests."""
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from unittest.mock import patch

from contract import Invalid
import foundation_checkpoint as checkpoint
import foundation_overlay_vm as overlay


class CheckpointTests(unittest.TestCase):
    def test_runtime_floor_refuses_before_starting_child(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(checkpoint.shutil, 'disk_usage', return_value=SimpleNamespace(free=checkpoint.FREE_FLOOR)), \
             patch.object(checkpoint.subprocess, 'Popen') as child:
            with self.assertRaisesRegex(Invalid, 'runtime free-space'):checkpoint.run_command([], Path(temporary), 'convert', 1)
            child.assert_not_called()

    def test_runtime_floor_or_log_failure_stops_only_own_child(self):
        for message in ('runtime free-space floor', 'runtime log bound'):
            child = Mock();child.poll.return_value = None
            with tempfile.TemporaryDirectory() as temporary, \
                 patch.object(checkpoint, 'command_guard', side_effect=[None, Invalid(message)]), \
                 patch.object(checkpoint.subprocess, 'Popen', return_value=child):
                with self.assertRaisesRegex(Invalid, message):checkpoint.run_command([], Path(temporary), 'convert', 1)
                child.terminate.assert_called_once_with();child.wait.assert_called_once_with(timeout=3)

    def test_runtime_deadline_stops_child_and_preserves_logs(self):
        child = Mock();child.poll.return_value = None
        with tempfile.TemporaryDirectory() as temporary, patch.object(checkpoint, 'command_guard'), \
             patch.object(checkpoint.time, 'monotonic', side_effect=[0, 2]), \
             patch.object(checkpoint.subprocess, 'Popen', return_value=child):
            with self.assertRaisesRegex(Invalid, 'deadline'):checkpoint.run_command([], Path(temporary), 'convert', 1)
            child.terminate.assert_called_once_with()
            self.assertTrue((Path(temporary)/'convert.stdout').exists())

    def test_runtime_log_cap_and_successful_command(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(checkpoint.shutil, 'disk_usage', return_value=SimpleNamespace(free=2**40)):
            output = Path(temporary);(output/'convert.stderr').write_bytes(b'x'*checkpoint.LOG_CAP)
            with self.assertRaisesRegex(Invalid, 'log bound'):checkpoint.command_guard(output)
        child = Mock();child.poll.return_value = 0;child.returncode = 0
        with tempfile.TemporaryDirectory() as temporary, patch.object(checkpoint, 'command_guard'), \
             patch.object(checkpoint.subprocess, 'Popen', return_value=child):
            self.assertEqual(checkpoint.run_command([], Path(temporary), 'compare', 1), b'')
            child.terminate.assert_not_called()

    def test_failed_source_cannot_be_checkpointed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'result.json';path.write_text(json.dumps({'status': 'FAIL'}))
            with self.assertRaisesRegex(Invalid, 'successful overlay'):checkpoint.sources(path)

    def test_standalone_checkpoint_starts_new_bounded_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'result.json';image = path.parent/'target.qcow2';image.write_bytes(b'fixture')
            record = {'status': 'PASS-foundation-checkpoint', 'case': 'checkpoint', 'disk_sha256': checkpoint.digest(image),
                      'disk_bytes': image.stat().st_size, 'guest_visible_bytes_equal': True, 'source_files_unchanged': True, 'standalone': True}
            path.write_text(json.dumps(record))
            _, _, rows = overlay.lineage(path)
            self.assertEqual(len(rows), 1);self.assertEqual(rows[0]['path'], str(image))
            for key in ('guest_visible_bytes_equal', 'source_files_unchanged', 'standalone'):
                path.write_text(json.dumps(dict(record, **{key: False})))
                with self.assertRaisesRegex(Invalid, 'verified standalone'):overlay.lineage(path)

    def test_ordinary_chain_depth_stays_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'result.json'
            path.write_text(json.dumps({'status': 'PASS-foundation-overlay-phase', 'parents': [{}]*12}))
            with self.assertRaisesRegex(Invalid, 'ancestry depth'):overlay.lineage(path)

    def test_checkpoint_requires_exact_recorded_source_sizes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'result.json';image = path.parent/'target.qcow2';image.write_bytes(b'fixture')
            row = {'path': str(image), 'sha256': checkpoint.digest(image), 'bytes': 8}
            path.write_text(json.dumps({'status': 'PASS-foundation-overlay-phase', 'parents': [row],
                                        'disk_sha256': row['sha256'], 'disk_bytes': 7}))
            with self.assertRaisesRegex(Invalid, 'byte count'):checkpoint.sources(path)


if __name__ == '__main__':unittest.main()
