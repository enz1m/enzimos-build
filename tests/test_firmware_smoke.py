# SPDX-License-Identifier: MIT
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract import Invalid
from firmware_smoke import MODES, QMP, new_output, qemu_argv, sandbox_argv, run


class FirmwareSmokeTests(unittest.TestCase):
    def test_modes_have_no_host_disk_network_or_kvm(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                argv = qemu_argv(mode)
                self.assertEqual(argv[argv.index('-nic') + 1], 'none')
                self.assertEqual(argv[argv.index('-accel') + 1], 'tcg,thread=single,tb-size=32')
                self.assertEqual(argv[argv.index('-smp') + 1], '1')
                self.assertEqual(argv[argv.index('-m') + 1], '256M')
                self.assertIn('-nodefaults', argv)
                self.assertIn('-no-user-config', argv)
                self.assertNotIn('-kernel', argv)
                drives = [argv[i + 1] for i, token in enumerate(argv) if token == '-drive']
                self.assertEqual(len(drives), 0 if mode == 'bios' else 2)
                if drives:
                    self.assertIn('readonly=on', drives[0])
                    self.assertTrue(drives[1].endswith('file=/work/vars.fd'))
                self.assertNotIn('/dev/kvm', ' '.join(argv))

    def test_secure_capable_is_not_an_enrollment_command(self):
        argv = qemu_argv('uefi-secure-capable')
        self.assertIn('OVMF_CODE.secboot.4m.fd', ' '.join(argv))
        self.assertNotIn('enroll', ' '.join(argv))
        with self.assertRaises(Invalid):
            qemu_argv('uefi-disable-security')

    def test_sandbox_exposes_only_usr_and_explicit_output(self):
        argv = sandbox_argv('bios', Path('/test/new-output'))
        self.assertIn('--unshare-all', argv)
        self.assertIn('--clearenv', argv)
        self.assertIn('--die-with-parent', argv)
        bindings = [argv[i + 1:i + 3] for i, token in enumerate(argv) if token in ('--bind', '--ro-bind')]
        self.assertEqual(bindings, [['/usr', '/usr'], ['/test/new-output', '/work']])
        self.assertNotIn('--dev-bind', argv)
        self.assertIn('--as=4294967296:4294967296', argv)
        self.assertIn('--cpu=20:20', argv)

    def test_output_is_new_and_not_traversing(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = new_output(root / 'new')
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(FileExistsError):
                new_output(target)
            (root / 'link').symlink_to(target, target_is_directory=True)
            for bad in (root / 'link' / 'out', root / '..' / 'out'):
                with self.assertRaises(Invalid):
                    new_output(bad)
        with self.assertRaises(Invalid):
            new_output(Path(__file__).resolve().parents[1] / 'must-not-create')

    def test_qmp_filters_async_events_and_matches_id(self):
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, 'rb') as stream, os.fdopen(write_fd, 'wb') as writer:
            writer.write(b'{"event":"RESET"}\n{"return":{"running":true},"id":1}\n')
            writer.flush()
            process = SimpleNamespace(stdout=stream, stdin=io.BytesIO())
            protocol = QMP(process, time.monotonic() + 2)
            self.assertEqual(protocol.command('query-status'), {'running': True})
            self.assertEqual(json.loads(process.stdin.getvalue())['execute'], 'query-status')
            with self.assertRaises(Invalid):
                protocol.command('blockdev-add')

    def test_failed_control_stops_child_and_preserves_failure_report(self):
        with tempfile.TemporaryDirectory() as temp, \
             patch('firmware_smoke.Path.is_file', return_value=True), \
             patch('firmware_smoke.os.geteuid', return_value=1000), \
             patch('firmware_smoke.digest', return_value='f' * 64), \
             patch('firmware_smoke.subprocess.Popen') as popen, \
             patch('firmware_smoke.QMP') as protocol:
            process = popen.return_value
            process.poll.return_value = None
            process.wait.return_value = -9
            protocol.return_value.receive.side_effect = Invalid('simulated control failure')
            output = Path(temp) / 'failed'
            with self.assertRaises(Invalid):
                run('bios', output)
            process.kill.assert_called_once()
            process.wait.assert_called_once_with(timeout=5)
            result = json.loads((output / 'result.json').read_text())
            self.assertEqual(result['status'], 'FAIL')
            self.assertFalse(result['release_qualified'])
            self.assertFalse(result['guest_os_booted'])

    def test_root_refused_before_any_process_or_output(self):
        with tempfile.TemporaryDirectory() as temp, \
             patch('firmware_smoke.os.geteuid', return_value=0), \
             patch('firmware_smoke.subprocess.Popen') as popen:
            output = Path(temp) / 'never'
            with self.assertRaises(Invalid):
                run('bios', output)
            popen.assert_not_called()
            self.assertFalse(output.exists())

    def test_qmp_invalid_eof_and_deadline(self):
        for message in (b'not-json\n', b'[]\n', b''):
            with self.subTest(message=message):
                read_fd, write_fd = os.pipe()
                with os.fdopen(read_fd, 'rb') as stream:
                    os.write(write_fd, message)
                    os.close(write_fd)
                    protocol = QMP(SimpleNamespace(stdout=stream), time.monotonic() + 2)
                    with self.assertRaises(Invalid):
                        protocol.receive()
        with patch('firmware_smoke.select.select') as select_mock:
            protocol = QMP(SimpleNamespace(stdout=None), time.monotonic() - 1)
            with self.assertRaises(Invalid):
                protocol.receive()
            select_mock.assert_not_called()

    def test_qmp_oversize_and_command_error(self):
        process = SimpleNamespace(stdout=SimpleNamespace(fileno=lambda: 7), stdin=io.BytesIO())
        protocol = QMP(process, time.monotonic() + 2)
        with patch('firmware_smoke.select.select', return_value=([7], [], [])), \
             patch('firmware_smoke.os.read', return_value=b'x' * (1024 * 1024 + 1)):
            with self.assertRaises(Invalid):
                protocol.receive()
        protocol = QMP(process, time.monotonic() + 2)
        protocol.buffer = b'{"id":1,"error":{"desc":"failed"}}\n'
        with self.assertRaises(Invalid):
            protocol.command('quit')


if __name__ == '__main__':
    unittest.main()
