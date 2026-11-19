# SPDX-License-Identifier: MIT
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract import Invalid
from target_vm import read_log as plain_read_log
from encrypted_inputs import PRIMARY, RECOVERY, checked_source
from encrypted_vm import ConsoleResponse, command, judge, read_log, PROVISION_PASS, ROOT_PASS, RECOVERY_PASS, SEQUENCE


class EncryptedLabTests(unittest.TestCase):
    def test_console_answers_once_and_only_fixture_prompts(self):
        response = ConsoleResponse()
        self.assertIsNone(response.next('unrelated password question'))
        self.assertEqual(response.next('Please enter passphrase for disk test:'), PRIMARY.encode() + b'\n')
        self.assertIsNone(response.next('Please enter passphrase for disk test:'))
        response = ConsoleResponse(recovery=True)
        self.assertIsNone(response.next('Please enter passphrase for disk test:'))
        self.assertEqual(response.next('ENZIMOS recovery passphrase:'), RECOVERY.encode() + b'\n')

    def test_read_only_source_and_real_disk_boot_arguments(self):
        args = command(Path('/new'), 'provision', Path('/inputs'), Path('/reviewed/source'))
        self.assertIn('if=none,id=source,format=qcow2,readonly=on,file=/inputs/source.qcow2', args)
        for mode in ('uefi', 'bios'):
            args = command(Path('/new'), mode, Path('/inputs'))
            for flag in ('-kernel', '-initrd', '-append', '-netdev', '-enable-kvm'):
                self.assertNotIn(flag, args)
            self.assertIn('--cpu=600:600', args)
            self.assertIn('--unshare-all', args)
        with self.assertRaises(Invalid):
            command(Path('/new'), 'bios', Path('/inputs'), Path('/source'))

    def test_judgement_requires_scope_markers_console_and_poweroff(self):
        judge(PROVISION_PASS + '\nENZIMOS_CRYPT_KEYS_PASS wrong-rejected recovery-accepted\nreboot: Power down', 0, -1)
        for phase, (mode, _) in enumerate(SEQUENCE):
            result = RECOVERY_PASS + '\nENZIMOS_RECOVERY_RAM_STARTED root-still-locked' if phase in (4, 5) else ROOT_PASS + '\nENZIMOS_CRYPT_KERNEL=expected'
            text = f'{result}\nENZIMOS_CRYPT_MODE={mode}\nENZIMOS_CRYPT_PHASE={phase}\nreboot: Power down'
            judge(text, 0, phase, 'expected', True)
            for bad in (text + '\nENZIMOS_CRYPT_FAILURE', text.replace('Power down', 'Restarting'), text.replace(result, 'missing')):
                with self.assertRaises(Invalid):
                    judge(bad, 0, phase, 'expected', True)
            with self.assertRaises(Invalid):
                judge(text, 0, phase, 'expected', False)
        with self.assertRaises(Invalid):
            judge('', 0, True)


    def test_log_reader_is_bounded_even_if_guest_exits_between_polls(self):
        with tempfile.TemporaryDirectory() as tmp, patch('encrypted_vm.MAX_LOG', 16), patch('target_vm.MAX_LOG', 16):
            path = Path(tmp) / 'serial.log'
            for reader in (read_log, plain_read_log):
                path.write_bytes(b'x' * 16)
                self.assertEqual(reader(path), 'x' * 16)
                path.write_bytes(b'x' * 17)
                with self.assertRaises(Invalid):
                    reader(path)

    def test_source_receipt_cannot_self_authorize_arbitrary_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'result.json'
            path.write_text('{"status":"PASS-disposable-target-phase","phase":-1,"disk_sha256":"invented"}')
            with self.assertRaises(Invalid):
                checked_source(path)


if __name__ == '__main__':
    unittest.main()
