# SPDX-License-Identifier: MIT
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract import Invalid, MAX_JSON
from kernel_audit import audit, audit_file


class KernelAuditTests(unittest.TestCase):
    def test_config_capability_is_not_runtime_enforcement(self):
        result = audit('CONFIG_HIBERNATION=y\nCONFIG_SECURITY_LOCKDOWN_LSM=y\n'
                       'CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE=y\n# CONFIG_MODULE_SIG_FORCE is not set\n')
        self.assertEqual(result['flags']['CONFIG_MODULE_SIG_FORCE'], 'n')
        self.assertEqual(result['flags']['CONFIG_ENCRYPTED_HIBERNATION'], 'not-present')
        self.assertFalse(result['running_kernel_examined'])
        self.assertFalse(result['secure_boot_enforcement_verified'])
        self.assertFalse(result['authenticated_resume_verified'])
        self.assertIn('compile-time-lockdown-not-forced-runtime-must-be-observed', result['findings'])

    def test_ambiguous_or_executable_looking_input_is_rejected(self):
        for text in ('CONFIG_HIBERNATION=y\nCONFIG_HIBERNATION=n',
                     'CONFIG_HIBERNATION=y\n# CONFIG_HIBERNATION is not set',
                     'CONFIG_HIBERNATION=$(touch /tmp/never)', 'source /etc/passwd', '',
                     '# comment\n', '# ' + 'x' * MAX_JSON):
            with self.subTest(prefix=text[:40]):
                with self.assertRaises(Invalid):
                    audit(text)

    def test_real_mixed_case_symbols_do_not_alias_security_flags(self):
        result = audit('CONFIG_SCSI_DC395x=m\nCONFIG_FONT_8x16=y\n'
                       '# CONFIG_MT76x02_LIB is not set\nCONFIG_hibernation=y\n')
        self.assertEqual(result['flags']['CONFIG_HIBERNATION'], 'not-present')
        self.assertIn('hibernation-built-in-not-established', result['findings'])
        with self.assertRaises(Invalid):
            audit('CONFIG_MT76x02_LIB=m\n# CONFIG_MT76x02_LIB is not set\n')

    def test_unrelated_config_values_are_never_followed_or_echoed(self):
        result = audit('CONFIG_MODULE_SIG=y\nCONFIG_MODULE_SIG_KEY="/private/not-read.pem"\n')
        self.assertNotIn('/private/not-read.pem', str(result))

    def test_file_inputs_and_nonregular_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'config').write_text('CONFIG_HIBERNATION=y\n')
            self.assertEqual(audit_file(root / 'config')['flags']['CONFIG_HIBERNATION'], 'y')
            (root / 'link').symlink_to(root / 'config')
            os.mkfifo(root / 'fifo')
            for name in ('link', 'fifo'):
                with self.assertRaises(Invalid):
                    audit_file(root / name)


if __name__ == '__main__':
    unittest.main()
