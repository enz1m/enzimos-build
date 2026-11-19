# SPDX-License-Identifier: MIT
"""The installed-backup payload stages one checker with an explicit scenario."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import install_iso_vm as vm


class BackupPayloadTests(unittest.TestCase):
    def test_boot_bound_is_explicit_bounded_and_unattended_only(self):
        with patch.object(vm, 'constrain_job') as lock, patch.object(vm, 'new_output') as create:
            for bound in (True, '3000', 899, 4*3600+1):
                with self.subTest(bound=bound), self.assertRaises(vm.Invalid):
                    vm.run('boot', 'uefi', Path('/tmp/never-created'), boot_seconds=bound)
            with self.assertRaises(vm.Invalid):
                vm.run('install', 'uefi', Path('/tmp/never-created'), boot_seconds=3000)
            with self.assertRaises(vm.Invalid):
                vm.run('boot', 'uefi', Path('/tmp/never-created'), boot_seconds=3000, vnc=600)
            lock.assert_not_called();create.assert_not_called()


if __name__ == '__main__':
    unittest.main()
