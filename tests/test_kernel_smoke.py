# SPDX-License-Identifier: MIT
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract import Invalid
from kernel_smoke import PASS, CMDLINE, judge, command, run


class KernelSmokeTests(unittest.TestCase):
    def test_real_checks_and_shutdown_required(self):
        log = 'ENZIMOS_INITRD_KERNEL=fixture\n' + PASS + '\nreboot: Power down\n'
        result = judge(log, 0, 'fixture')
        self.assertTrue(result['kernel_initrd_smoke_passed'])
        self.assertFalse(result['installed_os_qualified'])
        self.assertFalse(result['bootloader_qualified'])
        self.assertFalse(result['secure_boot_enforcement_verified'])
        for value, code, version in ((log, 1, 'fixture'), (log, 0, 'wrong'), (PASS, 0, 'fixture'),
                                      (log.replace('reboot: Power down', ''), 0, 'fixture'),
                                      (log + 'Kernel panic - not syncing', 0, 'fixture'),
                                      (log + 'ENZIMOS_INITRD_FAILURE', 0, 'fixture'),
                                      (log.replace('KERNEL=fixture', 'KERNEL=fixture-extra'), 0, 'fixture')):
            with self.assertRaises(Invalid):
                judge(value, code, version)

    def test_direct_kernel_profile_is_diskless_and_not_a_security_bypass_option(self):
        args = command(Path('/a/kernel'), Path('/a/initrd'))
        self.assertNotIn('-drive', args)
        self.assertNotIn('-enable-kvm', args)
        self.assertEqual(args[args.index('-nic') + 1], 'none')
        self.assertEqual(args[args.index('-m') + 1], '768M')
        self.assertEqual(args[args.index('-append') + 1], CMDLINE)
        self.assertNotIn('lockdown=', CMDLINE)
        self.assertIn('--unshare-all', args)
        mounts = [args[i + 1] for i, value in enumerate(args) if value == '--ro-bind']
        self.assertEqual(mounts, ['/usr', '/a/kernel', '/a/initrd'])

    def test_root_execution_refused(self):
        with patch('kernel_smoke.os.geteuid', return_value=0):
            with self.assertRaises(Invalid):
                run('not-read', 'linux', 'not-created')


if __name__ == '__main__':
    unittest.main()
