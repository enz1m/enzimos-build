# SPDX-License-Identifier: MIT
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract import Invalid
from prepare_target_lab import public_cache, iso_command, PACMAN_CONFIG, GPG_CONFIG
from target_vm import command, judge, PROVISION_PASS, ROOT_PASS, SEQUENCE, DISK_SIZE


class TargetLabTests(unittest.TestCase):
    def test_only_provisioner_can_use_direct_kernel(self):
        args = command(Path('/new'), 'provision', Path('/reviewed'))
        self.assertIn('-kernel', args)
        self.assertIn('if=none,id=payload,format=raw,readonly=on,file=/inputs/payload.iso', args)
        self.assertIn('virtio-blk-pci,drive=target,serial=enzimos-lab-target', args)
        for mode in ('uefi', 'bios'):
            args = command(Path('/new'), mode)
            for forbidden in ('-kernel', '-initrd', '-append', '-enable-kvm', '-netdev'):
                self.assertNotIn(forbidden, args)
            self.assertEqual(args[args.index('-nic') + 1], 'none')
            self.assertIn('--unshare-all', args)
            self.assertIn('--die-with-parent', args)
            self.assertIn(f'--fsize={DISK_SIZE}:{DISK_SIZE}', args)
            self.assertNotIn('/dev/sda', ' '.join(args))
        with self.assertRaises(Invalid):
            command(Path('/new'), 'custom')

    def test_exact_success_and_failure_markers(self):
        judge(PROVISION_PASS + '\nENZIMOS_TARGET_PACKAGES=146\nreboot: Power down', 0, -1)
        for phase, (mode, _) in enumerate(SEQUENCE):
            log = f'{ROOT_PASS}\nENZIMOS_ROOT_KERNEL=test-kernel\nENZIMOS_ROOT_MODE={mode}\nENZIMOS_ROOT_PHASE={phase}\nreboot: Power down'
            judge(log, 0, phase, 'test-kernel')
            for bad in (log.replace(ROOT_PASS, 'not-' + ROOT_PASS), log.replace('test-kernel', 'other'),
                        log.replace('Power down', 'Restarting'), log + '\nENZIMOS_ROOT_FAILURE',
                        log + '\nerror: command failed to execute correctly', log + '\nKernel panic - not syncing'):
                with self.assertRaises(Invalid):
                    judge(bad, 0, phase, 'test-kernel')
            with self.assertRaises(Invalid):
                judge(log, 1, phase, 'test-kernel')
        with self.assertRaises(Invalid):
            judge('', 0, 4)

    def test_public_cache_rejects_missing_quorum_before_gpg(self):
        with tempfile.TemporaryDirectory() as tmp, patch('prepare_target_lab.execute') as execute:
            record = {'signature': {'signature_valid': True, 'certifications': [{'masters': ['one', 'two']}]}}
            with self.assertRaises(Invalid):
                public_cache(Path(tmp) / 'cache', Path(tmp), Path(tmp), [record])
            execute.assert_not_called()
        self.assertIn('LocalFileSigLevel = Required TrustedOnly', PACMAN_CONFIG)
        self.assertNotIn('Never', PACMAN_CONFIG)
        self.assertNotIn('Server', PACMAN_CONFIG)
        self.assertIn('trust-model direct', GPG_CONFIG)
        self.assertIn('no-autostart', GPG_CONFIG)

    def test_iso_assembly_is_sandboxed_and_output_bounded(self):
        args = iso_command(Path('/source'), Path('/new'))
        self.assertIn('--unshare-all', args)
        self.assertIn('--fsize=1073741824:1073741824', args)



if __name__ == '__main__':
    unittest.main()
