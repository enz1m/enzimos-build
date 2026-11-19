# SPDX-License-Identifier: MIT
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract import Invalid
from update_catalogue import changes
from update_vm import command, judge, CUT, FILE_CAP, RECOVER


class UpdateLabTests(unittest.TestCase):
    def test_full_catalogue_delta_uses_bytes_not_only_version(self):
        old = {'packages': [{'name': 'a', 'version': '1', 'sha256_from_metadata': 'old'}, {'name': 'b', 'version': '2', 'sha256_from_metadata': 'same'}]}
        new = {'packages': [{'name': 'a', 'version': '1', 'sha256_from_metadata': 'changed'}, {'name': 'c', 'version': '2', 'sha256_from_metadata': 'new'}]}
        delta = changes(old, new)
        self.assertEqual(delta['added'], ['c']); self.assertEqual(delta['removed'], ['b'])
        self.assertEqual(delta['changed'], [{'name': 'a', 'old': '1', 'new': '1'}])

    def test_guest_only_commands_and_bounded_write_budget(self):
        for action in ('update', 'boot-0', 'boot-1', 'boot-2', 'boot-3', 'recovery', 'rollback'):
            args, _ = command(Path('/new'), Path('/inputs'), action, 'success')
            for forbidden in ('-kernel', '-initrd', '-append', '-enable-kvm', '-netdev'):
                self.assertNotIn(forbidden, args)
            self.assertIn(f'--fsize={FILE_CAP}:{FILE_CAP}', args)
            self.assertIn('--unshare-all', args)
            self.assertEqual(args[args.index('-nic') + 1], 'none')
        args, _ = command(Path('/new'), Path('/inputs'), 'update', 'interrupt')
        self.assertIn('-qmp', args)
        args, _ = command(Path('/new'), Path('/inputs'), 'setup', 'success')
        self.assertIn('-kernel', args)
        self.assertIn('enzimos.scenario=success', args[-1])
        with self.assertRaises(Invalid): command(Path('/new'), Path('/inputs'), 'arbitrary', 'success')

    def test_interruption_is_not_graceful_shutdown_or_completed_transaction(self):
        kernels = {'old': {'linux-lts': 'old'}, 'new': {'linux': 'new'}}
        judge(CUT, 0, 'update', 'interrupt', kernels, True, True)
        for text, cut in [(CUT, False), (CUT + '\nreboot: Power down', True), (CUT + '\n[ALPM] transaction completed', True), ('not-' + CUT, True)]:
            with self.assertRaises(Invalid): judge(text, 0, 'update', 'interrupt', kernels, True, cut)
        with self.assertRaises(Invalid): judge(CUT, 1, 'update', 'interrupt', kernels, True, True)
        text = RECOVER + '\nENZIMOS_UPDATE_RECOVERY_RAM_STARTED root-locked\nreboot: Power down'
        judge(text, 0, 'recovery', 'interrupt', kernels, True)
        with self.assertRaises(Invalid): judge(text + '\nENZIMOS_UPDATE_FAILURE', 0, 'recovery', 'interrupt', kernels, True)


if __name__ == '__main__':
    unittest.main()
