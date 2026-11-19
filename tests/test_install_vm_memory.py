# SPDX-License-Identifier: MIT
import os
"""Bounded dual-session qualification must preserve default and host headroom."""
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import install_iso_vm as vm

class GuestMemoryTests(unittest.TestCase):
    def test_bounded_vm_keeps_one_keyboard_controller_with_or_without_a_display(self):
        with patch.object(vm, 'sandbox', side_effect=lambda _: ['sandbox']), patch.object(vm, 'accel', return_value=[]):
            for memory, desktop, backup in [(2048, False, False), (4096, True, True)]:
                argv = vm.qemu(Path('/tmp/fixture'), 'bios', guest_ram_mib=memory, desktop=desktop, backup_usb=backup)
                self.assertEqual(argv[argv.index('-m')+1], f'{memory}M')
                self.assertEqual(argv[argv.index('-smp')+1], str(min(4, len(os.sched_getaffinity(0)))))
                self.assertIn('--as=6442450944:6442450944', argv)
                self.assertEqual(argv[argv.index('-nic')+1], 'none')
                self.assertEqual(argv.count('qemu-xhci'), 1)
                self.assertEqual(argv.count('usb-kbd'), 1)
                self.assertEqual(argv[argv.index('-display')+1], 'vnc=unix:/work/vnc.sock')

    def test_invalid_memory_fails_before_output_creation_or_job_lock(self):
        with patch.object(vm, 'constrain_job') as lock, patch.object(vm, 'new_output') as create:
            for memory in (True, '4096', 0, 2049, 8192):
                with self.subTest(memory=memory), self.assertRaises(vm.Invalid):
                    vm.run('boot', 'uefi', Path('/tmp/never-created'), guest_ram_mib=memory)
            lock.assert_not_called();create.assert_not_called()

    def test_larger_guest_refuses_host_pressure_before_any_mutation(self):
        with patch.object(Path, 'read_text', return_value='MemAvailable: 8388607 kB\n'), patch.object(vm, 'constrain_job') as lock, patch.object(vm, 'new_output') as create:
            with self.assertRaisesRegex(vm.Invalid, 'host available memory'):
                vm.run('boot', 'uefi', Path('/tmp/never-created'), guest_ram_mib=4096)
            lock.assert_not_called();create.assert_not_called()
