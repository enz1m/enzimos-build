# SPDX-License-Identifier: MIT
import os
"""Online first-launch fixtures must not silently enable WAN on existing tests."""
from pathlib import Path
import unittest
from unittest.mock import patch
import install_iso_vm as vm

class GuestNetworkTests(unittest.TestCase):
    def test_default_offline_and_isolated_ethernet_keep_network_namespace(self):
        with patch.object(vm, 'accel', return_value=[]):
            for enabled in (False, True):
                argv = vm.qemu(Path('/tmp/fixture'), 'bios', network=enabled)
                self.assertIn('--unshare-all', argv)
                self.assertNotIn('--share-net', argv)
                self.assertEqual(argv[argv.index('-nic')+1], 'user,model=virtio-net-pci,restrict=on' if enabled else 'none')

        for guest_port in ('22', '22222'):
            with patch.dict(os.environ, {'ENZIMOS_VM_SSH_PORT': '23520', 'ENZIMOS_VM_SSH_GUEST_PORT': guest_port}), patch.object(vm, 'accel', return_value=[]):
                argv = vm.qemu(Path('/tmp/fixture'), 'bios', network=True)
                self.assertIn('--share-net', argv)
                self.assertEqual(argv[argv.index('-nic')+1], f'user,model=virtio-net-pci,restrict=on,hostfwd=tcp:127.0.0.1:23520-:{guest_port}')
        with patch.dict(os.environ, {'ENZIMOS_VM_SSH_PORT': '23520', 'ENZIMOS_VM_SSH_GUEST_PORT': '0'}):
            with self.assertRaises(vm.Invalid): vm.ssh_forward()

    def test_explicit_attended_outbound_nat_has_dns_and_no_port_forwards(self):
        with patch.object(vm, 'accel', return_value=[]):
            argv = vm.qemu(Path('/tmp/fixture'), 'bios', network=True, vnc=True, internet=True)
        self.assertIn('--share-net', argv)
        self.assertIn('/etc/resolv.conf', argv)
        self.assertEqual(argv[argv.index('-nic')+1], 'user,model=virtio-net-pci')
        self.assertFalse(any('hostfwd' in a for a in argv))
        self.assertEqual(argv[argv.index('-smp')+1], str(min(4, len(os.sched_getaffinity(0)))))

    def test_invalid_outbound_request_refuses_before_output_or_job_lock(self):
        with patch.object(vm, 'constrain_job') as lock, patch.object(vm, 'new_output') as create:
            for kwargs in ({'internet': 'yes'}, {'internet': True},
                           {'internet': True, 'network': True},
                           {'internet': True, 'vnc': 60}):
                with self.subTest(kwargs=kwargs), self.assertRaises(vm.Invalid):
                    vm.run('boot', 'uefi', Path('/tmp/never-created'), **kwargs)
            with self.assertRaises(vm.Invalid):
                vm.run('install', 'uefi', Path('/tmp/never-created'), internet=True, network=True, vnc=60)
            lock.assert_not_called();create.assert_not_called()
