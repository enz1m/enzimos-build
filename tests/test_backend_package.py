# SPDX-License-Identifier: MIT
"""Packaged backend boundaries/evidence without installing or launching services."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import build_system_backend as package
from contract import Invalid


class BackendPackageTests(unittest.TestCase):
    def test_package_is_separate_and_does_not_auto_enable(self):
        self.assertFalse(any(name.endswith('.py') for name in package.FILES))
        activation = (package.SOURCE/'org.enzimos.System1.service').read_text()
        self.assertIn('SystemdService=enzimos-system-backend.service', activation);self.assertIn('Exec=/bin/false', activation)
        service = (package.SOURCE/'enzimos-system-backend.service').read_text()
        self.assertIn('ExecStart=/usr/lib/enzimos-backend/enzimos-system-backend', service);self.assertNotIn('[Install]', service)
        self.assertNotIn('PrivateMounts=yes', service)
        self.assertEqual([line for line in (package.SOURCE/'native-policy.install').read_text().splitlines() if line and not line.startswith('#')], [])
        self.assertNotIn('system-services', (package.SOURCE/'PKGBUILD.in').read_text())

    def test_root_build_refuses_before_scheduling(self):
        with patch.object(package.os, 'geteuid', return_value=0), patch.object(package, 'constrain_job') as constrain:
            with self.assertRaisesRegex(Invalid, 'unprivileged'):package.build_backend('/unused')
            constrain.assert_not_called()

    def test_recipe_uses_audited_policy_artifact_and_matching_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = root/'policy.tar'
            runtime = root/'runtime'
            runtime.write_bytes(b'runtime fixture')
            info = (b'pkgname = enzimos-native-policy\npkgver = 0.1.0-155\n'
                    b'depend = enzimos-rust-packages=0.2.0-2\n')
            with tarfile.open(policy, 'w') as archive:
                member = tarfile.TarInfo('.PKGINFO')
                member.size = len(info)
                archive.addfile(member, io.BytesIO(info))
            policy_report = root/'policy.json'
            policy_report.write_text(json.dumps({
                'status': 'PASS-unsigned-policy-package-built',
                'payload_audit': {'status': 'PASS-exact-authored-package-payload'},
                'package_name': 'enzimos-native-policy', 'release': 155, 'package': str(policy),
                'sha256': hashlib.sha256(policy.read_bytes()).hexdigest(),
            }))
            runtime_summary = root/'runtime.json'
            candidate = {
                'package_name': 'enzimos-rust-packages', 'version': '0.2.0-2',
                'elf_count': 10, 'package': runtime.name,
                'sha256': hashlib.sha256(runtime.read_bytes()).hexdigest(),
            }
            summary = {'result': 'PASS', 'packages': {'packages': candidate}}
            runtime_summary.write_text(json.dumps(summary))
            _, policy_version, runtime_record = package.paired_inputs(policy_report, runtime_summary)
            recipe = package.backend_recipe((package.SOURCE/'PKGBUILD.in').read_text(),
                                            policy_version, runtime_record['version'])
            self.assertIn("'enzimos-native-policy=0.1.0-155'", recipe)
            self.assertIn("'enzimos-rust-packages=0.2.0-2'", recipe)
            candidate['version'] = '0.2.0-1'
            runtime_summary.write_text(json.dumps(summary))
            with self.assertRaisesRegex(Invalid, 'native policy requires a different Rust runtime'):
                package.paired_inputs(policy_report, runtime_summary)


if __name__ == '__main__':unittest.main()
