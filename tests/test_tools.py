# SPDX-License-Identifier: MIT
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cli import stage_policy
from contract import BASELINE, Invalid, inventory_check, load, strict_baseline, validate_catalogue

WORKSPACE = Path(__file__).resolve().parents[2]
MANIFESTS = WORKSPACE / 'enzimos-manifests'
PACKAGES = WORKSPACE / 'enzimos-packages'


class ToolsTests(unittest.TestCase):
    def test_policy_drift(self):
        mutations = [
            lambda p: p.update(schema_version=True),
            lambda p: p.update(base='immutable'),
            lambda p: p.update(firmware=['uefi']),
            lambda p: p['boot'].update(bios_loader='grub'),
            lambda p: p['boot'].update(hibernation_status='required-now'),
            lambda p: p['storage'].update(home_history_default=False),
            lambda p: p['updates'].update(native_default='offline'),
            lambda p: p['defaults'].update(time='plain-ntp'),
            lambda p: p['defaults'].update(phone_remote=True),
            lambda p: p['installer'].update(backend='distinst'),
            lambda p: p.update(force=True),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                value = copy.deepcopy(BASELINE)
                mutate(value)
                with self.assertRaises(Invalid):
                    strict_baseline(value)

    def test_catalogue_app_removal_and_invented_ids(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for path in MANIFESTS.glob('*.json'):
                (root / path.name).write_bytes(path.read_bytes())
            _, apps, artifacts = validate_catalogue(root)
            self.assertEqual(apps['browser']['flatpak_id'], 'org.enzim.Browser')
            self.assertEqual(apps['browser']['delivery'], 'project-flatpak')
            self.assertIn('app-browser', artifacts['required_roles'])

            cases = (
                ('apps', lambda value: value['apps'][0].update(flatpak_id='invented.project.Id')),
                ('apps', lambda value: value['apps'].pop()),
                ('apps', lambda value: value['browser'].update(delivery='flathub-flatpak')),
                ('artifacts', lambda value: value['required_roles'].remove('app-browser')),
            )
            for case, (document, mutate) in enumerate(cases):
                with self.subTest(document=document, case=case):
                    path = root / f'{document}.json'
                    original = path.read_text()
                    invalid = json.loads(original)
                    mutate(invalid)
                    path.write_text(json.dumps(invalid))
                    with self.assertRaises(Invalid):
                        validate_catalogue(root)
                    path.write_text(original)

    def test_json_rejects_duplicate_nonfinite_and_oversize(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'bad.json'
            for body in ('{"a":1,"a":2}', 'NaN', 'Infinity', '[' * 2000, ' ' * (2 * 1024 * 1024 + 1)):
                path.write_text(body)
                with self.assertRaises(Invalid):
                    load(path)

    def test_json_refuses_symlinks_and_fifos_without_reading_them(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'file').write_text('{}')
            (root / 'link').symlink_to(root / 'file')
            os.mkfifo(root / 'fifo')
            for name in ('link', 'fifo'):
                with self.assertRaises(Invalid):
                    load(root / name)

    def test_staging_checksums_no_host_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'new'
            result = stage_policy(MANIFESTS, PACKAGES, output)
            self.assertFalse(result['executes_build'])
            self.assertFalse(result['release_authorized'])
            recipe = (output / 'PKGBUILD').read_text()
            for name in ('product.json', 'LICENSE'):
                self.assertIn(hashlib.sha256((output / name).read_bytes()).hexdigest(), recipe)
            self.assertNotIn('@POLICY_SHA256@', recipe)
            self.assertNotIn('/etc/', recipe)
            self.assertNotIn('systemctl', recipe)
            with self.assertRaises(FileExistsError):
                stage_policy(MANIFESTS, PACKAGES, output)

    def test_staging_refuses_symlink_and_source_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'link').symlink_to(root, target_is_directory=True)
            with self.assertRaises(Invalid):
                stage_policy(MANIFESTS, PACKAGES, root / 'link' / 'new')
            with self.assertRaises(Invalid):
                stage_policy(MANIFESTS, PACKAGES, MANIFESTS / 'must-not-create')
            with self.assertRaises(Invalid):
                stage_policy(MANIFESTS, PACKAGES, root / '..' / 'must-not-create')

    def test_inventory_adversarial_cases(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'payload').write_bytes(b'fixture')
            (root / 'link').symlink_to(root / 'payload')
            entry = {'role': 'a', 'path': 'payload', 'size': 7,
                     'sha256': hashlib.sha256(b'fixture').hexdigest()}
            inventory = {'schema_version': 1, 'artifacts': [entry]}
            result = inventory_check(root, inventory, {'a'})
            self.assertTrue(result['roles_complete'])
            self.assertFalse(result['release_authorized'])
            self.assertFalse(inventory_check(root, inventory, {'a', 'b'})['roles_complete'])
            for key, value in [('path', '../payload'), ('path', '/etc/passwd'), ('path', 'a/../payload'),
                               ('path', 'link'), ('path', 'a//payload'), ('path', '.'),
                               ('size', True), ('size', 8), ('sha256', '0' * 64), ('role', 'unknown')]:
                with self.subTest(key=key, value=value):
                    bad = copy.deepcopy(inventory)
                    bad['artifacts'][0][key] = value
                    with self.assertRaises(Invalid):
                        inventory_check(root, bad, {'a'})
            inventory['artifacts'].append(copy.deepcopy(entry))
            with self.assertRaises(Invalid):
                inventory_check(root, inventory, {'a'})


if __name__ == '__main__':
    unittest.main()
