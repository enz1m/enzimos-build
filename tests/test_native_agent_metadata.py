# SPDX-License-Identifier: MIT
import configparser
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from native_agent_metadata import plan, stage


class NativeAgentMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        self.binaries = self.root / 'bins'
        self.binaries.mkdir()
        self.destination = self.root / 'stage'
        (self.destination / 'usr/lib/enzui/apps').mkdir(parents=True)
        self.app = 'files-app'
        self.app_id = 'io.github.enzui.Files'
        self.unit = 'enzui-agent-' + self.app_id + '.service'
        self.metadata = self.source / self.app / 'packaging/agent'
        self.metadata.mkdir(parents=True)
        catalog = {'schema': 1, 'registration': {'app': {'id': self.app_id}, 'functions': []},
                   'activation_unit': self.unit}
        self.write(self.app_id + '.json', json.dumps(catalog))
        self.write(self.app_id + '.background.json', json.dumps({'schema': 1,
                   'app_id': self.app_id, 'unit': self.unit, 'executable': '/usr/bin/files-app'}))
        self.write(self.unit, '[Unit]\nDescription=Files\n[Service]\n'
                   'ExecStart=/usr/bin/files-app --agent-background\nRestart=no\n')
        self.write('dbus/' + self.app_id + '.service', '[D-BUS Service]\n'
                   'Name=' + self.app_id + '\nExec=/usr/bin/files-app --agent-background\n'
                   'SystemdService=' + self.unit + '\n')
        self.git('init', '-q')
        self.git('config', 'user.name', 'fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.commit()
        binary = b'\x7fELFqualified-fixture-binary'
        (self.binaries / self.app).write_bytes(binary)
        (self.binaries / self.app).chmod(0o755)
        (self.destination / 'usr/lib/enzui/apps' / self.app).write_bytes(binary)
        (self.destination / 'usr/lib/enzui/apps' / self.app).chmod(0o755)
        self.receipt = {'schema': 1, 'source': {'revision': self.revision, 'dirty': False},
                        'framework': {'dirty': False}, 'features': ['center'],
                        'files': {self.app: hashlib.sha256(binary).hexdigest()}}
        self.save_receipt()

    def write(self, name, value):
        path = self.metadata / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.source), *args], stderr=subprocess.DEVNULL)

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        self.revision = self.git('rev-parse', 'HEAD').decode().strip()

    def save_receipt(self):
        (self.binaries / (self.app + '.receipt.json')).write_text(json.dumps(self.receipt))

    def install(self):
        return stage(self.source, self.binaries, self.destination, self.app)

    def test_exact_source_and_binary_stage_discovery_without_autostart(self):
        result = self.install()
        self.assertFalse(result['service_enabled'])
        self.assertEqual(len(result['files']), 4)
        self.assertEqual(result['revision'], self.revision)
        self.assertEqual((self.destination / 'usr/bin/files-app').readlink(),
                         Path('/usr/lib/enzui/apps/files-app'))
        self.assertFalse((self.destination / 'usr/lib/systemd/user/default.target.wants').exists())
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.install()

    def test_worktree_replacement_is_never_used_as_package_metadata(self):
        self.write(self.unit, '[Unit]\nDescription=Hostile\n[Service]\nExecStart=/bin/sh -c evil\n')
        self.install()
        data = (self.destination / 'usr/lib/systemd/user' / self.unit).read_text()
        self.assertIn('ExecStart=/usr/bin/files-app --agent-background', data)
        self.assertNotIn('evil', data)

    def test_wrong_source_revision_or_unqualified_build_is_refused_before_writes(self):
        for change in ({'features': []}, {'source': {'revision': self.revision, 'dirty': True}},
                       {'source': {'revision': 'a' * 40, 'dirty': False}}):
            prior = self.receipt.copy()
            self.receipt.update(change)
            self.save_receipt()
            with self.assertRaises(ValueError):
                self.install()
            self.assertFalse((self.destination / 'usr/share').exists())
            self.receipt = prior

    def test_receipt_or_installed_binary_tampering_is_refused(self):
        retained = self.binaries / self.app
        retained.write_bytes(b'\x7fELFother')
        with self.assertRaisesRegex(ValueError, 'differs from receipt'):
            self.install()
        retained.write_bytes(b'\x7fELFqualified-fixture-binary')
        (self.destination / 'usr/lib/enzui/apps' / self.app).write_bytes(b'other')
        with self.assertRaisesRegex(ValueError, 'staged native app binary'):
            self.install()

    def test_committed_dbus_command_or_service_mismatch_is_refused(self):
        for text in ('Exec=/bin/sh -c evil', 'SystemdService=unrelated.service'):
            self.write('dbus/' + self.app_id + '.service', '[D-BUS Service]\n'
                       'Name=' + self.app_id + '\nExec=/usr/bin/files-app --agent-background\n'
                       'SystemdService=' + self.unit + '\n' + text + '\n')
            self.commit()
            self.receipt['source']['revision'] = self.revision
            self.save_receipt()
            with self.assertRaises((ValueError, configparser.Error)):
                self.install()
            self.assertFalse((self.destination / 'usr/share').exists())

    def test_staging_parent_symlink_cannot_redirect_metadata(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.destination / 'usr/share').symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'parent is a symlink'):
            self.install()
        self.assertEqual(list(outside.iterdir()), [])

    def test_duplicate_catalog_identity_key_is_refused(self):
        self.write(self.app_id + '.json', '{"schema":1,"schema":1}')
        self.commit()
        self.receipt['source']['revision'] = self.revision
        self.save_receipt()
        with self.assertRaisesRegex(ValueError, 'duplicate metadata key'):
            plan(self.source, self.binaries, self.destination, self.app)

    def test_script_with_matching_receipt_is_not_a_native_process_identity(self):
        data = b'#!/bin/sh\nsleep 100\n'
        (self.binaries / self.app).write_bytes(data)
        self.receipt['files'][self.app] = hashlib.sha256(data).hexdigest()
        self.save_receipt()
        with self.assertRaisesRegex(ValueError, 'native ELF required'):
            self.install()
        self.assertFalse((self.destination / 'usr/share').exists())

    def test_repeated_systemd_environment_is_preserved_but_repeated_exec_is_refused(self):
        unit_data = (self.metadata / self.unit).read_text()
        self.write(self.unit, unit_data + 'Environment=ENZUI_APP_CREDENTIAL=%S/private\n'
                   'Environment=ENZUI_CENTER_SOCKET=%t/center.sock\n')
        self.commit()
        self.receipt['source']['revision'] = self.revision
        self.save_receipt()
        value = plan(self.source, self.binaries, self.destination, self.app)
        emitted = value['files']['usr/lib/systemd/user/' + self.unit]
        self.assertIn(b'Environment=ENZUI_APP_CREDENTIAL=%S/private', emitted)
        self.assertIn(b'Environment=ENZUI_CENTER_SOCKET=%t/center.sock', emitted)
        self.write(self.unit, unit_data + 'ExecStart=/usr/bin/files-app --agent-background\n')
        self.commit()
        self.receipt['source']['revision'] = self.revision
        self.save_receipt()
        with self.assertRaisesRegex(ValueError, 'duplicate metadata directive'):
            self.install()
