# SPDX-License-Identifier: MIT
"""Clean-builder planning does not transfer runtime payload authentication."""
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from contract import Invalid, digest
import clean_build_plan as builder
from clean_build_plan import missing_payload


class CleanBuildPlanTests(unittest.TestCase):
    def row(self, name='gcc', version='1', checksum='a'*64):
        return {'name': name, 'version': version, 'architecture': 'x86_64', 'sha256_from_metadata': checksum}

    def test_exact_existing_bytes_are_not_missing(self):
        row = self.row()
        self.assertEqual(missing_payload({'packages': [row]}, {'packages': [row]}), [])

    def test_same_name_different_cohort_or_bytes_are_missing(self):
        row = self.row()
        for old in ([], [self.row(version='2')], [self.row(checksum='b'*64)]):
            self.assertEqual(missing_payload({'packages': [row]}, {'packages': old}), [row])

    def test_ambiguous_malformed_or_excess_manifest_refuses(self):
        for document in ({}, {'packages': None}, {'packages': [self.row()]*513}, {'packages': [self.row(), self.row()]},
                         {'packages': [None]}, {'packages': [self.row(checksum=True)]}, {'packages': [self.row(name='../gcc')]}):
            with self.assertRaises(Invalid):missing_payload({'packages': [self.row()]}, document)

    def test_runtime_inputs_and_copied_databases_rechecked_after_resolution(self):
        for changed in ('seed', 'available', 'database', None):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary);root = base/'root';(root/'usr/bin').mkdir(parents=True);(root/'usr/bin/pacman').touch()
                seed_path = base/'seed.json';seed_path.write_text('{}')
                available = base/'available.json';available.write_text(json.dumps({'packages': [self.row()]}))
                databases = base/'databases';databases.mkdir();db = databases/'core.db';db.write_bytes(b'original-db')
                seed = {'requested_packages': ['python'], 'databases': [{'file': 'core.db', 'repository': 'core', 'bytes': db.stat().st_size,
                        'sha256': digest(db), 'server': 'https://example.invalid'}]}
                output = base/'plan'
                def run(*args, **kwargs):
                    target = {'seed': seed_path, 'available': available, 'database': output/'db/sync/core.db'}.get(changed)
                    if target:target.write_bytes(target.read_bytes()+b' ')
                    return SimpleNamespace(returncode=0, stdout=b'fixed', stderr=b'')
                with patch.object(builder.os, 'geteuid', return_value=1000), patch.object(builder, 'constrain_job', return_value={}), \
                     patch.object(builder.shutil, 'disk_usage', return_value=SimpleNamespace(free=2**40)), \
                     patch.object(builder, 'read_seed', return_value=seed), patch.object(builder.subprocess, 'run', side_effect=run), \
                     patch.object(builder, 'parse_resolution', return_value={'packages': [self.row()]}):
                    if changed:
                        with self.assertRaisesRegex(Invalid, 'changed'):builder.plan(root, seed_path, databases, available, output)
                        self.assertFalse((output/'plan.json').exists())
                    else:
                        result = builder.plan(root, seed_path, databases, available, output)
                        self.assertFalse(result['toolchain_freshly_verified']);self.assertFalse(result['build_executed'])
                        self.assertEqual(result['databases'], seed['databases'])


if __name__ == '__main__':unittest.main()
