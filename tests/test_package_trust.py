# SPDX-License-Identifier: MIT
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract import Invalid
from package_trust import MASTERS, quorum, valid_identities, accept_status, revoked_keys, gpg_base
from acquire_packages import validate_plan

FP = 'A' * 40
UID = 'Example <example@archlinux.org>'


def listing(fp=FP, uid=UID, validity='f'):
    return f'pub:f:255:22:KEY:1:99999:::::sc:\nfpr:::::::::{fp}:\nuid:{validity}::::::::{uid}:\n'


class PackageTrustTests(unittest.TestCase):
    def test_three_distinct_contexts_not_one_full_trust_result(self):
        for number in (0, 1, 2, 3, 5):
            values = {master: listing() if i < number else '' for i, master in enumerate(MASTERS)}
            self.assertEqual(FP in quorum(values, set()), number >= 3)
        with self.assertRaises(Invalid):
            quorum({MASTERS[0]: listing()}, set())

    def test_same_uid_domain_revocation_and_master_exclusion(self):
        values = {master: listing(uid=f'User{i} <u{i}@archlinux.org>') for i, master in enumerate(MASTERS)}
        self.assertNotIn(FP, quorum(values, set()))
        self.assertFalse(valid_identities(listing(uid='Example <example@elsewhere.org>')))
        self.assertFalse(valid_identities(listing(validity='m')))
        values = {master: listing() for master in MASTERS}
        self.assertNotIn(FP, quorum(values, {FP}))
        with self.assertRaises(Invalid):
            quorum(values, {MASTERS[0]})
        self.assertFalse(quorum({m: listing(fp=MASTERS[0]) for m in MASTERS}, set()))

    def test_signature_needs_quorum_and_valid_crypto_not_trust_fully_alone(self):
        status = f'[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG KEY name\n[GNUPG:] VALIDSIG {FP} 1970-01-01 100 0 4 0 22 10 00 {FP}\n[GNUPG:] TRUST_FULLY 0 classic\n'
        keys = {FP: {'primary': FP, 'validity': 'f', 'created': 1, 'expires': 9999, 'capabilities': 's'}}
        eligible = quorum({m: listing() for m in MASTERS}, set())
        self.assertTrue(accept_status(status, 0, keys, eligible, set(), 1000)['signature_valid'])
        for code, allowed, revoked in ((1, eligible, set()), (0, {}, set()), (0, eligible, {FP})):
            with self.assertRaises(Invalid):
                accept_status(status, code, keys, allowed, revoked, 1000)
        with self.assertRaises(Invalid):
            accept_status(status + '[GNUPG:] BADSIG rejected\n', 0, keys, eligible, set(), 1000)

    def test_contexts_mount_only_public_inputs_and_selected_package(self):
        args = gpg_base(Path('/scratch'), Path('/keys'), Path('/pkgs'), 'master-0', 'test.pkg.tar.zst')
        mounts = [args[i + 1] for i, item in enumerate(args) if item == '--ro-bind']
        self.assertEqual(mounts, ['/usr', '/keys/archlinux.gpg', '/pkgs/test.pkg.tar.zst', '/pkgs/test.pkg.tar.zst.sig'])
        self.assertIn('--no-auto-key-retrieve', args)
        self.assertIn('--no-autostart', args)
        self.assertEqual(args[args.index('--trust-model') + 1], 'classic')
        self.assertEqual(args[args.index('--max-cert-depth') + 1], '1')

    def test_revocation_format_is_strict(self):
        self.assertEqual(revoked_keys(FP + '\n'), {FP})
        for text in ('', 'AAAA\n', '# ignore\n'):
            with self.assertRaises(Invalid):
                revoked_keys(text)

    def test_download_plan_rejects_escape_redirect_origins_and_large_batches(self):
        plan = {'repository_snapshot': '2026-09-14', 'packages': [{'name': 'base', 'repository': 'core',
                'url': 'https://archive.archlinux.org/repos/2026/09/14/core/os/x86_64/base-1-1-any.pkg.tar.zst',
                'download_bytes_from_metadata': 123, 'sha256_from_metadata': 'a' * 64}]}
        self.assertEqual(len(validate_plan(plan)), 1)
        for change in ({'url': 'file:///etc/passwd'}, {'url': plan['packages'][0]['url'] + '?x=1'},
                       {'download_bytes_from_metadata': True}, {'download_bytes_from_metadata': 1024**3}):
            bad = copy.deepcopy(plan); bad['packages'][0].update(change)
            with self.assertRaises(Invalid):
                validate_plan(bad)
        bad = copy.deepcopy(plan); bad['packages'] *= 2
        with self.assertRaises(Invalid):
            validate_plan(bad)

    def test_download_plan_requires_explicit_snapshot_for_package_override(self):
        url = 'https://archive.archlinux.org/repos/2026/11/11/extra/os/x86_64/xorg-xwayland-24.1.15-1-x86_64.pkg.tar.zst'
        package = {'name': 'xorg-xwayland', 'repository': 'extra', 'url': url,
                   'download_bytes_from_metadata': 123, 'sha256_from_metadata': 'a' * 64}
        plan = {'repository_snapshot': '2026-09-27', 'packages': [package]}
        with self.assertRaises(Invalid):
            validate_plan(plan)
        package['repository_snapshot'] = '2026-11-11'
        self.assertEqual(validate_plan(plan), [package])
        package['repository_snapshot'] = '../2026/11/11'
        with self.assertRaises(Invalid):
            validate_plan(plan)


if __name__ == '__main__':
    unittest.main()
