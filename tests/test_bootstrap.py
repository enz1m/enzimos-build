# SPDX-License-Identifier: MIT
from datetime import datetime, timezone
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract import Invalid
from signed_bootstrap import FILES, read_lock, parse_key_listing, verify_status, check_input_files, sandbox, verify
from bootstrap_archive import ROOT, validate_members, describe, MAX_UNPACKED
from prepare_bootstrap import extractor_argv, toolroot_argv, strip_privileged_modes, prepare

FP = 'A' * 40
OTHER = 'B' * 40
STATUS = f'[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG {FP[-16:]} ignored UID\n[GNUPG:] VALIDSIG {FP} 1970-01-01 100 0 4 0 22 10 00 {FP}\n[GNUPG:] TRUST_UNDEFINED 0 pgp\n'
KEYS = {FP: {'primary': FP, 'validity': '-', 'created': 1, 'expires': 2000, 'capabilities': 'sc'}}


def member(name, kind='file', link='', size=0):
    item = tarfile.TarInfo(name)
    item.type = {'directory': tarfile.DIRTYPE, 'file': tarfile.REGTYPE, 'symlink': tarfile.SYMTYPE,
                 'hardlink': tarfile.LNKTYPE, 'fifo': tarfile.FIFOTYPE, 'device': tarfile.CHRTYPE}[kind]
    item.size = size; item.linkname = link
    return item


def minimal():
    return [member(ROOT, 'directory'), member('version'), member('pkglist.x86_64.txt'),
            member(ROOT + '/usr', 'directory'), member(ROOT + '/usr/file', size=5)]


class SignatureTests(unittest.TestCase):
    def test_direct_full_fingerprint_policy_does_not_claim_package_trust(self):
        result = verify_status(STATUS, 0, FP, KEYS, 1000)
        self.assertTrue(result['signature_valid'])
        self.assertFalse(result['release_authorized'])
        self.assertIn('not-general-Web-of-Trust', result['trust_policy'])

    def test_wrong_signer_error_expiry_weak_hash_and_multiple_signatures(self):
        variants = [STATUS.replace(FP, OTHER), STATUS.replace(' 100 0 ', ' 1100 0 '),
                    STATUS.replace(' 100 0 ', ' 100 900 '), STATUS.replace(' 22 10 00 ', ' 22 2 00 '),
                    STATUS.replace(' 22 10 00 ', ' 22 10 01 '), STATUS + STATUS,
                    STATUS.replace('[GNUPG:] GOODSIG', '[GNUPG:] NOTGOODSIG'), 'garbage\n' + STATUS]
        variants += [STATUS + '[GNUPG:] ' + tag + ' rejected\n' for tag in
                     ('BADSIG', 'ERRSIG', 'NO_PUBKEY', 'EXPKEYSIG', 'EXPSIG', 'KEYREVOKED', 'REVKEYSIG', 'TRUST_NEVER', 'FAILURE')]
        for value in variants:
            with self.subTest(value=value[:80]):
                with self.assertRaises(Invalid):
                    verify_status(value, 0, FP, KEYS, 1000)
        with self.assertRaises(Invalid):
            verify_status(STATUS, 1, FP, KEYS, 1000)

    def test_unused_expired_key_notice_is_not_a_rejection_but_expired_signer_is(self):
        # GnuPG emits KEYEXPIRED for expired keys it merely considered (e.g. unused subkeys).
        noisy = STATUS.replace('[GNUPG:] NEWSIG\n', '[GNUPG:] KEYEXPIRED 1642399435\n[GNUPG:] NEWSIG\n[GNUPG:] KEYEXPIRED 1627870212\n')
        self.assertTrue(verify_status(noisy, 0, FP, KEYS, 1000)['signature_valid'])
        keys = copy.deepcopy(KEYS);keys[FP]['expires'] = 900
        with self.assertRaises(Invalid):verify_status(noisy, 0, FP, keys, 1000)

    def test_key_validity_and_subkey_binding(self):
        for update in ({'expires': 900}, {'created': 200}, {'validity': 'r'}, {'capabilities': 'scD'}, {'primary': OTHER}):
            keys = copy.deepcopy(KEYS);keys[FP].update(update)
            with self.assertRaises(Invalid):
                verify_status(STATUS, 0, FP, keys, 1000)
        keys = copy.deepcopy(KEYS)
        keys[OTHER] = dict(keys[FP], primary=FP, capabilities='s')
        subkey_status = STATUS.replace('VALIDSIG ' + FP, 'VALIDSIG ' + OTHER)
        self.assertTrue(verify_status(subkey_status, 0, FP, keys, 1000)['signature_valid'])

    def test_public_key_listing_and_private_marker_rejection(self):
        listing = f'pub:-:255:22:KEY:1:2000::-:::sc:\nfpr:::::::::{FP}:\nsub:-:255:22:SUB:2:2000:::::s:\nfpr:::::::::{OTHER}:\n'
        keys = parse_key_listing(listing)
        self.assertEqual(keys[OTHER]['primary'], FP)
        with self.assertRaises(Invalid):
            parse_key_listing('sec:-:255:22:PRIVATE:\n')
        with self.assertRaises(Invalid):
            parse_key_listing(listing + listing)
        self.assertEqual(parse_key_listing(listing + listing, allow_identical_duplicates=True), keys)
        with self.assertRaises(Invalid):
            parse_key_listing(listing + listing.replace(':2000:', ':3000:'), allow_identical_duplicates=True)

    def test_review_lock_expiry_and_structure(self):
        policy = {
            'schema_version': 1,
            'purpose': 'development-bootstrap-not-release',
            'release': '2000.01.01',
            'expected_primary_fingerprint': FP,
            'reviewed_at': '2000-01-01T00:00:00+00:00',
            'review_before': '2000-01-08T00:00:00+00:00',
            'inputs': {
                role: {'file': name, 'bytes': 4, 'sha256': 'a' * 64,
                       'url': f'https://example.invalid/{name}'}
                for role, name in FILES.items()
            },
        }
        reviewed = datetime(2000, 1, 2, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'lock.json'
            path.write_text(json.dumps(policy))
            self.assertEqual(read_lock(path, reviewed), policy)
            for date in (datetime(1999, 12, 31, tzinfo=timezone.utc),
                         datetime(2000, 1, 8, tzinfo=timezone.utc)):
                with self.assertRaises(Invalid):
                    read_lock(path, date)
            for mutate in (lambda p: p.update(schema_version=True),
                           lambda p: p.update(expected_primary_fingerprint=FP[-8:]),
                           lambda p: p['inputs']['artifact'].update(file='../escape'),
                           lambda p: p.update(review_before='2000-01-09T00:00:00+00:00')):
                invalid = copy.deepcopy(policy)
                mutate(invalid)
                path.write_text(json.dumps(invalid))
                with self.assertRaises(Invalid):
                    read_lock(path, reviewed)

    def test_hashes_and_final_input_symlinks_are_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy = {'inputs': {}}
            for role, name in (('artifact', 'bootstrap.tar.zst'), ('signature', 'bootstrap.tar.zst.sig'), ('certificate', 'release-key.pgp')):
                (root / name).write_bytes(b'data')
                policy['inputs'][role] = {'bytes': 4, 'sha256': hashlib.sha256(b'data').hexdigest()}
            self.assertEqual(check_input_files(root, policy), root)
            (root / 'bootstrap.tar.zst').write_bytes(b'evil')
            with self.assertRaises(Invalid):
                check_input_files(root, policy)
            (root / 'bootstrap.tar.zst').write_bytes(b'data')
            (root / 'release-key.pgp').unlink()
            (root / 'release-key.pgp').symlink_to(root / 'bootstrap.tar.zst')
            with self.assertRaises(Invalid):
                check_input_files(root, policy)

    def test_sandbox_has_no_private_home_network_or_auto_key_retrieval(self):
        argv = sandbox(Path('/scratch/out'), Path('/scratch/in'))
        self.assertIn('--unshare-all', argv)
        self.assertIn('--no-autostart', argv)
        self.assertIn('--no-auto-key-retrieve', argv)
        bindings = [argv[i + 1] for i, value in enumerate(argv) if value == '--ro-bind']
        self.assertEqual(bindings, ['/usr', '/scratch/in/bootstrap.tar.zst', '/scratch/in/bootstrap.tar.zst.sig', '/scratch/in/release-key.pgp'])
        self.assertNotIn('/home', argv)


class ArchiveTests(unittest.TestCase):
    def test_minimal_and_guest_absolute_symlink(self):
        items = minimal() + [member(ROOT + '/link', 'symlink', '/usr/file'), member(ROOT + '/hard', 'hardlink', ROOT + '/usr/file')]
        result = validate_members(items)
        self.assertTrue(result['archive_policy_valid'])
        self.assertFalse(result['deployable_root'])
        self.assertEqual(result['regular_bytes'], 5)

    def test_systemd_literal_hex_escapes_are_posix_names(self):
        path = ROOT + r'/usr/system-systemd\x2dcryptsetup.slice'
        items = minimal() + [member(path), member(ROOT + '/unit', 'symlink', r'usr/system-systemd\x2dcryptsetup.slice')]
        self.assertTrue(validate_members(items)['archive_policy_valid'])
        with self.assertRaises(Invalid):
            describe(member(ROOT + r'/usr/bad\qname'))

    def test_bad_paths_types_and_root_metadata(self):
        cases = [member('/etc/passwd'), member(ROOT + '/../escape'), member(ROOT + '/x//y'),
                 member('other'), member(ROOT + '/fifo', 'fifo'), member(ROOT + '/dev', 'device'),
                 member('version', 'symlink', '/usr/file'), member(ROOT + '/big', size=MAX_UNPACKED + 1),
                 member(ROOT + '/x\\y'), member(ROOT + '/x\ny')]
        for item in cases:
            with self.subTest(name=item.name):
                with self.assertRaises(Invalid):
                    describe(item)

    def test_duplicate_missing_and_link_ancestors(self):
        cases = [minimal() + [member(ROOT + '/usr/file')], minimal()[1:],
                 minimal() + [member(ROOT + '/missing/file')],
                 minimal() + [member(ROOT + '/link', 'symlink', 'usr'), member(ROOT + '/link/child')]]
        for items in cases:
            with self.assertRaises(Invalid):
                validate_members(items)

    def test_escaping_cyclic_and_symlink_hardlinks(self):
        cases = [minimal() + [member(ROOT + '/link', 'symlink', '../../outside')],
                 minimal() + [member(ROOT + '/hard', 'hardlink', 'version')],
                 minimal() + [member(ROOT + '/a', 'hardlink', ROOT + '/b'), member(ROOT + '/b', 'hardlink', ROOT + '/a')],
                 minimal() + [member(ROOT + '/a', 'symlink', 'usr/file'), member(ROOT + '/b', 'hardlink', ROOT + '/a')]]
        for items in cases:
            with self.assertRaises(Invalid):
                validate_members(items)

    def test_sanitization_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp);root = base / 'root';root.mkdir()
            outside = base / 'outside';outside.write_text('untouched');outside.chmod(0o4755)
            (root / 'link').symlink_to(outside)
            (root / 'file').write_text('inside');(root / 'file').chmod(0o6755)
            (root / 'inaccessible').mkdir(mode=0o000)
            result = strip_privileged_modes(root)
            self.assertEqual(result['private_directory_owner_access_repairs'], 1)
            self.assertEqual((root / 'inaccessible').stat().st_mode & 0o700, 0o700)
            self.assertEqual(result['remaining_special_modes_removed'], 1)
            self.assertEqual((root / 'file').stat().st_mode & 0o6000, 0)
            self.assertEqual(outside.stat().st_mode & 0o6000, 0o4000)

    def test_extract_and_toolroot_commands_are_narrow(self):
        argv = extractor_argv(Path('/input/archive'), Path('/output/new'))
        for flag in ('--no-same-owner', '--no-same-permissions', '--no-xattrs', '--no-acls'):
            self.assertIn(flag, argv)
        argv = toolroot_argv(Path('/clean/root'), 'packages')
        bindings = [argv[i + 1] for i, v in enumerate(argv) if v == '--ro-bind']
        self.assertEqual(bindings, ['/clean/root'])
        self.assertEqual(argv[-2:], ['/usr/bin/pacman', '--query'])
        with self.assertRaises(Invalid):
            toolroot_argv(Path('/clean/root'), 'install')

    @unittest.skipIf(sys.version_info < (3, 14), 'explicit zstd preparation requires Python 3.14')
    def test_bad_signature_stops_before_archive_parser_or_extractor(self):
        with tempfile.TemporaryDirectory() as temp, \
             patch('prepare_bootstrap.os.geteuid', return_value=1000), \
             patch('prepare_bootstrap.shutil.disk_usage') as space, \
             patch('prepare_bootstrap.verify', side_effect=Invalid('bad signature')), \
             patch('prepare_bootstrap.audit_archive') as audit, \
             patch('prepare_bootstrap.command') as execute:
            space.return_value.free = 100 * 1024**3
            output = Path(temp) / 'out'
            with self.assertRaises(Invalid):
                prepare('lock', 'inputs', output)
            audit.assert_not_called()
            execute.assert_not_called()
            report = json.loads((output / 'preparation.json').read_text())
            self.assertEqual(report['status'], 'FAIL')
            self.assertFalse(report['release_authorized'])

    def test_root_is_refused_before_work(self):
        with patch('signed_bootstrap.os.geteuid', return_value=0), patch('signed_bootstrap.subprocess.run') as execute:
            with self.assertRaises(Invalid):
                verify('missing', 'missing', 'missing')
            with self.assertRaises(Invalid):
                prepare('missing', 'missing', 'missing')
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
