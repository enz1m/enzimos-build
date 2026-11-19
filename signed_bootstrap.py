#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline verification of a reviewed development bootstrap lock; never signs or fetches."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

from contract import Invalid, digest, load, object_fields, same

FINGERPRINT = re.compile(r'[0-9A-F]{40}')
# KEYEXPIRED can describe an unused expired subkey. EXPKEYSIG rejects an expired
# signing key; verify_status also checks the actual signing subkey and primary.
BAD_STATUS = {'BADSIG', 'ERRSIG', 'NO_PUBKEY', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG',
              'SIGEXPIRED', 'KEYREVOKED', 'FAILURE', 'ERROR', 'NODATA', 'TRUST_NEVER'}
MAX_ARCHIVE = 192 * 1024**2
# Operators may reserve extra disk space beyond each operation's bounded inputs.
_reserve = os.environ.get('ENZIMOS_BUILD_RESERVE_GIB', '0')
if not _reserve.isascii() or not _reserve.isdigit() or int(_reserve) > 1048576:
    raise ValueError('ENZIMOS_BUILD_RESERVE_GIB must be a nonnegative integer')
FREE_FLOOR = int(_reserve) * 1024**3
FILES = {'artifact': 'bootstrap.tar.zst', 'signature': 'bootstrap.tar.zst.sig',
         'certificate': 'release-key.pgp'}


def read_lock(path, now=None):
    value = load(path)
    object_fields(value, 'schema_version purpose release expected_primary_fingerprint reviewed_at review_before inputs', 'bootstrap lock')
    same(value['schema_version'], 1, 'bootstrap lock version')
    same(value['purpose'], 'development-bootstrap-not-release', 'bootstrap lock purpose')
    if type(value['release']) is not str or not re.fullmatch(r'\d{4}\.\d{2}\.\d{2}', value['release']):
        raise Invalid('invalid release date')
    if type(value['expected_primary_fingerprint']) is not str or not FINGERPRINT.fullmatch(value['expected_primary_fingerprint']):
        raise Invalid('full uppercase primary fingerprint required')
    try:
        reviewed, before = [datetime.fromisoformat(value[k]) for k in ('reviewed_at', 'review_before')]
        if reviewed.utcoffset() is None or before.utcoffset() is None:
            raise ValueError('timezone required')
        clock = datetime.now(timezone.utc) if now is None else now
        if not reviewed <= clock < before or (before - reviewed).total_seconds() > 7 * 86400:
            raise ValueError('review stale or clock inconsistent')
    except (TypeError, ValueError) as exc:
        raise Invalid('lock needs a current, timezone-aware review (maximum seven days)') from exc
    object_fields(value['inputs'], 'artifact signature certificate', 'bootstrap inputs')
    for role, name in FILES.items():
        item = value['inputs'][role]
        object_fields(item, 'file bytes sha256 url', f'bootstrap {role}')
        same(item['file'], name, f'bootstrap {role} name')
        bound = MAX_ARCHIVE if role == 'artifact' else 512 * 1024
        if type(item['bytes']) is not int or not 0 < item['bytes'] <= bound:
            raise Invalid('input size outside budget')
        if type(item['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', item['sha256']):
            raise Invalid('invalid input SHA-256')
        if type(item['url']) is not str or not item['url'].startswith('https://'):
            raise Invalid('source provenance must use HTTPS; this tool never fetches it')
    return value


def check_input_files(inputs, policy):
    root = Path(inputs).resolve(strict=True)
    for role, name in FILES.items():
        path = root / name
        expected = policy['inputs'][role]
        if path.is_symlink() or not path.is_file() or path.stat().st_size != expected['bytes']:
            raise Invalid('input is missing, nonregular, symlinked or has the wrong size')
        if digest(path) != expected['sha256']:
            raise Invalid('input SHA-256 does not match the reviewed lock')
    return root


def parse_key_listing(text, allow_identical_duplicates=False):
    """Read GnuPG's public-key records; never follow filenames or trust UID strings."""
    keys = {}
    pending = None
    primary = None
    for line in text.splitlines():
        fields = line.split(':')
        if fields[0] in ('sec', 'ssb'):
            raise Invalid('private key material is not permitted')
        if fields[0] in ('pub', 'sub'):
            if len(fields) < 12:
                raise Invalid('malformed public-key record')
            pending = fields
        elif fields[0] == 'fpr' and pending is not None:
            if len(fields) < 10 or not FINGERPRINT.fullmatch(fields[9]):
                raise Invalid('malformed fingerprint record')
            fingerprint = fields[9]
            if pending[0] == 'pub':
                primary = fingerprint
            if primary is None:
                raise Invalid('orphaned key record')
            try:
                created = int(pending[5]); expires = int(pending[6] or '0')
            except ValueError as exc:
                raise Invalid('invalid key validity interval') from exc
            record = {'primary': primary, 'validity': pending[1],
                      'created': created, 'expires': expires, 'capabilities': pending[11]}
            if fingerprint in keys and (not allow_identical_duplicates or keys[fingerprint] != record):
                raise Invalid('duplicate or conflicting key record')
            keys[fingerprint] = record
            pending = None
    return keys


def verify_status(status, returncode, expected_primary, keys, now):
    if returncode != 0:
        raise Invalid('GnuPG rejected the detached signature')
    records = []
    for line in status.splitlines():
        if not line.startswith('[GNUPG:] '):
            raise Invalid('unexpected GnuPG status output')
        fields = line[len('[GNUPG:] '):].split()
        if not fields:
            raise Invalid('empty GnuPG status record')
        if fields[0] in BAD_STATUS:
            raise Invalid('GnuPG reported a signature/key rejection')
        records.append(fields)
    signatures = [r for r in records if r[0] == 'VALIDSIG']
    if len(signatures) != 1 or sum(r[0] == 'GOODSIG' for r in records) != 1 or sum(r[0] == 'NEWSIG' for r in records) != 1:
        raise Invalid('exactly one good data signature required')
    sig = signatures[0]
    if len(sig) != 11 or not FINGERPRINT.fullmatch(sig[1]) or not FINGERPRINT.fullmatch(sig[10]):
        raise Invalid('malformed VALIDSIG record')
    signer, primary = sig[1], sig[10]
    if primary != expected_primary:
        raise Invalid('signature primary key is not the reviewed release identity')
    try:
        created, expires = int(sig[3]), int(sig[4])
    except ValueError as exc:
        raise Invalid('invalid signature times') from exc
    if created <= 0 or created > now or (expires != 0 and expires <= now):
        raise Invalid('signature is expired or from the future')
    if sig[8] not in ('8', '9', '10') or sig[9] != '00':
        raise Invalid('binary signature with SHA-256/384/512 required')
    for fingerprint in {signer, primary}:
        key = keys.get(fingerprint)
        if key is None or key['primary'] != primary:
            raise Invalid('signer is absent from the supplied public certificate')
        if key['validity'] in ('r', 'e', 'd', 'i') or 'D' in key['capabilities']:
            raise Invalid('revoked/expired/disabled/invalid public key')
        if key['created'] > created or key['created'] > now or (key['expires'] and key['expires'] <= now):
            raise Invalid('key validity interval does not permit verification now')
    if 's' not in keys[signer]['capabilities']:
        raise Invalid('signing key lacks signing capability')
    return {'signature_valid': True, 'primary_fingerprint': primary, 'signing_fingerprint': signer,
            'signature_created_unix': created, 'trust_policy': 'reviewed-full-fingerprint-pin-not-general-Web-of-Trust',
            'revocation_scope': 'supplied-reviewed-certificate-only', 'release_authorized': False}


def new_output(path):
    path = Path(path).absolute()
    if '..' in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise Invalid('output traversal/symlinks forbidden')
    path = path.resolve(strict=False)
    if path.is_relative_to(Path(__file__).resolve().parent):
        raise Invalid('output must be outside this source repository')
    path.mkdir(mode=0o700, exist_ok=False)
    return path


def sandbox(output, inputs):
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib', '/lib64', '--dir', '/etc', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/tmp', '--dir', '/inputs',
            *[arg for name in FILES.values() for arg in ('--ro-bind', str(inputs / name), '/inputs/' + name)],
            '--bind', str(output), '/work',
            '--chdir', '/work', '--setenv', 'HOME', '/work/gnupg', '--setenv', 'PATH', '/usr/bin',
            '--setenv', 'LANG', 'C.UTF-8', '--', '/usr/bin/prlimit', '--cpu=30:30',
            '--as=1073741824:1073741824', '--fsize=8388608:8388608', '--', '/usr/bin/gpg',
            '--no-options', '--batch', '--no-tty', '--no-autostart', '--homedir', '/work/gnupg',
            '--no-auto-key-retrieve', '--auto-key-locate', 'clear']


def verify(lock, inputs, output):
    if os.geteuid() == 0:
        raise Invalid('verification tooling must run unprivileged')
    policy = read_lock(lock)
    lock_hash = digest(Path(lock))
    inputs = check_input_files(inputs, policy)
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR:
        raise Invalid('free-space floor reached; no cleanup or host changes attempted')
    output = new_output(output)
    (output / 'gnupg').mkdir(mode=0o700)
    base = sandbox(output, inputs)
    operations = [('public-preflight', ['--with-colons', '--import-options', 'show-only', '--import', '/inputs/release-key.pgp']),
                  ('import', ['--import', '/inputs/release-key.pgp']),
                  ('keys', ['--with-colons', '--fixed-list-mode', '--fingerprint', '--list-keys']),
                  ('verify', ['--status-fd', '1', '--verify', '/inputs/bootstrap.tar.zst.sig', '/inputs/bootstrap.tar.zst'])]
    results = {}
    report = {'status': 'FAIL', 'release_authorized': False, 'host_private_keyring_used': False}
    try:
        for name, args in operations:
            result = subprocess.run(base + args, stdin=subprocess.DEVNULL, capture_output=True,
                                    timeout=40, env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
            if len(result.stdout) + len(result.stderr) > 2 * 1024**2:
                raise Invalid('GnuPG output exceeds bound')
            (output / f'{name}.stdout').write_bytes(result.stdout)
            (output / f'{name}.stderr').write_bytes(result.stderr)
            results[name] = result
            if name != 'verify' and result.returncode != 0:
                raise Invalid('isolated public-certificate preparation failed')
            if name == 'public-preflight':
                public_keys = parse_key_listing(result.stdout.decode('utf-8'), allow_identical_duplicates=True)
                if policy['expected_primary_fingerprint'] not in public_keys:
                    raise Invalid('reviewed public release identity missing before import')
        keys = parse_key_listing(results['keys'].stdout.decode('utf-8'))
        verdict = verify_status(results['verify'].stdout.decode('utf-8'), results['verify'].returncode,
                                policy['expected_primary_fingerprint'], keys, int(time.time()))
        check_input_files(inputs, policy)
        if read_lock(lock) != policy or digest(Path(lock)) != lock_hash:
            raise Invalid('reviewed lock changed during signature verification')
        report.update(verdict, status='PASS-bootstrap-signature-only', checked_at=datetime.now(timezone.utc).isoformat(),
                      release=policy['release'], inputs=policy['inputs'], lock_sha256=lock_hash,
                      private_keys_created=False, package_closure_verified=False, guest_os_booted=False)
        return report
    except BaseException as exc:
        report['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise
    finally:
        (output / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', required=True, type=Path)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path, help='NEW private output directory')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.lock, args.inputs, args.output), indent=2))
    except (Invalid, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status': 'FAIL', 'release_authorized': False,
                          'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
