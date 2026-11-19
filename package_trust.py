#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline Arch package checks using isolated single-master GnuPG contexts."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from contract import Invalid, digest, load
from signed_bootstrap import parse_key_listing, verify_status, new_output

MASTERS = (
    '2AC0A42EFB0B5CBC7A0402ED4DC95B6D7BE9892E',
    '3572FA2A1B067F22C58AF155F8B821B42A6FDCD7',
    '69E6471E3AE065297529832E6BA0F5A2037F4F41',
    '99B6618472A3B3B814185BAED7D3D823B88BDB9B',
    'D8AFDDA07A5B6EDFA7D8CCDAD6D055F927843F1C',
)
UID = re.compile(r'[^<>\r\n]*<[^ <>@]+@archlinux\.org>')


def valid_identities(listing):
    result = set()
    primary = None
    waiting = False
    usable = False
    for line in listing.splitlines():
        row = line.split(':')
        if row[0] in ('sec', 'ssb'):
            raise Invalid('private key material is forbidden')
        if row[0] == 'pub':
            waiting = True; primary = None
            usable = len(row) > 11 and row[1] not in ('r', 'e', 'd', 'i') and 'D' not in row[11]
        elif row[0] == 'fpr' and waiting:
            if len(row) < 10 or not re.fullmatch('[0-9A-F]{40}', row[9]):
                raise Invalid('invalid primary fingerprint in certification listing')
            primary = row[9]; waiting = False
        elif row[0] == 'uid' and primary and usable:
            if len(row) > 9 and row[1] in ('f', 'u') and UID.fullmatch(row[9]):
                result.add((primary, row[9]))
    return result


def quorum(listings, revoked):
    if len(listings) != len(MASTERS) or set(listings) != set(MASTERS):
        raise Invalid('exactly one independent context per reviewed master is required')
    approvals = {}
    for master, text in listings.items():
        if master in revoked:
            raise Invalid('a pinned master has been revoked; review required')
        for identity in valid_identities(text):
            approvals.setdefault(identity, set()).add(master)
    accepted = {}
    for (primary, identity), masters in approvals.items():
        if len(masters) >= 3 and primary not in revoked and primary not in MASTERS:
            accepted.setdefault(primary, []).append({'identity': identity, 'masters': sorted(masters)})
    return accepted


def revoked_keys(text):
    values = set(text.splitlines())
    if not values or any(not re.fullmatch('[0-9A-F]{40}', value) for value in values):
        raise Invalid('invalid administrative revocation list')
    return values


def accept_status(status, code, keys, eligible, revoked, now):
    records = [line.split() for line in status.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
    if len(records) != 1 or len(records[0]) != 12:
        raise Invalid('exactly one data-signature identity required')
    primary, signer = records[0][-1], records[0][2]
    if primary not in eligible or primary in revoked or signer in revoked:
        raise Invalid('signer lacks current three-master same-identity approval or is revoked')
    checked = verify_status(status, code, primary, keys, now)
    checked.update(trust_policy='three-independent-current-master-contexts-same-archlinux.org-UID',
                   certifications=eligible[primary], release_authorized=False)
    return checked


def gpg_base(output, keyring, packages, home, filename=None):
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib', '/lib64', '--dir', '/etc', '--dev', '/dev', '--proc', '/proc',
            '--tmpfs', '/tmp', '--dir', '/keyring', '--ro-bind', str(keyring / 'archlinux.gpg'), '/keyring/archlinux.gpg',
            '--dir', '/packages',
            *([] if filename is None else ['--ro-bind', str(packages / filename), '/packages/' + filename,
                                           '--ro-bind', str(packages / (filename + '.sig')), '/packages/' + filename + '.sig']),
            '--bind', str(output), '/work', '--setenv', 'PATH', '/usr/bin', '--setenv', 'LANG', 'C.UTF-8',
            '--setenv', 'HOME', '/work/' + home, '--', '/usr/bin/prlimit', '--cpu=40:40',
            '--as=1073741824:1073741824', '--fsize=8388608:8388608', '--', '/usr/bin/gpg',
            '--no-options', '--batch', '--no-tty', '--no-autostart', '--no-auto-key-retrieve',
            '--auto-key-locate', 'clear', '--trust-model', 'classic', '--max-cert-depth', '1',
            '--homedir', '/work/' + home]


def execute(argv, output, label):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=50,
                            env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
    if len(result.stdout) + len(result.stderr) > 8 * 1024**2:
        raise Invalid('GnuPG output exceeds bound')
    (output / (label + '.stdout')).write_bytes(result.stdout)
    (output / (label + '.stderr')).write_bytes(result.stderr)
    return result


def prepare_contexts(output, keyring, packages):
    ring = keyring / 'archlinux.gpg'
    revoked = revoked_keys((keyring / 'archlinux-revoked').read_text())
    if not ring.is_file() or ring.is_symlink() or ring.stat().st_size > 4 * 1024**2:
        raise Invalid('expected a bounded reviewed public keyring')
    keys = None; listings = {}
    for index, master in enumerate(MASTERS):
        home = 'master-' + str(index)
        (output / home).mkdir(mode=0o700)
        (output / (home + '.trust')).write_text(master + ':6:\n')
        base = gpg_base(output, keyring, packages, home)
        steps = [('preflight', ['--with-colons', '--import-options', 'show-only', '--import', '/keyring/archlinux.gpg']),
                 ('import', ['--import', '/keyring/archlinux.gpg']),
                 ('ownertrust', ['--import-ownertrust', '/work/' + home + '.trust']),
                 ('trustdb', ['--check-trustdb']),
                 ('listing', ['--with-colons', '--fixed-list-mode', '--fingerprint', '--list-keys'])]
        for label, args in steps:
            result = execute(base + args, output, home + '-' + label)
            if result.returncode != 0:
                raise Invalid('public trust-context setup failed')
            if label == 'preflight':
                parse_key_listing(result.stdout.decode(), allow_identical_duplicates=True)
            if label == 'listing':
                listings[master] = result.stdout.decode()
                if keys is None:
                    keys = parse_key_listing(listings[master])
    now = int(time.time())
    for master in MASTERS:
        key = keys.get(master)
        if (key is None or key['validity'] in ('r', 'e', 'd', 'i') or 'D' in key['capabilities']
                or key['created'] > now or (key['expires'] and key['expires'] <= now)
                or 'c' not in key['capabilities']):
            raise Invalid('pinned master key is unavailable, unusable or expired')
    return keys, quorum(listings, revoked), revoked


def check_trust_lock(path, keyring, now=None):
    value = load(path)
    if type(value) is not dict or type(value.get('schema_version')) is not int or value['schema_version'] != 1 or value.get('masters') != list(MASTERS):
        raise Invalid('trust lock does not match the reviewed master set')
    try:
        # A one-time review: the pinned keyring is the trust anchor, so it does not expire.
        start = datetime.fromisoformat(value['reviewed_at'])
        clock = datetime.now(timezone.utc) if now is None else now
        if start.utcoffset() is None or not start <= clock:
            raise ValueError('review from the future')
    except (TypeError, ValueError, KeyError) as exc:
        raise Invalid('current timezone-aware trust review required') from exc
    for filename in ('archlinux.gpg', 'archlinux-revoked'):
        record = value['files'][filename]; source = keyring / filename
        if (type(record.get('bytes')) is not int or not 0 < record['bytes'] <= 4 * 1024**2
                or type(record.get('sha256')) is not str or not re.fullmatch('[0-9a-f]{64}', record['sha256'])):
            raise Invalid('invalid keyring pin')
        if source.is_symlink() or not source.is_file() or source.stat().st_size != record['bytes'] or digest(source) != record['sha256']:
            raise Invalid('public keyring/revocation data do not match the reviewed trust lock')
    return value


def verify_plan(plan_path, keyring, packages, output, trust_lock):
    if os.geteuid() == 0:
        raise Invalid('run package verification unprivileged')
    plan = load(plan_path)
    plan_hash = digest(Path(plan_path))
    if type(plan) is not dict:
        raise Invalid('package plan must be an object')
    if type(plan.get('packages')) is not list or not 0 < len(plan['packages']) <= 1024:
        raise Invalid('invalid bounded package plan')
    keyring = Path(keyring).resolve(strict=True); packages = Path(packages).resolve(strict=True)
    trust = check_trust_lock(trust_lock, keyring)
    output = new_output(output)
    report = {'status': 'FAIL', 'release_authorized': False, 'packages': []}
    try:
        keys, eligible, revoked = prepare_contexts(output, keyring, packages)
        (output / 'eligible.json').write_text(json.dumps(eligible, indent=2) + '\n')
        seen = set()
        for item in plan['packages']:
            if type(item) is not dict or type(item.get('name')) is not str or not re.fullmatch('[a-z0-9][a-z0-9@+_.-]*', item['name']):
                raise Invalid('invalid package identity')
            filename = item['url'].rsplit('/', 1)[-1]
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+:-]*\.pkg\.tar\.(zst|xz)', filename) or filename in seen:
                raise Invalid('invalid or repeated package filename')
            seen.add(filename)
            path = packages / filename; signature = packages / (filename + '.sig')
            if path.is_symlink() or not path.is_file() or path.stat().st_size != item['download_bytes_from_metadata']:
                raise Invalid('package size/type mismatch')
            if digest(path) != item['sha256_from_metadata']:
                raise Invalid('package does not match the reviewed snapshot bytes')
            if signature.is_symlink() or not signature.is_file() or not 0 < signature.stat().st_size <= 65536:
                raise Invalid('missing/bad detached signature file')
            base = gpg_base(output, keyring, packages, 'master-0', filename)
            signature_hash = digest(signature)
            result = execute(base + ['--status-fd', '1', '--verify', '/packages/' + filename + '.sig', '/packages/' + filename], output, item['name'])
            accepted = accept_status(result.stdout.decode(), result.returncode, keys, eligible, revoked, int(time.time()))
            if digest(path) != item['sha256_from_metadata'] or digest(signature) != signature_hash:
                raise Invalid('package/signature changed during verification')
            report['packages'].append(dict(item, signature_sha256=signature_hash, signature=accepted))
        if load(plan_path) != plan or digest(Path(plan_path)) != plan_hash:
            raise Invalid('package plan changed during verification')
        if check_trust_lock(trust_lock, keyring) != trust:
            raise Invalid('trust lock changed during verification')
        report.update(status='PASS-package-signatures-and-quorum', trust_lock_sha256=digest(Path(trust_lock)), checked_at=datetime.now(timezone.utc).isoformat(),
                      package_count=len(report['packages']), plan_sha256=plan_hash,
                      keyring_sha256=digest(keyring / 'archlinux.gpg'), revoked_sha256=digest(keyring / 'archlinux-revoked'),
                      master_fingerprints=list(MASTERS), private_keys_generated=False,
                      qualification='package bytes/signers only; no dependency metadata, target installation or boot qualification')
        return report
    except BaseException as exc:
        report['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise
    finally:
        (output / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'keyring', 'packages', 'output', 'trust-lock'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verify_plan(args.plan, args.keyring, args.packages, args.output, args.trust_lock), indent=2))
    except (Invalid, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
