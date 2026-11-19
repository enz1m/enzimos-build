#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit bounded dated metadata acquisition and authenticated full headless closure."""
import argparse
from datetime import date, datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.request import build_opener, ProxyHandler, Request

from acquire_packages import acquire, NoRedirects
from contract import Invalid, digest, load
from headless_plan import read_seed, resolve
from package_trust import verify_plan
from package_closure import check
from signed_bootstrap import new_output, FREE_FLOOR


def changes(old, new):
    before = {p['name']: p for p in old['packages']}
    after = {p['name']: p for p in new['packages']}
    return {'added': sorted(after.keys() - before.keys()), 'removed': sorted(before.keys() - after.keys()),
            'changed': [{'name': n, 'old': before[n]['version'], 'new': after[n]['version']} for n in sorted(before.keys() & after.keys()) if before[n]['sha256_from_metadata'] != after[n]['sha256_from_metadata']]}


def prepare(snapshot, original_seed, old_plan, old_packages, toolroot, keyring, trust_lock, output):
    if os.geteuid() == 0:
        raise Invalid('run unprivileged')
    seed = read_seed(original_seed)
    day = date.fromisoformat(snapshot)
    if str(day) != snapshot or not date.fromisoformat(seed['repository_snapshot']) < day <= datetime.now(timezone.utc).date():
        raise Invalid('snapshot must be later than the baseline and not in the future')
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR + 2 * 1024**3:
        raise Invalid('insufficient catalogue headroom')
    output = new_output(output)
    result = {'status': 'FAIL', 'release_authorized': False}
    try:
        db = output / 'databases'; db.mkdir()
        seed['repository_snapshot'] = snapshot
        opener = build_opener(ProxyHandler({}), NoRedirects())
        deadline = time.monotonic() + 180
        for item in seed['databases']:
            server = f"https://archive.archlinux.org/repos/{snapshot.replace('-', '/')}/{item['repository']}/os/x86_64"
            path = db / item['file']; count = 0
            with opener.open(Request(server + '/' + item['file'], headers={'User-Agent': 'enzimos-explicit-update-lab'}), timeout=25) as response, path.open('xb') as stream:
                if response.status != 200:
                    raise Invalid('unexpected repository metadata response')
                while block := response.read(1024**2):
                    count += len(block)
                    if count > 32 * 1024**2 or time.monotonic() > deadline or shutil.disk_usage(output).free < FREE_FLOOR:
                        raise Invalid('metadata acquisition bound exceeded')
                    stream.write(block)
            item.update(server=server, bytes=count, sha256=digest(path))
        seed_path = output / 'seed.json'; seed_path.write_text(json.dumps(seed, indent=2) + '\n')
        resolved = resolve(Path(toolroot).resolve(strict=True), seed_path, db, output / 'resolution')
        plan_path = output / 'resolution/resolution.json'
        delta = changes(load(old_plan), resolved)
        (output / 'changes.json').write_text(json.dumps(delta, indent=2) + '\n')
        packages = output / 'packages'; packages.mkdir()
        missing = []
        for item in resolved['packages']:
            name = item['url'].rsplit('/', 1)[-1]
            old = Path(old_packages) / name
            if old.is_file() and not old.is_symlink() and digest(old) == item['sha256_from_metadata']:
                for suffix in ('', '.sig'):
                    source = Path(old_packages) / (name + suffix)
                    if source.is_symlink() or not source.is_file():
                        raise Invalid('invalid reused package/signature')
                    os.link(source, packages / source.name)
            else:
                missing.append(item)
        if missing:
            subset = dict(resolved, packages=missing)
            (output / 'download-plan.json').write_text(json.dumps(subset, indent=2) + '\n')
            acquire(output / 'download-plan.json', output / 'downloaded')
            for item in missing:
                name = item['url'].rsplit('/', 1)[-1]
                for suffix in ('', '.sig'):
                    os.link(output / 'downloaded' / (name + suffix), packages / (name + suffix))
        verification = verify_plan(plan_path, keyring, packages, output / 'verification', trust_lock)
        closure = check(toolroot, packages, plan_path, seed_path, output / 'closure')
        result.update(status='PASS-authenticated-update-catalogue', checked_at=datetime.now(timezone.utc).isoformat(),
                      snapshot=snapshot, package_count=verification['package_count'], newly_acquired=len(missing),
                      downloaded_package_bytes=sum(p['download_bytes_from_metadata'] for p in missing), changes=delta,
                      seed_sha256=digest(seed_path), plan_sha256=digest(plan_path),
                      trust_lock_sha256=digest(Path(trust_lock)), closure_status=closure['status'],
                      repository_metadata_signature_authenticated=False, guest_update_executed=False)
        return result
    except BaseException as exc:
        result['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise
    finally:
        (output / 'catalogue.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--snapshot', required=True)
    for name in ('original-seed', 'old-plan', 'old-packages', 'toolroot', 'keyring', 'trust-lock', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    try:
        print(json.dumps(prepare(a.snapshot, a.original_seed, a.old_plan, a.old_packages, a.toolroot, a.keyring, a.trust_lock, a.output), indent=2))
    except (Invalid, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
