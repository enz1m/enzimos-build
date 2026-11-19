#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Acquire/verify a complete expanded qualification closure; execution remains separate."""
import argparse
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from acquire_packages import acquire
from contract import Invalid, digest, load
from headless_plan import read_seed, resolve
from package_trust import verify_plan
from package_closure import check
from signed_bootstrap import new_output, FREE_FLOOR


def reuse_file(source,target):
    try:os.link(source,target)
    except OSError as error:
        if error.errno!=errno.EXDEV:raise
        shutil.copyfile(source,target)


def prepare(seed, databases, reuse, toolroot, keyring, trust_lock, output):
    if os.geteuid() == 0:
        raise Invalid('run unprivileged')
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR + 1024**3:
        raise Invalid('insufficient preparation headroom')
    output = new_output(output)
    report = {'status': 'FAIL', 'release_authorized': False}
    try:
        read_seed(seed)
        plan = resolve(Path(toolroot).resolve(strict=True), seed, databases, output / 'resolution')
        plan_path = output / 'resolution/resolution.json'
        packages = output / 'packages'; packages.mkdir()
        missing = []
        for item in plan['packages']:
            name = item['url'].rsplit('/', 1)[-1]
            found = False
            for directory in reuse:
                p = Path(directory) / name; sig = p.with_name(p.name + '.sig')
                if p.is_file() and not p.is_symlink() and p.stat().st_size == item['download_bytes_from_metadata'] and digest(p) == item['sha256_from_metadata'] and sig.is_file() and not sig.is_symlink():
                    reuse_file(p, packages / name); reuse_file(sig, packages / sig.name)
                    found = True; break
            if not found: missing.append(item)
        if missing:
            (output / 'download-plan.json').write_text(json.dumps(dict(plan, packages=missing), indent=2)+'\n')
            acquire(output / 'download-plan.json', output / 'downloaded')
            for item in missing:
                name = item['url'].rsplit('/', 1)[-1]
                for suffix in ('', '.sig'):
                    os.link(output / 'downloaded' / (name+suffix), packages / (name+suffix))
        verification = verify_plan(plan_path, keyring, packages, output / 'verification', trust_lock)
        closure = check(toolroot, packages, plan_path, seed, output / 'closure')
        shutil.copyfile(seed, output / 'seed.json')
        report.update(status='PASS-foundation-catalogue', checked_at=datetime.now(timezone.utc).isoformat(),
                      package_count=verification['package_count'], new_packages=len(missing),
                      new_bytes=sum(p['download_bytes_from_metadata'] for p in missing),
                      closure=closure['status'], seed_sha256=digest(Path(seed)), plan_sha256=digest(plan_path))
        return report
    except BaseException as exc:
        report['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__
        raise
    finally:
        (output / 'catalogue.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('seed','databases','toolroot','keyring','trust-lock','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--reuse',type=Path,action='append',default=[])
    a=p.parse_args()
    try:
        print(json.dumps(prepare(a.seed,a.databases,a.reuse,a.toolroot,a.keyring,a.trust_lock,a.output),indent=2))
    except (Invalid,OSError,ValueError,KeyError,subprocess.SubprocessError) as exc:
        print(json.dumps({'status':'FAIL','error':str(exc) if isinstance(exc,Invalid) else type(exc).__name__}),file=sys.stderr)
        raise SystemExit(2)
