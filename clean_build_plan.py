#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Print-only clean-builder dependency plan; no acquisition, install or build."""
import argparse
from datetime import datetime, timezone
import json
import os
import re
from pathlib import Path
import shutil
import subprocess

from contract import Invalid, digest, load
from headless_plan import check_empty_target, parse_resolution, read_seed, resolver_argv
from lab_resources import constrain_job
from signed_bootstrap import FREE_FLOOR, new_output

BUILD_TOOLS = ('base-devel', 'devtools', 'python')


def package_index(document):
    if not isinstance(document, dict) or not isinstance(document.get('packages'), list) or len(document['packages']) > 512:
        raise Invalid('bounded package manifest required')
    result = {}
    for row in document['packages']:
        if not isinstance(row, dict):raise Invalid('package record required')
        name = row.get('name');version = row.get('version');checksum = row.get('sha256_from_metadata')
        if (not isinstance(name, str) or re.fullmatch('[a-z0-9][a-z0-9@+_.-]*', name) is None or name in result or
            not isinstance(version, str) or re.fullmatch('[A-Za-z0-9][A-Za-z0-9.+_:~-]*', version) is None or
            row.get('architecture') not in ('x86_64', 'any') or
            not isinstance(checksum, str) or re.fullmatch('[0-9a-f]{64}', checksum) is None):
            raise Invalid('invalid or duplicate build-plan package identity')
        result[name] = row
    return result


def missing_payload(resolution, available):
    known = package_index(available)
    missing = []
    for row in package_index(resolution).values():
        old = known.get(row['name'])
        if old is None or any(old[key] != row[key] for key in ('version', 'architecture', 'sha256_from_metadata')):
            missing.append(row)
    return missing


def plan(toolroot, seed_path, databases, available, output):
    if os.geteuid() == 0:raise Invalid('unprivileged dependency planning required')
    resources = constrain_job(cpu_limit=8)
    root = Path(toolroot).resolve(strict=True);seed_path = Path(seed_path).resolve(strict=True)
    if root == Path('/') or not (root/'usr/bin/pacman').is_file():raise Invalid('explicit prepared toolroot required')
    seed_hash = digest(seed_path);seed = read_seed(seed_path)
    available = Path(available).resolve(strict=True)
    available_hash = digest(available);available_document = load(available)
    package_index(available_document)
    # Build tools belong only to this isolated plan, never the runtime seed.
    requested = dict(seed, requested_packages=sorted(set(seed['requested_packages']) | set(BUILD_TOOLS)))
    output = Path(output).absolute()
    if shutil.disk_usage(output.parent).free < FREE_FLOOR+80*1024**2:raise Invalid('build-plan headroom')
    out = new_output(output)
    for name in ('db/local', 'db/sync', 'cache', 'gpg'):(out/name).mkdir(parents=True, exist_ok=True)
    for item in seed['databases']:
        path = Path(databases)/item['file']
        if path.is_symlink() or not path.is_file() or path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
            raise Invalid('build-plan metadata binding mismatch')
        destination = out/'db/sync'/item['file']
        shutil.copyfile(path, destination)
        if destination.stat().st_size != item['bytes'] or digest(destination) != item['sha256']:
            raise Invalid('build-plan database changed while copying')
    config = '[options]\nArchitecture = x86_64\nRootDir = /tmp/target\nDBPath = /tmp/plan/db\nCacheDir = /tmp/plan/cache\nGPGDir = /tmp/plan/gpg\nLogFile = /tmp/plan/pacman.log\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = Required\n'
    for item in seed['databases']:config += f"[{item['repository']}]\nServer = {item['server']}\n"
    (out/'pacman.conf').write_text(config)
    args = resolver_argv(root, out, requested)
    (out/'command.json').write_text(json.dumps(args, indent=2)+'\n')
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=40, env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
    if len(result.stdout)+len(result.stderr) > 2*1024**2:raise Invalid('build-plan output bound')
    (out/'stdout').write_bytes(result.stdout);(out/'stderr').write_bytes(result.stderr)
    if result.returncode:raise Invalid('clean-build dependency resolution failed')
    resolved = parse_resolution(result.stdout.decode(), requested)
    check_empty_target(out)
    if digest(seed_path) != seed_hash or digest(available) != available_hash:
        raise Invalid('build-plan input changed during resolution')
    for item in seed['databases']:
        path = out/'db/sync'/item['file']
        if path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
            raise Invalid('build-plan database changed during resolution')
    absent = missing_payload(resolved, available_document)
    report = {'status': 'PASS-print-only-clean-build-plan', 'checked_at': datetime.now(timezone.utc).isoformat(),
              'runtime_seed_sha256': seed_hash, 'available_manifest_sha256': available_hash,
              'databases': seed['databases'], 'toolchain_freshly_verified': False,
              'additional_requested_packages': list(BUILD_TOOLS), 'host_resource_policy': resources,
              'resolution': resolved, 'missing_from_recorded_runtime_payload': absent,
              'missing_download_bytes_from_metadata': sum(row['download_bytes_from_metadata'] for row in absent),
              'package_authentication_performed': False, 'package_bytes_downloaded': False, 'target_installed': False,
              'build_executed': False, 'clean_arch_toolchain': False, 'release_authorized': False,
              'scope': 'hash-bound dated metadata and existing read-only prepared toolroot; not fresh package authentication or deployable builder'}
    (out/'plan.json').write_text(json.dumps(report, indent=2)+'\n');return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('toolroot', 'seed', 'databases', 'available', 'output'):parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(plan(args.toolroot, args.seed, args.databases, args.available, args.output), indent=2))
