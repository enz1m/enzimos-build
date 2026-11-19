# SPDX-License-Identifier: MIT
"""Build a local developer extension from a verified frozen package catalogue."""
import json
import os
from pathlib import Path
import shutil
from contract import Invalid, digest, load
from headless_plan import DEVELOPER_PROFILES, read_seed, resolve
from signed_bootstrap import new_output


CONDITIONAL_BASE = frozenset({'nvidia-open', 'nvidia-open-lts', 'nvidia-utils', 'lib32-nvidia-utils'})

def required_base_versions(packages):
    return {p['name']: p['version'] for p in packages if p['name'] not in CONDITIONAL_BASE}


def require(value, message):
    if not value:
        raise Invalid(message)


def prepare(cohort, base_plan, toolroot, databases, output):
    cohort, base_plan = Path(cohort), Path(base_plan)
    verification = load(cohort / 'verification/verification.json')
    catalogue = load(cohort / 'catalogue.json')
    plan_path = cohort / 'resolution/resolution.json'
    plan = load(plan_path)
    seed = read_seed(cohort / 'seed.json')
    require(seed['purpose'] == 'developer-setup-fixtures-not-product-payload', 'developer catalogue purpose')
    require(catalogue['status'] == 'PASS-foundation-catalogue' and catalogue['plan_sha256'] == digest(plan_path), 'developer catalogue binding')
    require(verification['status'] == 'PASS-package-signatures-and-quorum' and verification['plan_sha256'] == digest(plan_path), 'developer verification binding')
    verified = {p['name']: p for p in verification['packages']}
    require(len(verified) == len(plan['packages']) and all(verified[p['name']]['sha256_from_metadata'] == p['sha256_from_metadata'] for p in plan['packages']), 'developer verified package inventory')
    base = load(base_plan)
    require(base['repository_snapshot'] == seed['repository_snapshot'], 'developer base snapshot mismatch')
    base_versions = {p['name']: p['version'] for p in base['packages']}
    require({'filesystem', 'glibc', 'pacman', 'systemd'}.issubset(base_versions), 'developer base anchors missing')
    require(all(p['name'] not in base_versions or p['version'] == base_versions[p['name']] for p in plan['packages']), 'developer partial-upgrade refused')
    output = new_output(output)
    payload = output / 'packages'
    payload.mkdir(mode=0o700)
    rows = []
    closures = {}
    for name, roots in sorted(DEVELOPER_PROFILES.items()):
        subset = dict(seed, purpose=f'developer-profile-{name}-fixtures-not-product-payload', requested_packages=sorted(roots))
        source = output / f'{name}-seed.json'
        source.write_text(json.dumps(subset, indent=2) + '\n')
        result = resolve(Path(toolroot).resolve(strict=True), source, databases, output / f'{name}-resolution')
        for p in result['packages']:
            require(p['name'] in verified and p['sha256_from_metadata'] == verified[p['name']]['sha256_from_metadata'], 'developer profile outside verified closure')
        closures[name] = sorted(p['name'] for p in result['packages'])
    for p in plan['packages']:
        filename = p['url'].rsplit('/', 1)[-1]
        original = cohort / 'packages' / filename
        signature = original.with_name(filename + '.sig')
        require(original.is_file() and not original.is_symlink() and original.stat().st_size == p['download_bytes_from_metadata'] and digest(original) == p['sha256_from_metadata'], 'developer package changed')
        require(signature.is_file() and not signature.is_symlink() and digest(signature) == verified[p['name']]['signature_sha256'], 'developer signature changed')
        for src in (original, signature):
            shutil.copy2(src, payload / src.name)
            (payload / src.name).chmod(0o644)
        rows.append({'name': p['name'], 'version': p['version'], 'filename': filename,
                     'bytes': p['download_bytes_from_metadata'], 'sha256': p['sha256_from_metadata'],
                     'signature_sha256': verified[p['name']]['signature_sha256'],
                     'url': p['url'], 'signature_bytes': signature.stat().st_size})
    manifest = {'schema': 2, 'kind': 'enzimos-developer-extension', 'id': 'developer-' + seed['repository_snapshot'],
                'base_packages': required_base_versions(base['packages']), 'packages': rows, 'profiles': {name: sorted(roots) for name, roots in DEVELOPER_PROFILES.items()},
                'closures': closures, 'release_authorized': False}
    target = output / 'manifest.json'
    target.write_text(json.dumps(manifest, indent=2) + '\n')
    target.chmod(0o644)
    report = {'status': 'PASS-local-developer-extension-built', 'release_authorized': False,
              'manifest_sha256': digest(target), 'base_plan_sha256': digest(base_plan),
              'verified_plan_sha256': digest(plan_path), 'package_count': len(rows),
              'profile_package_counts': {name: len(packages) for name, packages in closures.items()},
              'transport_authority': 'explicit private fixture; production requires signed release metadata admission'}
    (output / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
