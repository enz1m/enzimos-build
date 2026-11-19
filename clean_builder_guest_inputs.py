#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit bounded offline builder-payload ISO from freshly authenticated packages."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
from contract import Invalid, digest, load
from package_trust import verify_plan
from foundation_inputs import FIX
from prepare_target_lab import iso_command, public_cache, GPG_CONFIG
from build_initrd_lab import run_command, audit_packages
from lab_resources import constrain_job
from signed_bootstrap import FREE_FLOOR, new_output


def prepare(base_inputs, plan, packages, keyring, trust_lock, output):
    if os.geteuid() == 0:raise Invalid('unprivileged clean-builder input preparation required')
    resources = constrain_job(cpu_limit=8)
    base_inputs = Path(base_inputs).resolve(strict=True);base = load(base_inputs);directory = base_inputs.parent
    if base['status'] != 'PASS-foundation-inputs':raise Invalid('unexpired foundation inputs required')
    for name, row in base['inputs'].items():
        if digest(directory/name) != row['sha256']:raise Invalid('base image changed')
    output = Path(output).absolute()
    if shutil.disk_usage(output.parent).free < FREE_FLOOR+512*1024**2:raise Invalid('builder ISO headroom')
    out = new_output(output);packages = Path(packages).resolve(strict=True)
    verified = verify_plan(plan, keyring, packages, out/'verification', trust_lock)
    audit = audit_packages(packages, verified['packages'])
    (out/'archive-audit.json').write_text(json.dumps(audit, indent=2)+'\n')
    stage = out/'iso-stage';stage.mkdir()
    for path in (directory/'iso-stage').iterdir():
        if path.is_file() and path.name != 'SHA256SUMS':shutil.copyfile(path, stage/path.name)
    for path in FIX.glob('*.py'):shutil.copyfile(path, stage/path.name)
    shutil.copyfile(plan, stage/'clean-builder-plan.json')
    approved = public_cache(out/'admission', Path(keyring).resolve(strict=True), packages, verified['packages'])
    keys = stage/'builder-public-keys';keys.mkdir()
    for name in ('pubring.gpg', 'trustdb.gpg'):shutil.copyfile(out/'admission/public'/name, keys/name)
    (keys/'gpg.conf').write_text(GPG_CONFIG)
    target = stage/'builder-packages';target.mkdir()
    for row in verified['packages']:
        name = row['url'].rsplit('/', 1)[-1]
        for suffix in ('', '.sig'):os.link(packages/(name+suffix), target/(name+suffix))
    (stage/'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.relative_to(stage)}\n' for p in sorted(stage.rglob('*')) if p.is_file()))
    args = iso_command(stage, out)
    if args[-2] != '/output/payload.iso':raise Invalid('ISO output contract')
    args[-2] = '/output/patch.iso';run_command(args, out, 'patch-iso', 120)
    if (out/'patch.iso').stat().st_size > 384*1024**2:raise Invalid('builder ISO size bound')
    for name in base['inputs']:
        if name != 'patch.iso':os.link(directory/name, out/name)
    report = dict(base)
    report.update(checked_at=datetime.now(timezone.utc).isoformat(), host_resource_policy=resources,
                  builder_plan_sha256=digest(Path(plan)), builder_verification_sha256=digest(out/'verification/verification.json'),
                  builder_package_count=verified['package_count'], builder_approved_signers=approved, fixture_hashes={p.name:digest(p) for p in FIX.iterdir() if p.is_file()},
                  inputs={name:{'bytes':(out/name).stat().st_size,'sha256':digest(out/name)} for name in base['inputs']})
    (out/'inputs.json').write_text(json.dumps(report,indent=2)+'\n');return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base-inputs','plan','packages','keyring','trust-lock','output'):parser.add_argument('--'+name,type=Path,required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.base_inputs,args.plan,args.packages,args.keyring,args.trust_lock,args.output),indent=2))
