#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Freshly verify the cached Samba package(s) for a guest-only SMB backup check."""
import argparse
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import shutil
from contract import Invalid,digest,load
from lab_resources import constrain_job
from signed_bootstrap import FREE_FLOOR,new_output
from package_trust import verify_plan
from prepare_target_lab import public_cache,GPG_CONFIG,iso_command
from build_initrd_lab import audit_packages,run_command
from foundation_inputs import FIX
from foundation_catalogue import reuse_file


def prepare(base_path, output, keyring, trust, script=None, *, source):
    if os.geteuid()==0:raise Invalid('unprivileged remote test inputs required')
    resources=constrain_job(cpu_limit=8);base_path=Path(base_path).resolve(strict=True);base=load(base_path)
    if base['status']!='PASS-foundation-inputs':raise Invalid('fresh base inputs required')
    for name,row in base['inputs'].items():
        if digest(base_path.parent/name)!=row['sha256']:raise Invalid('remote base changed')
    output=Path(output).absolute()
    if shutil.disk_usage(output.parent).free<FREE_FLOOR+64*1024**2:raise Invalid('remote input headroom')
    source = Path(source)
    all_rows = load(source/'plan.json')['packages']
    out = new_output(output)
    # Keep in step with SAMBA_PACKAGES in fixtures/foundation/test_remote_backup.py.
    names=('samba',)
    rows=[row for row in all_rows if row['name'] in names]
    if len(rows)!=len(names):raise Invalid('closed Samba package set unavailable')
    plan=out/'smb-plan.json';plan.write_text(json.dumps({'packages':rows},indent=2)+'\n')
    # A fresh independently reviewed keyring/lock may be supplied; never extend an old review.
    keyring = Path(keyring)
    trust = Path(trust)
    verified=verify_plan(plan,keyring,source/'packages',out/'verification',trust)
    audit=audit_packages(source/'packages',verified['packages']);(out/'audit.json').write_text(json.dumps(audit,indent=2)+'\n')
    approved=public_cache(out/'admission',keyring,source/'packages',verified['packages'])
    stage=out/'iso-stage';stage.mkdir()
    for path in (base_path.parent/'iso-stage').iterdir():
        if path.is_file() and path.name!='SHA256SUMS':shutil.copyfile(path,stage/path.name)
    for path in FIX.glob('*.py'):shutil.copyfile(path,stage/path.name)
    shutil.copyfile(plan,stage/plan.name);keys=stage/'smb-public-keys';keys.mkdir();packages=stage/'smb-packages';packages.mkdir()
    for name in ('pubring.gpg','trustdb.gpg'):shutil.copyfile(out/'admission/public'/name,keys/name)
    (keys/'gpg.conf').write_text(GPG_CONFIG)
    for row in rows:
        filename=row['url'].rsplit('/',1)[-1]
        for suffix in ('','.sig'):reuse_file(source/'packages'/(filename+suffix),packages/(filename+suffix))
    if script:
        if not (FIX/(script+'.py')).is_file():raise Invalid('payload-script module missing')
        (stage/'payload-script.json').write_text(json.dumps({'module':script})+'\n')
    (stage/'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.relative_to(stage)}\n' for p in sorted(stage.rglob('*')) if p.is_file()))
    args=iso_command(stage,out);args[-2]='/output/patch.iso';run_command(args,out,'remote-iso',120)
    if (out/'patch.iso').stat().st_size>48*1024**2:raise Invalid('remote ISO bound')
    for name in base['inputs']:
        if name!='patch.iso':reuse_file(base_path.parent/name,out/name)
    report=dict(base,payload_script=script or base.get('payload_script'),checked_at=datetime.now(timezone.utc).isoformat(),host_resource_policy=resources,smb_verification_sha256=digest(out/'verification/verification.json'),smb_approved_signers=approved,
                fixture_hashes={p.name:digest(p) for p in FIX.iterdir() if p.is_file()},
                inputs={name:{'bytes':(out/name).stat().st_size,'sha256':digest(out/name)} for name in base['inputs']})
    (out/'inputs.json').write_text(json.dumps(report,indent=2)+'\n');return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base-inputs',required=True);p.add_argument('--output',required=True)
    p.add_argument('--keyring', type=Path, required=True)
    p.add_argument('--trust-lock', type=Path, required=True)
    p.add_argument('--source', type=Path, required=True, help='verified Samba input folder with plan.json and packages/')
    p.add_argument('--script-module')
    a = p.parse_args()
    print(json.dumps(prepare(a.base_inputs, a.output, a.keyring, a.trust_lock,
                             a.script_module, source=a.source), indent=2))
