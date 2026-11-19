#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fresh authenticated full core-build closure plus exact authored build inputs."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
from contract import Invalid, digest, load
from package_trust import verify_plan
from foundation_inputs import FIX
from foundation_catalogue import reuse_file
from prepare_target_lab import iso_command, public_cache, GPG_CONFIG
from build_initrd_lab import audit_packages, run_command
from lab_resources import constrain_job
from signed_bootstrap import FREE_FLOOR, new_output

def prepare(base_inputs, plan, packages, keyring, trust_lock, output, native_build, backend_build):
    if os.geteuid()==0:raise Invalid('unprivileged core input preparation required')
    resources=constrain_job(cpu_limit=8)
    base_inputs=Path(base_inputs).resolve(strict=True);base=load(base_inputs);directory=base_inputs.parent
    if base['status']!='PASS-foundation-inputs':raise Invalid('unexpired core inputs required')
    for name,row in base['inputs'].items():
        if digest(directory/name)!=row['sha256']:raise Invalid('base changed')
    if shutil.disk_usage(Path(output).absolute().parent).free<FREE_FLOOR+1024**3:raise Invalid('core ISO headroom')
    out=new_output(output);packages=Path(packages).resolve(strict=True)
    verification=verify_plan(plan,keyring,packages,out/'verification',trust_lock)
    audit=audit_packages(packages,verification['packages'])
    (out/'archive-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
    stage=out/'iso-stage';stage.mkdir()
    for path in (directory/'iso-stage').iterdir():
        if path.is_file() and path.name!='SHA256SUMS':shutil.copyfile(path,stage/path.name)
    for path in FIX.glob('*.py'):shutil.copyfile(path,stage/path.name)
    shutil.copyfile(plan,stage/'core-build-plan.json')
    approved=public_cache(out/'admission',Path(keyring).resolve(strict=True),packages,verification['packages'])
    keys=stage/'core-public-keys';keys.mkdir()
    for name in ('pubring.gpg','trustdb.gpg'):shutil.copyfile(out/'admission/public'/name,keys/name)
    (keys/'gpg.conf').write_text(GPG_CONFIG)
    archives=stage/'core-packages';archives.mkdir()
    for row in verification['packages']:
        name=row['url'].rsplit('/',1)[-1]
        for suffix in ('','.sig'):reuse_file(packages/(name+suffix),archives/(name+suffix))
    source_receipts={}
    for label,report_path in (('native',native_build),('backend',backend_build)):
        report_path=Path(report_path).resolve(strict=True);folder=report_path.parent
        report=load(report_path);target=stage/('core-source-'+label);target.mkdir()
        expected='enzimos-native-policy' if label=='native' else 'enzimos-system-backend'
        if report['package_name']!=expected:raise Invalid('wrong closed core package identity')
        for name in ('policy.tar','PKGBUILD','native-policy.install','LICENSE','makepkg.conf'):
            if digest(folder/name)!=report['build_inputs'][name]:raise Invalid('captured authored input changed')
            shutil.copyfile(folder/name,target/name)
        shutil.copyfile(folder/'build.json',target/'original-build.json')
        source_receipts[label]=digest(folder/'build.json')
    (stage/'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.relative_to(stage)}\n' for p in sorted(stage.rglob('*')) if p.is_file()))
    args=iso_command(stage,out)
    if args[-2]!='/output/payload.iso':raise Invalid('core ISO contract')
    args[-2]='/output/patch.iso';run_command(args,out,'patch-iso',180)
    if (out/'patch.iso').stat().st_size>768*1024**2:raise Invalid('core ISO bound')
    for name in base['inputs']:
        if name!='patch.iso':reuse_file(directory/name,out/name)
    report=dict(base)
    report.update(checked_at=datetime.now(timezone.utc).isoformat(),host_resource_policy=resources,
        core_build_plan_sha256=digest(Path(plan)),core_source_receipts=source_receipts,core_approved_signers=approved,
        core_verification_sha256=digest(out/'verification/verification.json'),
        fixture_hashes={p.name:digest(p) for p in FIX.iterdir() if p.is_file()},
        inputs={n:{'bytes':(out/n).stat().st_size,'sha256':digest(out/n)} for n in base['inputs']})
    (out/'inputs.json').write_text(json.dumps(report,indent=2)+'\n');return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('base-inputs','plan','packages','keyring','trust-lock','output','native-build','backend-build'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();print(json.dumps(prepare(a.base_inputs,a.plan,a.packages,a.keyring,a.trust_lock,a.output,a.native_build,a.backend_build),indent=2))
