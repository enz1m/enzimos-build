#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Revise only external guest test scripts, not installed policy or embedded recovery."""
import argparse
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from contract import Invalid,digest,load
from signed_bootstrap import FREE_FLOOR,new_output
from foundation_inputs import FIX
from prepare_target_lab import iso_command
from build_initrd_lab import run_command
from lab_resources import constrain_job


def prepare(base_path,output):
    if os.geteuid()==0:raise Invalid('unprivileged test-input revision required')
    resources=constrain_job()
    base_path=Path(base_path).resolve(strict=True);base=load(base_path);directory=base_path.parent
    if base['status']!='PASS-foundation-inputs' or 'patch.iso' not in base['inputs']:raise Invalid('unexpired patched base required')
    for n,v in base['inputs'].items():
        if digest(directory/n)!=v['sha256']:raise Invalid('base artifact changed')
    if any(digest(FIX/name)!=base['fixture_hashes'].get(name) for name in ('foundation_test.py','foundation-test.service','test_rebind.py','test_ownership.py')):
        raise Invalid('installed test entrypoint changed; an explicit fixture refresh is required')
    if shutil.disk_usage(Path(output).absolute().parent).free<FREE_FLOOR+64*1024**2:raise Invalid('test ISO headroom unavailable')
    out=new_output(output);stage=out/'iso-stage';stage.mkdir()
    for name in ('native-policy.pkg.tar.zst','recovery.patch','recovery-base.sha256','recovery-composed.sha256','policy-manifest.json','foundation-test.service'):
        os.link(directory/'iso-stage'/name,stage/name)
    for p in FIX.glob('*.py'):
        if p.is_symlink() or p.stat().st_size>128*1024:raise Invalid('test source budget/type')
        shutil.copyfile(p,stage/p.name)
    (stage/'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.name}\n' for p in sorted(stage.iterdir())))
    args=iso_command(stage,out)
    if args[-2]!='/output/payload.iso':raise Invalid('unexpected ISO output contract')
    args[-2]='/output/patch.iso';run_command(args,out,'patch-iso',60)
    if (out/'patch.iso').stat().st_size>48*1024**2:raise Invalid('test patch ISO budget')
    for n in base['inputs']:
        if n!='patch.iso':os.link(directory/n,out/n)
    report=dict(base)
    report.update(checked_at=datetime.now(timezone.utc).isoformat(),test_revision_of=digest(base_path),host_resource_policy=resources,
        payload_fixture_hashes={p.name:digest(p) for p in FIX.glob('*.py')},
        inputs={n:{'bytes':(out/n).stat().st_size,'sha256':digest(out/n)} for n in base['inputs']})
    (out/'inputs.json').write_text(json.dumps(report,indent=2)+'\n');return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--base-inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:print(json.dumps(prepare(a.base_inputs,a.output),indent=2))
    except (Invalid,OSError,ValueError,KeyError,subprocess.SubprocessError) as exc:
        print(json.dumps({'status':'FAIL','error':str(exc)}),file=sys.stderr);raise SystemExit(2)
