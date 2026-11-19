#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind audited clean guest core artifacts to their original source receipts."""
import argparse
import json
from pathlib import Path
import shutil
from contract import Invalid,digest,load
from core_artifacts import decode_export
from lab_resources import constrain_job
from signed_bootstrap import new_output,FREE_FLOOR


def export(first,second,inputs,output):
    resources=constrain_job(cpu_limit=8)
    first=Path(first).resolve(strict=True);second=Path(second).resolve(strict=True);inputs=Path(inputs).resolve(strict=True)
    a=load(first);b=load(second)
    for result in (a,b):
        if result['status']!='PASS-foundation-overlay-phase' or result['case']!='core-build' or result['inputs_manifest_sha256']!=digest(inputs):raise Invalid('qualified same-input core builds required')
    if a['core_artifacts']!=b['core_artifacts'] or a['previous_result_sha256']!=b['previous_result_sha256']:raise Invalid('independent guest outputs differ')
    if first==second:raise Invalid('distinct guest runs required')
    if shutil.disk_usage(Path(output).absolute().parent).free<FREE_FLOOR+4*1024**2:raise Invalid('core export headroom')
    out=new_output(output);reports={}
    for label in ('native','backend'):
        for path,result in ((first,a),(second,b)):
            file=path.parent/'core-artifacts'/(label+'.pkg.tar.zst')
            if digest(file)!=result['core_artifacts'][label]['sha256']:raise Invalid('clean artifact changed')
        source=inputs.parent/'iso-stage'/('core-source-'+label);report=load(source/'original-build.json')
        folder=out/label;folder.mkdir();file=folder/(label+'.pkg.tar.zst');shutil.copyfile(first.parent/'core-artifacts'/(label+'.pkg.tar.zst'),file)
        report.update(status='PASS-clean-guest-core-package-built',package=str(file),sha256=digest(file),payload_audit=a['core_artifacts'][label]['audit'],
            clean_arch_toolchain=True,cross_host_reproducibility=False,host_resource_policy=resources,
            toolchain_scope='fresh signature-checked Arch installation inside two disposable guests; normal makepkg dependency checks',
            makepkg_nodeps_scope='not used in these clean builds',source_receipt_sha256=digest(source/'original-build.json'),
            clean_guest_results=[digest(first),digest(second)])
        (folder/'build.json').write_text(json.dumps(report,indent=2)+'\n');reports[label]=report
    (out/'export.json').write_text(json.dumps({'status':'PASS-two-clean-guest-core-exports','inputs_sha256':digest(inputs),
        'guest_results':[digest(first),digest(second)],'packages':{key:value['sha256'] for key,value in reports.items()},
        'cross_host_reproducibility':False,'runtime_qualification_transferred':False},indent=2)+'\n')
    return reports


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('first','second','inputs','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();print(json.dumps(export(a.first,a.second,a.inputs,a.output),indent=2))
