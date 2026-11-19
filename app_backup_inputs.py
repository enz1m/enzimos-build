#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Plan/acquire/authenticate one dated headless Flatpak backup experiment closure."""
import argparse
import json
import os
from pathlib import Path
import shutil
from contract import Invalid,digest,load
from lab_resources import constrain_job
from signed_bootstrap import FREE_FLOOR,new_output
from headless_plan import FOUNDATION,resolve
from acquire_packages import acquire
from package_trust import verify_plan
from package_closure import check as closure
from build_initrd_lab import audit_packages
from foundation_catalogue import reuse_file


def prepare(output, *, baseline, toolroot, trust, reuse=()):
    if os.geteuid()==0:raise Invalid('unprivileged app backup inputs required')
    resources=constrain_job(cpu_limit=8);output=Path(output).absolute()
    if shutil.disk_usage(output.parent).free<FREE_FLOOR+2*1024**3:raise Invalid('app backup input admission')
    old = Path(baseline)
    toolroot = Path(toolroot)
    trust = Path(trust)
    caches = (old/'packages', *(Path(p) for p in reuse))
    seed = load(old/'seed.json')
    out = new_output(output)
    seed['purpose']='headless-app-backup-qualification-not-product-payload';seed['requested_packages']=sorted(FOUNDATION|{'flatpak'})
    (out/'seed.json').write_text(json.dumps(seed,indent=2)+'\n')
    # Existing read-only sanitized toolroot and exact dated database bytes only.
    plan=resolve(toolroot,out/'seed.json',old/'resolution/db/sync',out/'resolution')
    (out/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    cache=out/'packages';cache.mkdir();missing=[]
    for row in plan['packages']:
        name=row['url'].rsplit('/',1)[-1];found=None
        for folder in caches:
            p=folder/name
            if p.is_file() and (folder/(name+'.sig')).is_file() and p.stat().st_size==row['download_bytes_from_metadata'] and digest(p)==row['sha256_from_metadata']:found=folder;break
        if found is None:missing.append(row)
        else:
            for suffix in ('','.sig'):reuse_file(found/(name+suffix),cache/(name+suffix))
    # Flatpak's portal/AppStream closure includes graphics libraries even in a headless guest.
    if sum(row['download_bytes_from_metadata'] for row in missing)>128*1024**2 or len(missing)>100:raise Invalid('app backup acquisition exceeds reviewed closure increment')
    if missing:
        small=dict(plan,packages=missing);(out/'download-plan.json').write_text(json.dumps(small,indent=2)+'\n');acquire(out/'download-plan.json',out/'downloaded')
        for row in missing:
            name=row['url'].rsplit('/',1)[-1]
            for suffix in ('','.sig'):reuse_file(out/'downloaded'/(name+suffix),cache/(name+suffix))
    verified=verify_plan(out/'plan.json',toolroot/'usr/share/pacman/keyrings',cache,out/'verification',trust)
    audit=audit_packages(cache,verified['packages']);(out/'audit.json').write_text(json.dumps(audit,indent=2)+'\n')
    closure(toolroot,cache,out/'plan.json',out/'seed.json',out/'closure')
    baseline={row['name']:row for row in load(old/'resolution/resolution.json')['packages']}
    additional=[row for row in plan['packages'] if row['name'] not in baseline]
    if any(row['name'] in baseline and row!=baseline[row['name']] for row in plan['packages']):raise Invalid('application fixture cannot silently replace the baseline cohort')
    (out/'additional-plan.json').write_text(json.dumps(dict(plan,packages=additional),indent=2)+'\n')
    result={'status':'PASS-app-backup-authenticated-inputs','resources':resources,'package_count':len(plan['packages']),'additional':len(additional),
            'downloaded':len(missing),'downloaded_bytes':sum(row['download_bytes_from_metadata'] for row in missing),'verification_sha256':digest(out/'verification/verification.json'),'host_installed':False}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');return result


if __name__=='__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--baseline', type=Path, required=True, help='verified baseline seed, database, resolution and packages')
    p.add_argument('--toolroot', type=Path, required=True, help='read-only build tool root with public pacman keyrings')
    p.add_argument('--reuse', type=Path, action='append', default=[], help='additional archived package directory')
    p.add_argument('--trust-lock', type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(prepare(a.output, baseline=a.baseline, toolroot=a.toolroot,
                             reuse=a.reuse, trust=a.trust_lock), indent=2))
