#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare explicit verified data and self-contained guest tools for the unified lab."""
import argparse
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tarfile
from contract import Invalid,digest,load
from build_initrd_lab import builder_argv,run_command
from package_trust import verify_plan
from package_closure import check as closure_check
from prepare_target_lab import public_cache,GPG_CONFIG,iso_command
from update_inputs import SOURCE_HASH,kernel_names
from encrypted_inputs import PRIMARY
from signed_bootstrap import FREE_FLOOR,new_output
from lab_resources import constrain_job
FIX=Path(__file__).resolve().parent/'fixtures/foundation'
BACKUP_PASSWORD='ENZIMOS-PUBLIC-DISPOSABLE-BACKUP-ONLY'


def initrd(assembly,out,kver,script,name,policy):
    root=assembly/'root'
    overrides={
        'usr/lib/enzimos-lab/provision.sh':FIX/script,
        'etc/mkinitcpio-target-provision.conf':FIX/'mkinitcpio.conf',
        'usr/lib/systemd/system/enzimos-target-provision.service':FIX/'enzimos-target-provision.service',
        'usr/lib/systemd/system/enzimos-target-provision.target':FIX/'enzimos-target-provision.target',
        'usr/lib/initcpio/install/enzimos-foundation':FIX/'initcpio-hook',
        'usr/lib/enzimos-lab/foundation_recovery.py':FIX/'foundation_recovery.py',
        'usr/lib/enzimos-lab/foundation_test.py':FIX/'foundation_test.py',
    }
    for source in sorted((policy/'usr/lib/enzimos').glob('*.py')):
        overrides['usr/lib/enzimos/'+source.name]=source
    overrides['etc/apparmor.d/enzimos-restic']=policy/'etc/apparmor.d/enzimos-restic'
    overrides['usr/lib/enzimos/recovery-pacman.conf']=policy/'usr/lib/enzimos/recovery-pacman.conf'
    # Only add missing placeholders to this fresh private SANITIZED build root.
    # It is not deployable; source bytes are mounted read-only and independently hashed.
    for dest in overrides:
        if dest.startswith('usr/lib/enzimos/'):continue
        p=root/dest
        if not p.exists():p.parent.mkdir(parents=True,exist_ok=True);p.touch()
        if p.is_symlink() or not p.is_file():raise Invalid('unsafe assembly placeholder')
    args=builder_argv(root,out,['/usr/bin/mkinitcpio','-k',kver,'-c','/etc/mkinitcpio-target-provision.conf','-g','/tmp/artifacts/'+name])
    args[args.index('--bind')]='--ro-bind'
    mounts=['--tmpfs','/usr/lib/enzimos']
    for dest,src in overrides.items():mounts+=['--ro-bind',str(src),'/' + dest]
    args[args.index('--'):args.index('--')]=mounts
    run_command(args,out,name,180)


def prepare(old,new,assembly,policy_build,keyring,trust_lock,source_result,output):
    if os.geteuid()==0:raise Invalid('unprivileged preparation required')
    resources=constrain_job()
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR+2*1024**3:raise Invalid('preparation space floor')
    old=Path(old).resolve(strict=True);new=Path(new).resolve(strict=True);assembly=Path(assembly).resolve(strict=True)
    source_result=Path(source_result).resolve(strict=True);source=source_result.parent/'target.qcow2'
    if load(source_result).get('disk_sha256')!=SOURCE_HASH or digest(source)!=SOURCE_HASH:raise Invalid('pinned encrypted baseline required')
    for catalogue in (old,new):
        c=load(catalogue/'catalogue.json')
        if c['status']!='PASS-foundation-catalogue' or digest(catalogue/'resolution/resolution.json')!=c['plan_sha256']:raise Invalid('foundation catalogue changed')
    pbuild=load(policy_build);pkg=Path(pbuild['package'])
    if pbuild['status']!='PASS-unsigned-policy-package-built' or digest(pkg)!=pbuild['sha256']:raise Invalid('reviewed original policy build required')
    out=new_output(output);report={'status':'FAIL','release_authorized':False}
    try:
        verified=[]
        for label,directory in [('old',old),('new',new)]:
            verified.append(verify_plan(directory/'resolution/resolution.json',keyring,directory/'packages',out/('verify-'+label),trust_lock))
        if any(v['package_count']!=189 for v in verified):raise Invalid('fixed 189-package catalogue expected')
        closure_check(assembly/'root',new/'packages',new/'resolution/resolution.json',new/'seed.json',out/'closure')
        versions=[kernel_names(d/'packages',v['packages']) for d,v in zip((old,new),verified)]
        built=load(assembly/'build.json');k=next(k for k in built['kernels'] if k['flavor']=='linux')
        if k['uname']!=versions[0]['linux'] or digest(assembly/'artifacts/linux.vmlinuz')!=k['kernel_sha256']:raise Invalid('assembly kernel mismatch')
        policy=out/'policy-tools';policy.mkdir()
        modules={name for name in pbuild['sources'] if name.startswith('usr/lib/enzimos/') and name.endswith('.py')}
        if not {'usr/lib/enzimos/'+n for n in ('native.py','backup.py','maintenance.py')}<=modules or len(modules)>16 or any(len(Path(n).parts)!=4 for n in modules):raise Invalid('bounded flat policy module set required')
        wanted=modules|{'etc/apparmor.d/enzimos-restic','usr/lib/enzimos/recovery-pacman.conf'}
        with tarfile.open(pkg,'r|zst') as ar:
            for m in ar:
                if m.name in wanted:
                    if not m.isfile() or m.size>128*1024:raise Invalid('bad original policy member')
                    p=policy/m.name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(ar.extractfile(m).read())
        if any(not (policy/n).is_file() or digest(policy/n)!=pbuild['sources'][n] for n in wanted):raise Invalid('policy tool identity mismatch')
        shutil.copyfile(assembly/'artifacts/linux.vmlinuz',out/'kernel')
        initrd(assembly,out,k['uname'],'setup.sh','setup.img',policy)
        initrd(assembly,out,k['uname'],'recovery-entry.sh','recovery.img',policy)
        stage=out/'iso-stage';stage.mkdir();combined=stage/'packages';combined.mkdir()
        for directory,verification in zip((old,new),verified):
            for record in verification['packages']:
                name=record['url'].rsplit('/',1)[-1]
                for suffix in ('','.sig'):
                    p=combined/(name+suffix)
                    if not p.exists():os.link(directory/'packages'/(name+suffix),p)
        public_cache(out/'admission',Path(keyring).resolve(strict=True),combined,verified[0]['packages']+verified[1]['packages'])
        (stage/'public-keys').mkdir()
        for n in ('pubring.gpg','trustdb.gpg'):shutil.copyfile(out/'admission/public'/n,stage/'public-keys'/n)
        shutil.copyfile(out/'admission/approved.trust',stage/'public-keys/approved.trust')
        (stage/'public-keys/gpg.conf').write_text(GPG_CONFIG)
        shutil.copyfile(out/'closure/db/sync/verified.db.tar.gz',combined/'verified.db')
        for label,v in zip(('old','new'),verified):
            (stage/(label+'-packages.txt')).write_text(''.join(f"{r['name']} {r['version']}\n" for r in sorted(v['packages'],key=lambda p:p['name'])))
        (stage/'old-package-files.txt').write_text(''.join('/payload/packages/'+r['url'].rsplit('/',1)[-1]+'\n' for r in verified[0]['packages']))
        (stage/'kernels.env').write_text(f"OLD_REGULAR={versions[0]['linux']}\nOLD_LTS={versions[0]['linux-lts']}\nNEW_REGULAR={versions[1]['linux']}\nNEW_LTS={versions[1]['linux-lts']}\n")
        shutil.copyfile(pkg,stage/'native-policy.pkg.tar.zst')
        (stage/'policy-manifest.json').write_text(json.dumps(pbuild,indent=2)+'\n')
        for p in FIX.glob('*.py'):shutil.copyfile(p,stage/p.name)
        shutil.copyfile(FIX/'foundation-test.service',stage/'foundation-test.service')
        shutil.copyfile(out/'kernel',stage/'recovery.kernel');shutil.copyfile(out/'recovery.img',stage/'recovery.img')
        (stage/'fixture-primary').write_bytes(PRIMARY.encode())
        (stage/'fixture-backup-password').write_text(BACKUP_PASSWORD+'\n')
        (stage/'fixture-accounts').write_text('enzimos-admin:ENZIMOS-PUBLIC-LAB-ADMIN\nenzimos-user:ENZIMOS-PUBLIC-LAB-USER\n')
        conf='[options]\nArchitecture = x86_64\nCacheDir = /payload/packages\nLogFile = /var/log/pacman-foundation.log\nSigLevel = Required TrustedOnly DatabaseOptional\nLocalFileSigLevel = Required TrustedOnly\nCheckSpace\n'
        (stage/'pacman-install.conf').write_text(conf)
        (stage/'pacman-update.conf').write_text(conf+'[verified]\nServer = file:///payload/packages\n')
        (stage/'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.relative_to(stage)}\n' for p in sorted(stage.rglob('*')) if p.is_file()))
        run_command(iso_command(stage,out),out,'iso',100)
        report.update(status='PASS-foundation-inputs',host_resource_policy=resources,checked_at=datetime.now(timezone.utc).isoformat(),source_image=str(source),source_image_sha256=SOURCE_HASH,
                      review_before=load(Path(trust_lock))['review_before'],trust_lock_sha256=digest(Path(trust_lock)),old_kernels=versions[0],new_kernels=versions[1],policy_sha256=digest(pkg),
                      inputs={n:{'bytes':(out/n).stat().st_size,'sha256':digest(out/n)} for n in ('kernel','setup.img','recovery.img','payload.iso')},
                      fixture_hashes={p.name:digest(p) for p in FIX.iterdir() if p.is_file()},lab_credentials_only=True,hibernation='deferred-for-now')
        return report
    except BaseException as exc:
        report['failure']=str(exc);raise
    finally:(out/'inputs.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('old','new','assembly','policy-build','keyring','trust-lock','source-result','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3));resource.setrlimit(resource.RLIMIT_FSIZE,(1024**3,1024**3));resource.setrlimit(resource.RLIMIT_CPU,(600,600))
    try:print(json.dumps(prepare(a.old,a.new,a.assembly,a.policy_build,a.keyring,a.trust_lock,a.source_result,a.output),indent=2))
    except (Invalid,OSError,ValueError,KeyError,subprocess.SubprocessError) as exc:
        print(json.dumps({'status':'FAIL','error':str(exc)}),file=sys.stderr);raise SystemExit(2)
