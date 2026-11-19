#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Small reviewed fixture/package revisions over an unchanged authenticated base ISO.

Uses real mkinitcpio to add scripts/tools, Linux's concatenated-initramfs format,
and required reflinks. This is explicit lab-input composition, not OS immutability.
"""
import argparse
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from contract import Invalid,digest,load
from signed_bootstrap import FREE_FLOOR,new_output
from build_initrd_lab import builder_argv,run_command
from prepare_target_lab import iso_command
from foundation_inputs import FIX
from foundation_overlay_vm import clone_file
from lab_resources import constrain_job

TOOLS=['env','bash','lsinitcpio','bsdtar','bsdcpio','zstd','dd','od','awk','cut','grep','tr','rm','mktemp','head']


def patch(assembly,out,tools,kver,script,name):
    root=assembly/'root'
    overrides={
        'usr/lib/enzimos-lab/provision.sh':FIX/script,
        'usr/lib/enzimos-lab/foundation_recovery.py':FIX/'foundation_recovery.py',
        'usr/lib/enzimos-lab/foundation_test.py':FIX/'foundation_test.py',
        'usr/lib/enzimos-lab/test_recovery_stage.py':FIX/'test_recovery_stage.py',
        'usr/lib/enzimos-lab/test_staged_review.py':FIX/'test_staged_review.py',
        'usr/lib/enzimos-lab/test_recovery_activation.py':FIX/'test_recovery_activation.py',
        'usr/lib/enzimos-lab/test_retirement_context.py':FIX/'test_retirement_context.py',
        'usr/lib/enzimos-lab/test_recovery_workflow.py':FIX/'test_recovery_workflow.py',
        'usr/lib/enzimos-lab/test_mapped_references.py':FIX/'test_mapped_references.py',
        'usr/lib/systemd/system/enzimos-target-provision.service':FIX/'enzimos-target-provision.service',
        'usr/lib/systemd/system/enzimos-target-provision.target':FIX/'enzimos-target-provision.target',
        'etc/apparmor.d/enzimos-restic':tools/'etc/apparmor.d/enzimos-restic',
        'usr/lib/enzimos/recovery-pacman.conf':tools/'usr/lib/enzimos/recovery-pacman.conf',
        'usr/lib/enzimos/recovery-image.json':out/'recovery-identity.json',
    }
    for source in sorted([*(tools/'usr/lib/enzimos').glob('*.py'),*(tools/'usr/lib/enzimos').glob('*.conf')]):overrides['usr/lib/enzimos/'+source.name]=source
    noop=out/(name+'.hook');noop.write_text('build() { :; }\nhelp() { echo "Explicit lab patch files only"; }\n')
    overrides['usr/lib/initcpio/install/enzimos-foundation']=noop
    config=out/(name+'.conf')
    config.write_text('MODULES=()\nBINARIES=('+ ' '.join('/usr/bin/'+n for n in TOOLS)+' /usr/lib/libffi.so.8)\nFILES=(/usr/lib/initcpio/functions '+' '.join('/'+n for n in overrides)+')\nHOOKS=(enzimos-foundation)\nCOMPRESSION="zstd"\nCOMPRESSION_OPTIONS=(-T1)\n')
    overrides['etc/mkinitcpio-target-provision.conf']=config
    for dest in overrides:
        if dest.startswith('usr/lib/enzimos/') or dest in ('usr/lib/enzimos-lab/test_recovery_stage.py', 'usr/lib/enzimos-lab/test_staged_review.py', 'usr/lib/enzimos-lab/test_recovery_activation.py', 'usr/lib/enzimos-lab/test_recovery_workflow.py', 'usr/lib/enzimos-lab/test_retirement_context.py', 'usr/lib/enzimos-lab/test_mapped_references.py'):continue
        p=root/dest
        if not p.is_file() or p.is_symlink():raise Invalid('missing fixed assembly mountpoint')
    args=builder_argv(root,out,['/usr/bin/prlimit','--fsize=67108864:67108864','--core=0:0','--','/usr/bin/mkinitcpio','-k',kver,'-c','/etc/mkinitcpio-target-provision.conf','-g','/tmp/artifacts/'+name])
    args[args.index('--bind')]='--ro-bind';mounts=['--tmpfs','/usr/lib/enzimos','--tmpfs','/usr/lib/enzimos-lab']
    for dest,source in overrides.items():mounts+=['--ro-bind',str(source),'/' + dest]
    args[args.index('--'):args.index('--')]=mounts
    run_command(args,out,name,120)
    if (out/name).stat().st_size>32*1024**2:raise Invalid('patch size exceeded bound')


def append(base,patch_file,destination):
    clone_file(base,destination)
    with destination.open('ab') as dst,patch_file.open('rb') as src:
        dst.write(b'\0'*((-dst.tell())%4));shutil.copyfileobj(src,dst);dst.flush();os.fsync(dst.fileno())


def prepare(base_inputs,assembly,policy_build,output):
    if os.geteuid()==0:raise Invalid('unprivileged preparation required')
    resources=constrain_job(cpu_limit=8)
    base_inputs=Path(base_inputs).resolve(strict=True);base=load(base_inputs);assembly=Path(assembly).resolve(strict=True)
    if base['status']!='PASS-foundation-inputs' or 'patch.iso' in base['inputs']:raise Invalid('unexpired original foundation inputs required')
    for name,v in base['inputs'].items():
        if digest(base_inputs.parent/name)!=v['sha256']:raise Invalid('base input changed')
    # Two <=32 MiB patches and appended copies, <=48 MiB ISO, and bounded logs.
    # Large unchanged images/ISO MUST be reflinked/hardlinked, never silently copied.
    if shutil.disk_usage(Path(output).absolute().parent).free<FREE_FLOOR+224*1024**2:raise Invalid('patch preparation headroom')
    build=load(Path(policy_build));package=Path(build['package'])
    if digest(package)!=build['sha256']:raise Invalid('policy build changed')
    out=new_output(output);report={'status':'FAIL','release_authorized':False}
    try:
        tools=out/'tools';tools.mkdir()
        modules={name for name in build['sources'] if name.startswith('usr/lib/enzimos/') and name.endswith('.py')}
        if not {'usr/lib/enzimos/'+n for n in ('native.py','backup.py','maintenance.py')}<=modules or len(modules)>40 or any(len(Path(n).parts)!=4 for n in modules):raise Invalid('bounded flat policy module set required')
        # Every packaged policy .conf is part of the publisher's descriptor file set.
        confs={name for name in build['sources'] if name.startswith('usr/lib/enzimos/') and name.endswith('.conf') and len(Path(name).parts)==4}
        if 'usr/lib/enzimos/recovery-pacman.conf' not in confs or len(confs)>8:raise Invalid('bounded policy configuration set required')
        names=modules|confs|{'etc/apparmor.d/enzimos-restic'}
        with tarfile.open(package,'r|zst') as ar:
            for member in ar:
                if member.name in names:
                    if not member.isfile() or member.size>128*1024:raise Invalid('invalid authored policy member')
                    p=tools/member.name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(ar.extractfile(member).read())
                    # Preserve the packaged executable bit (the coordinator's rdinit entry).
                    os.chmod(p,0o755 if member.mode&0o111 else 0o644)
        for n in names:
            if digest(tools/n)!=build['sources'][n]:raise Invalid('policy source identity changed')
        built=load(assembly/'build.json');k=next(k for k in built['kernels'] if k['flavor']=='linux')
        if digest(assembly/'artifacts/linux.vmlinuz')!=base['inputs']['kernel']['sha256']:raise Invalid('base kernel mismatch')
        identity={'schema':1,'kernel_release':k['uname'],'kernel_sha256':base['inputs']['kernel']['sha256'],
                  'base_initrd_sha256':base['inputs']['recovery.img']['sha256'],
                  'policy_files':{Path(name).name:build['sources'][name] for name in sorted(names) if name.startswith('usr/lib/enzimos/')}}
        (out/'recovery-identity.json').write_text(json.dumps(identity,sort_keys=True)+'\n')
        patch(assembly,out,tools,k['uname'],'setup.sh','setup.patch')
        patch(assembly,out,tools,k['uname'],'recovery-entry.sh','recovery.patch')
        append(base_inputs.parent/'setup.img',out/'setup.patch',out/'setup.img')
        append(base_inputs.parent/'recovery.img',out/'recovery.patch',out/'recovery.img')
        stage=out/'iso-stage';stage.mkdir()
        for p in FIX.glob('*.py'):shutil.copyfile(p,stage/p.name)
        shutil.copyfile(FIX/'foundation-test.service',stage/'foundation-test.service')
        shutil.copyfile(package,stage/'native-policy.pkg.tar.zst')
        shutil.copyfile(out/'recovery.patch',stage/'recovery.patch')
        (stage/'recovery-image-manifest.json').write_text(json.dumps({'schema':1,'identity':identity,
            'files':{'kernel':base['inputs']['kernel'],'initrd.img':{'bytes':(out/'recovery.img').stat().st_size,'sha256':digest(out/'recovery.img')}}},sort_keys=True)+'\n')
        (stage/'recovery-base.sha256').write_text(base['inputs']['recovery.img']['sha256']+'\n')
        (stage/'recovery-composed.sha256').write_text(digest(out/'recovery.img')+'\n')
        (stage/'policy-manifest.json').write_text(json.dumps(build,indent=2)+'\n')
        (stage/'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.name}\n' for p in sorted(stage.iterdir())))
        args=iso_command(stage,out)
        # Preserve the base payload inode. The small second ISO has a distinct name.
        if args[-2]!='/output/payload.iso':raise Invalid('unexpected ISO output contract')
        args[-2]='/output/patch.iso'
        run_command(args,out,'patch-iso',60)
        for n in ('kernel','payload.iso'):os.link(base_inputs.parent/n,out/n)
        if (out/'patch.iso').stat().st_size>48*1024**2:raise Invalid('patch ISO exceeded bound')
        report=dict(base)
        report.update(status='PASS-foundation-inputs',host_resource_policy=resources,checked_at=datetime.now(timezone.utc).isoformat(),base_inputs_manifest_sha256=digest(base_inputs),base_inputs=str(base_inputs),policy_sha256=digest(package),
            inputs={n:{'bytes':(out/n).stat().st_size,'sha256':digest(out/n)} for n in ('kernel','setup.img','recovery.img','payload.iso','patch.iso')},
            fixture_hashes={p.name:digest(p) for p in FIX.iterdir() if p.is_file()},
            composition='unchanged authenticated Arch ISO; separately hashed patch ISO; concatenated real mkinitcpio cpio archives; no credentials in initrds')
        return report
    except BaseException as exc:report['failure']=str(exc);raise
    finally:(out/'inputs.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('base-inputs','assembly','policy-build','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args()
    try:print(json.dumps(prepare(a.base_inputs,a.assembly,a.policy_build,a.output),indent=2))
    except (Invalid,OSError,ValueError,KeyError,subprocess.SubprocessError) as exc:
        print(json.dumps({'status':'FAIL','error':str(exc)}),file=sys.stderr);raise SystemExit(2)
