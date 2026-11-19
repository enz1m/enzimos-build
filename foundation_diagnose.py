#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only diagnosis of a recorded failed foundation overlay, not recovery qualification."""
import argparse
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import time
from contract import Invalid,digest,load
from signed_bootstrap import new_output,FREE_FLOOR
from foundation_inputs import FIX
from foundation_overlay_vm import ancestry_bindings,inspect,pinned_file,clone_file
from target_vm import sandbox,read_log,MAX_LOG
from encrypted_vm import ConsoleResponse
from lab_resources import constrain_job


def cpio_entry(name,data,ino):
    encoded=name.encode()+b'\0'
    fields=(ino,0o100644,0,0,1,1789516800,len(data),0,0,0,0,len(encoded),0)
    header=b'070701'+b''.join(f'{x:08x}'.encode() for x in fields)
    result=header+encoded;result+=b'\0'*((-len(result))%4)
    result+=data;result+=b'\0'*((-len(data))%4)
    return result


def diagnose(failed,assembly,policy_build,base_inputs,output):
    if os.geteuid()==0:raise Invalid('unprivileged diagnosis required')
    resources=constrain_job()
    failed=Path(failed).resolve(strict=True);old=load(failed);assembly=Path(assembly).resolve(strict=True)
    if old['status']!='FAIL' or old.get('case') not in ('updates','defaults','backup-create','backup-fidelity','backup-retention','ownership-prepare','ownership-update','ownership-boot','ownership-pending','publication-recover','activation-boot','recovery-api-cut-review','credential-review-resume') or 'parents' not in old:raise Invalid('only the recorded failed update-overlay shape is supported')
    leaf=failed.parent/'target.qcow2'
    if leaf.is_symlink() or leaf.stat().st_size>old['root_leaf_cap']:raise Invalid('unbounded failed leaf')
    rows=old['parents']+[{'path':str(leaf),'sha256':digest(leaf),'bytes':leaf.stat().st_size}]
    for row in rows:pinned_file(row['path'],row['sha256'],3*1024**3)
    if shutil.disk_usage(Path(output).absolute().parent).free<FREE_FLOOR+24*1024**2:raise Invalid('diagnostic log/overlay headroom unavailable')
    out=new_output(output);process=None;r={'status':'FAIL','source_failure_sha256':digest(failed),'host_resource_policy':resources,'read_only_sources':rows,'release_authorized':False,'recovery_qualified':False}
    try:
        inspect(out,rows,False)
        built=load(assembly/'build.json');kernel=next(k for k in built['kernels'] if k['flavor']=='linux')
        if digest(assembly/'artifacts/linux.vmlinuz')!=kernel['kernel_sha256']:raise Invalid('assembly kernel changed')
        p=load(Path(policy_build));package=Path(p['package'])
        if digest(package)!=p['sha256']:raise Invalid('policy package changed')
        tools=out/'tools';tools.mkdir()
        modules={name for name in p['sources'] if name.startswith('usr/lib/enzimos/') and name.endswith('.py')}
        if not {'usr/lib/enzimos/'+name for name in ('native.py','backup.py','maintenance.py')}<=modules or len(modules)>26 or any(len(Path(name).parts)!=4 for name in modules):raise Invalid('bounded flat diagnostic policy module set required')
        names=modules|{'etc/apparmor.d/enzimos-restic'}
        with tarfile.open(package,'r|zst') as archive:
            for member in archive:
                if member.name in names:
                    if not member.isfile() or member.size>128*1024:raise Invalid('unexpected policy member')
                    dest=tools/member.name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(archive.extractfile(member).read())
        base_inputs=Path(base_inputs).resolve(strict=True);base=load(base_inputs)
        original=base_inputs.parent/'recovery.img'
        if base['status']!='PASS-foundation-inputs' or digest(original)!=base['inputs']['recovery.img']['sha256']:raise Invalid('original self-contained recovery initrd changed')
        clone_file(original,out/'diagnostic.img')
        patches={name:(tools/name).read_bytes() for name in names}
        patches['usr/lib/enzimos-lab/foundation_recovery.py']=(FIX/'foundation_recovery.py').read_bytes()
        with (out/'diagnostic.img').open('ab') as image:
            image.write(b'\0'*((-image.tell())%4))
            for i,(name,data) in enumerate(sorted(patches.items())):image.write(cpio_entry(name,data,10000+i))
            image.write(cpio_entry('TRAILER!!!',b'',20000));image.flush();os.fsync(image.fileno())
        r['diagnostic_initrd']={'base_sha256':digest(original),'overlay_files':{n:__import__('hashlib').sha256(d).hexdigest() for n,d in patches.items()},'sha256':digest(out/'diagnostic.img'),'method':'required reflink plus bounded concatenated newc archive; no root filesystem extraction'}
        if (out/'diagnostic.img').stat().st_size>160*1024**2:raise Invalid('diagnostic initrd budget')
        args=sandbox(out)+ancestry_bindings(rows)+['--ro-bind',str(assembly/'artifacts/linux.vmlinuz'),'/inputs/kernel','--ro-bind',str(out/'diagnostic.img'),'/inputs/initrd',
            '--','/usr/bin/prlimit','--core=0:0','--cpu=600:600','--as=6442450944:6442450944','--','/usr/bin/qemu-system-x86_64',
            '-no-user-config','-nodefaults','-machine','q35','-accel','tcg,thread=single,tb-size=32','-cpu','max','-smp','1','-m','2048M','-nic','none','-display','none','-device','VGA','-monitor','none','-serial','stdio','-no-reboot',
            '-bios','/usr/share/qemu/bios-256k.bin','-drive',f'if=none,id=target,format=qcow2,readonly=on,file=/lineage/layer-{len(rows)-1}.qcow2',
            '-object','iothread,id=labio,thread-pool-min=0,thread-pool-max=1',
            '-device','virtio-blk-pci,drive=target,serial=enzimos-lab-target,iothread=labio','-fw_cfg','name=opt/enzimos/case,string=diagnose',
            '-kernel','/inputs/kernel','-initrd','/inputs/initrd','-append','console=ttyS0,115200 rd.systemd.unit=enzimos-target-provision.target systemd.log_color=no panic=5']
        (out/'command.json').write_text(json.dumps(args,indent=2)+'\n');response=ConsoleResponse(True)
        with (out/'serial.log').open('wb') as log,(out/'stderr.log').open('wb') as err:
            process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=log,stderr=err,env={'PATH':'/usr/bin','LANG':'C.UTF-8'})
            deadline=time.monotonic()+650
            while process.poll() is None:
                if time.monotonic()>deadline or (out/'stderr.log').stat().st_size>MAX_LOG or shutil.disk_usage(out).free<FREE_FLOOR:raise Invalid('diagnostic bounds reached')
                text=read_log(out/'serial.log');value=response.next(text)
                if value is not None:process.stdin.write(value);process.stdin.flush()
                time.sleep(0.25)
        text=read_log(out/'serial.log')
        lines=[line for line in text.splitlines() if line.startswith('ENZIMOS_FOUNDATION_RESULT=')]
        if process.returncode or len(lines)!=1 or not response.sent or 'reboot: Power down' not in text:raise Invalid('diagnostic did not complete')
        result=json.loads(lines[0].split('=',1)[1])
        if result['status']!='PASS' or result['case']!='diagnose':raise Invalid('read-only diagnostic failed')
        for row in rows:pinned_file(row['path'],row['sha256'],3*1024**3)
        r.update(status='PASS-readonly-foundation-diagnostic',guest_result=result,checked_at=datetime.now(timezone.utc).isoformat(),serial_sha256=digest(out/'serial.log'))
        return r
    except BaseException as exc:r['failure']=str(exc);raise
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
        if process is not None:
            r['process_returncode']=process.returncode
            try:process.stdin.close()
            except OSError:pass
        (out/'result.json').write_text(json.dumps(r,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('failed','assembly','policy-build','base-inputs','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args()
    try:print(json.dumps(diagnose(a.failed,a.assembly,a.policy_build,a.base_inputs,a.output),indent=2))
    except (Invalid,OSError,ValueError,KeyError,subprocess.SubprocessError) as exc:
        print(json.dumps({'status':'FAIL','error':str(exc)}),file=sys.stderr);raise SystemExit(2)
