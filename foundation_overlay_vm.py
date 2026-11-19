#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded copy-on-write lab disks with an explicit, hash-bound read-only ancestry.

Unlike the older self-contained-image runner, this runner permits ONLY recorded
private parents at fixed sandbox names. No arbitrary backing paths or host devices.
"""
import argparse
from datetime import datetime,timezone
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from contract import Invalid,digest,load
from signed_bootstrap import FREE_FLOOR,new_output
from target_vm import sandbox,read_log,MAX_LOG
from foundation_vm import command,judge,backup_info,CASES,CUT_MARKERS
from encrypted_vm import ConsoleResponse
from foundation_inputs import BACKUP_PASSWORD
from update_vm import qmp_quit
from lab_resources import constrain_job

MIB=1024**2
ROOT_BUDGET={'payload-script':1024*MIB,'adopted-update':1024*MIB,'adopted-update-boot':384*MIB,'recovery-run-stage':1024*MIB,'recovery-run-boot':768*MIB,'recovery-run-finish':512*MIB,'calendar-firing':512*MIB,'calendar-persistent':384*MIB,'remote-rotation':640*MIB,'root-api-stage':1152*MIB,'root-api-finish':512*MIB,'coordinator-build-stage':768*MIB,'coordinator-stage':384*MIB,'coordinator-boot':256*MIB,'coordinator-finish':384*MIB,'fallback-retire-prepare':384*MIB,'fallback-retire-finish':384*MIB,'lifecycle63-api':1152*MIB,'root-retire-prepare':384*MIB,'root-retire-finish':384*MIB,'boot-retirement':384*MIB,'boot-retirement-review':384*MIB,'deferred-owed':384*MIB,'deferred-resume':1152*MIB,'backup-rotation':1152*MIB,'backup-rotation-cut':512*MIB,'backup-rotation-review':384*MIB,'backup-deferral-review':384*MIB,'backup-deferral':640*MIB,'maintenance-retry':384*MIB,'lifecycle-worker-cut-running':512*MIB,'lifecycle-worker-cut-completed':512*MIB,'lifecycle-worker-review':384*MIB,'lifecycle-api':512*MIB,'delivery-lifecycle':384*MIB,'delivery-lifecycle-review':384*MIB,'credential-review-controls':384*MIB,'credential-review-cut':384*MIB,'credential-review-resume':384*MIB,'recovery-workflow-lts':768*MIB,'recovery-workflow-cut-stage':768*MIB,'recovery-workflow-cut-publish':768*MIB,'recovery-workflow-review':384*MIB,'batch-hardening':768*MIB,'batch-remote':640*MIB,'workflow-prepare':512*MIB,'recovery-workflow':768*MIB,'recovery-api-cut-running':512*MIB,'recovery-api-cut-completed':512*MIB,'recovery-api-cut-review':384*MIB,'update-api-cut':2304*MIB,'update-api-cut-review':384*MIB,'backend-kill':512*MIB,'update-api':2304*MIB,'update-api-boot':384*MIB,'recovery-api':512*MIB,'backup-credentials':384*MIB,'backup-schedule':384*MIB,'flatpak-capture':640*MIB,'application-backup':1792*MIB,'selective-backup':384*MIB,'remote-backup':512*MIB,'backup-api-cut-running':640*MIB,'backup-api-cut-completed':640*MIB,'backup-api-review':384*MIB,'backup-api':640*MIB,'rebind-references':384*MIB,'recovery-retirement-context':384*MIB,'mapped-references':384*MIB,'backup-sources':384*MIB,'process-references':384*MIB,'backup-capture':512*MIB,'generation-pins':384*MIB,'backup-recapture':512*MIB,'backup-legacy-fidelity':1792*MIB,'core-build':2560*MIB,'clean-builder':2304*MIB,'backend-api':512*MIB,'backup-destination':384*MIB,'activation-prepare':512*MIB,'recovery-activation':512*MIB,'recovery-activation-lts':512*MIB,'recovery-activation-cut':512*MIB,'activation-boot':384*MIB,'staged-review-prepare':384*MIB,'recovery-staged-review':768*MIB,'staged-review-graph':384*MIB,'recovery-references':384*MIB,'publication-cut-kernel':384*MIB,'publication-cut-artifacts':384*MIB,'publication-cut-uefi':384*MIB,
             'publication-cut-bios':384*MIB,'publication-recover':384*MIB,'image-prepare':384*MIB,'recovery-image-confirm':128*MIB,'recovery-packaged-cut':384*MIB,'recovery-packaged-pending':256*MIB,'recovery-prepare':512*MIB,'recovery-packaged':768*MIB,'recovery-stage-boot':384*MIB,'root-references':512*MIB,'ownership-prepare':512*MIB,'ownership-update':1792*MIB,'ownership-cut':256*MIB,
             'updates':1792*MIB,'fault-pre':1792*MIB,'fault-post':1792*MIB,'fault-initrd':1280*MIB,
             'backups':512*MIB,'backup-create':512*MIB,'backup-fidelity':1792*MIB,'backup-retention':512*MIB,'backup-break':128*MIB,
             'defaults':256*MIB,'resources':512*MIB,'boot-observe':384*MIB,'boot-identity':256*MIB,'registry-prepare':512*MIB,'registry-boot':256*MIB,'rebind-update':1792*MIB,'rebind-cut':512*MIB,'rebind-replay':256*MIB,'probe-modules':256*MIB,'refresh':384*MIB,'full-esp':512*MIB,'boot-write':1792*MIB,
             'recovery-restic':2560*MIB,'recovery-snapper':256*MIB}


def pinned_file(path,expected,maximum):
    p=Path(path).resolve(strict=True)
    if p.stat().st_size>maximum or digest(Path(path))!=expected:raise Invalid('private image ancestry changed')
    return p


def lineage(previous):
    path=Path(previous).resolve(strict=True);r=load(path)
    if r['status']=='PASS-foundation-phase':rows=[]
    elif r['status']=='PASS-foundation-checkpoint':
        if r.get('case')!='checkpoint' or any(r.get(key) is not True for key in ('guest_visible_bytes_equal','source_files_unchanged','standalone')):
            raise Invalid('verified standalone checkpoint required')
        rows=[]
    elif r['status']=='PASS-foundation-overlay-phase':rows=list(r['parents'])
    # Offline direct-PID1 coordinator leaf (root_retirement_coordinator_vm.py).
    elif r['status']=='PASS-foundation-coordinator-phase' and r.get('case')=='root-retirement-coordinator':rows=list(r['parents'])
    else:raise Invalid('only successful recorded sources are admitted')
    if len(rows)>=12:raise Invalid('bounded ancestry depth exhausted; no implicit flattening')
    rows.append({'path':str(path.parent/'target.qcow2'),'sha256':r['disk_sha256'],'bytes':r['disk_bytes']})
    for i,row in enumerate(rows):
        p=pinned_file(row['path'],row['sha256'],3*1024**3)
        if p.stat().st_size!=row['bytes']:raise Invalid('parent byte count changed')
    return path,r,rows


def ancestry_bindings(rows):
    result=[]
    for i,row in enumerate(rows):result+=['--ro-bind',row['path'],f'/lineage/layer-{i}.qcow2']
    return result


def inspect(out,rows,include_leaf=True):
    names=[f'/lineage/layer-{i}.qcow2' for i in range(len(rows))]
    if include_leaf:names.append('/work/target.qcow2')
    reports=[]
    for i,name in enumerate(names):
        args=sandbox(out)+ancestry_bindings(rows)+['--','/usr/bin/prlimit','--cpu=10:10','--as=1073741824:1073741824','--','/usr/bin/qemu-img','info','-f','qcow2','--output=json',name]
        raw=subprocess.run(args,check=True,capture_output=True,timeout=15).stdout
        d=json.loads(raw)
        expected=None if i==0 else f'/lineage/layer-{i-1}.qcow2'
        if d.get('format')!='qcow2' or d.get('virtual-size')!=8*1024**3 or d.get('encrypted') or d.get('backing-filename')!=expected:
            raise Invalid('unrecognized backing chain: fixed names and geometry required')
        if expected and d.get('backing-filename-format')!='qcow2':raise Invalid('explicit qcow2 backing format required')
        reports.append(d)
    (out/'ancestry-info.json').write_text(json.dumps(reports,indent=2)+'\n')


def clone_file(source,destination):
    # Reflink MUST succeed. There is no unbudgeted full-copy fallback.
    with Path(source).open('rb') as src,Path(destination).open('xb') as dst:
        fcntl.ioctl(dst.fileno(),0x40049409,src.fileno())  # Linux FICLONE


def run(inputs_path,case,output,previous,mode='uefi',previous_inputs=None):
    if os.geteuid()==0 or case not in CASES or case=='setup' or mode not in ('uefi','bios'):raise Invalid('closed unprivileged derived case required')
    resources=constrain_job()
    inp=Path(inputs_path).resolve(strict=True);m=load(inp);ih=digest(inp)
    if m['status']!='PASS-foundation-inputs':raise Invalid('current reviewed inputs required')
    for n,v in m['inputs'].items():
        if n not in ('kernel','setup.img','recovery.img','payload.iso','patch.iso'):raise Invalid('unexpected input')
        pinned_file(inp.parent/n,v['sha256'],1024**3)
    prev,prior,parents=lineage(previous)
    if prior['inputs_manifest_sha256']!=ih:
        if previous_inputs is None:raise Invalid('changed inputs require an explicit prior manifest')
        old=load(Path(previous_inputs))
        if digest(Path(previous_inputs))!=prior['inputs_manifest_sha256']:raise Invalid('old input binding changed')
        for key in ('old_kernels','new_kernels','source_image_sha256'):
            if old[key]!=m[key]:raise Invalid('revision cannot silently change Arch cohort/source')
        if case!='refresh':
            if old['policy_sha256']!=m['policy_sha256']:raise Invalid('changed policy needs a real guest package refresh')
            for name in ('kernel','setup.img','recovery.img','payload.iso'):
                if old['inputs'][name]!=m['inputs'][name]:raise Invalid('only external test-script revisions may avoid refresh')
    root_budget=ROOT_BUDGET.get(case,256*MIB)
    bulk_backup=case in ('remote-rotation','lifecycle63-api','deferred-resume','backup-rotation','backup-rotation-cut','backup-rotation-review','backup-deferral','batch-hardening','batch-remote','backend-kill','flatpak-capture','application-backup','remote-backup','backup-api-cut-running','backup-api-cut-completed','backup-api','backups','backup-create','backup-recapture','backup-retention','backup-capture')
    backup_cap=2112*MIB if case in ('remote-rotation','lifecycle63-api','backup-rotation','backup-rotation-cut','backup-rotation-review','batch-remote','flatpak-capture','application-backup','remote-backup') or prior['backup_bytes']>1088*MIB else 1152*MIB if bulk_backup or prior['backup_bytes']>128*MIB else 128*MIB
    # For non-backup cases the repository is cloned but receives only filesystem/lock
    # metadata, not bulk backup writes. Reflink plus a separately bounded leaf keeps
    # the existing root's bytes out of the NEW-write admission budget.
    backup_reserve=backup_cap if bulk_backup else 128*MIB
    if shutil.disk_usage(Path(output).absolute().parent).free<FREE_FLOOR+root_budget+backup_reserve+64*MIB:
        raise Invalid('insufficient bounded overlay write headroom')
    out=new_output(output);process=None;started=time.monotonic()
    r={'status':'FAIL','case':case,'mode':mode,'parents':parents,'inputs_manifest_sha256':ih,'previous_result_sha256':digest(prev),
       'host_resource_policy':resources,'root_leaf_cap':root_budget,'backup_file_cap':backup_cap,'new_write_admission_bytes':root_budget+backup_reserve+64*MIB,
       'release_authorized':False,'secure_boot_qualified':False,'physical_power_loss_qualified':False,
       'host_networking':False,'guest_network_scope':'guest-only namespaces; no QEMU network interface',
       'storage_scope':'new private writable leaf; hash-bound read-only fixed-name parents; not a shipping image',
       'guest_ram_mib':2048,'vcpus':1}
    try:
        inspect(out,parents,False)
        create=sandbox(out)+ancestry_bindings(parents)+['--','/usr/bin/qemu-img','create','-f','qcow2','-F','qcow2','-b',f'/lineage/layer-{len(parents)-1}.qcow2','/work/target.qcow2']
        subprocess.run(create,check=True,stdout=subprocess.DEVNULL,timeout=15)
        bs=pinned_file(prev.parent/'backup.qcow2',prior['backup_sha256'],backup_cap)
        clone_file(bs,out/'backup.qcow2');backup_info(out);inspect(out,parents)
        if mode=='uefi':
            # A coordinator boot must see the firmware variables its staging phase wrote
            # (LoaderEntryOneShot); every other phase starts from fresh OVMF variables.
            carried=prev.parent/'vars.fd'
            if case in ('coordinator-boot','recovery-run-boot') and prior.get('mode')=='uefi' and carried.is_file() and not carried.is_symlink():shutil.copyfile(carried,out/'vars.fd')
            else:shutil.copyfile('/usr/share/edk2/x64/OVMF_VARS.4m.fd',out/'vars.fd')
            r['uefi_vars_source']='parent-phase' if case in ('coordinator-boot','recovery-run-boot') and prior.get('mode')=='uefi' and carried.is_file() else 'fresh-ovmf'
        args=command(out,inp.parent,case,mode,max(root_budget,backup_cap))
        args[args.index('--'):args.index('--')]=ancestry_bindings(parents)
        args=[a+',detect-zeroes=unmap' if a in ('if=none,id=backup,format=qcow2,file=/work/backup.qcow2,discard=unmap','if=none,id=target,format=qcow2,file=/work/target.qcow2,discard=unmap') else a for a in args]
        (out/'command.json').write_text(json.dumps(args,indent=2)+'\n')
        response=ConsoleResponse(case in ('recovery-run-boot','coordinator-boot','recovery-workflow','recovery-workflow-lts','recovery-workflow-cut-stage','recovery-workflow-cut-publish','recovery-workflow-review','recovery-retirement-context','recovery-activation','recovery-activation-lts','recovery-activation-cut','recovery-staged-review','recovery-image-confirm','recovery-restic','recovery-snapper','recovery-packaged','recovery-packaged-cut','recovery-packaged-pending'));backup_response=False;cut=False;failed_at=None
        with (out/'serial.log').open('wb') as log,(out/'stderr.log').open('wb') as err:
            process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=log,stderr=err,env={'PATH':'/usr/bin','LANG':'C.UTF-8'})
            deadline=time.monotonic()+(1850 if case=='refresh' else 4250 if case=='backup-rotation' else 3050);boot_deadline=time.monotonic()+700
            while process.poll() is None:
                if time.monotonic()>deadline or (out/'stderr.log').stat().st_size>MAX_LOG:raise Invalid('VM time/log limit')
                if shutil.disk_usage(out).free<FREE_FLOOR+32*MIB or (out/'target.qcow2').stat().st_size>=root_budget or (out/'backup.qcow2').stat().st_size>=backup_cap:
                    raise Invalid('VM free-space/leaf budget reached')
                text=read_log(out/'serial.log')
                if 'You are in emergency mode' in text:raise Invalid('guest emergency state')
                if 'ENZIMOS_FOUNDATION_FAILURE' in text:
                    failed_at=failed_at or time.monotonic()
                    if time.monotonic()-failed_at>300:raise Invalid('failed guest did not shut down')
                if case!='refresh':
                    if time.monotonic()>boot_deadline and 'ENZIMOS_FOUNDATION_CASE_START ' not in text and 'ENZIMOS_FOUNDATION_RECOVERY_RAM_STARTED' not in text and not (case=='recovery-run-boot' and 'ENZIMOS recovery passphrase:' in text):raise Invalid('boot progress budget')
                    v=response.next(text)
                    if v is not None:process.stdin.write(v);process.stdin.flush()
                    if case=='recovery-restic' and response.sent and not backup_response and 'ENZIMOS backup passphrase:' in text:
                        process.stdin.write(BACKUP_PASSWORD.encode()+b'\n');process.stdin.flush();backup_response=True
                if case in CUT_MARKERS and CUT_MARKERS[case] in {line.strip() for line in text.splitlines()} and not cut:
                    qmp=qmp_quit(out/'qmp.sock');(out/'qmp.json').write_text(json.dumps(qmp,indent=2)+'\n');cut=True
                time.sleep(0.25)
        text=read_log(out/'serial.log')
        if case in CUT_MARKERS:
            if not cut or not response.sent or process.returncode!=0 or 'reboot: Power down' in text:raise Invalid('not the requested controlled interruption')
            r['guest_result']={'case':case,'status':'PASS-controlled-cut','physical_power_loss':False}
        elif case=='recovery-run-boot':
            # The packaged recovery-run PID1 reports on the console and powers off.
            lines=[line for line in text.splitlines() if line.startswith('ENZIMOS_RECOVERY_RUN_RESULT=')]
            if process.returncode!=0 or len(lines)!=1 or not response.sent or 'reboot: Power down' not in text:raise Invalid('recovery run boot did not finish')
            r['guest_result']=json.loads(lines[0].split('=',1)[1])
            if r['guest_result'].get('status')!='PASS' or r['guest_result'].get('case')!='recovery-run-boot':raise Invalid('recovery run boot failed')
        elif case=='coordinator-boot':
            # The loader-started coordinator reports on the console and powers off.
            lines=[line for line in text.splitlines() if line.startswith('ENZIMOS_COORDINATOR_RESULT=')]
            if process.returncode!=0 or len(lines)!=1 or not response.sent or 'reboot: Power down' not in text:raise Invalid('coordinator boot did not finish')
            r['guest_result']=json.loads(lines[0].split('=',1)[1])
            if r['guest_result'].get('status')!='PASS' or r['guest_result'].get('case')!='root-retirement-coordinator-boot':raise Invalid('coordinator boot failed')
        else:r['guest_result']=judge(text,process.returncode,case,response.sent)
        if case=='recovery-restic' and not backup_response:raise Invalid('independent backup credential prompt missing')
        r.update(cut_requested=cut,backup_response_sent=backup_response)
        if case=='core-build':
            from core_artifacts import audit_exports
            r['core_artifacts']=audit_exports(text,inp.parent,out/'core-artifacts')
        for row in parents:pinned_file(row['path'],row['sha256'],3*1024**3)
        pinned_file(bs,prior['backup_sha256'],backup_cap)
        if digest(inp)!=ih:raise Invalid('inputs changed during execution')
        inspect(out,parents);backup_info(out)
        r.update(status='PASS-foundation-overlay-phase',checked_at=datetime.now(timezone.utc).isoformat(),disk_sha256=digest(out/'target.qcow2'),disk_bytes=(out/'target.qcow2').stat().st_size,
                 backup_sha256=digest(out/'backup.qcow2'),backup_bytes=(out/'backup.qcow2').stat().st_size,serial_sha256=digest(out/'serial.log'))
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
        r['elapsed_seconds']=round(time.monotonic()-started,3)
        (out/'result.json').write_text(json.dumps(r,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('inputs','previous','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--previous-inputs',type=Path);p.add_argument('--case',choices=CASES,required=True);p.add_argument('--mode',choices=('uefi','bios'),default='uefi');a=p.parse_args()
    try:print(json.dumps(run(a.inputs,a.case,a.output,a.previous,a.mode,a.previous_inputs),indent=2))
    except (Invalid,OSError,ValueError,KeyError,subprocess.SubprocessError) as exc:
        print(json.dumps({'status':'FAIL','error':str(exc)}),file=sys.stderr);raise SystemExit(2)
