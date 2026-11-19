#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit bounded private-VM runs for the integrated headless qualification."""
import argparse
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from contract import Invalid,digest,load
from signed_bootstrap import FREE_FLOOR,new_output
from target_vm import command as base_command,sandbox,disk_info,read_log,MAX_LOG
from encrypted_vm import ConsoleResponse
from update_inputs import SOURCE_HASH
from update_vm import qmp_quit
from lab_resources import constrain_job
ROOT_CAP=3*1024**3
SMALL_BACKUP_CAP=128*1024**2
FULL_BACKUP_CAP=2*1024**3+128*1024**2
CASES=('payload-script','adopted-update','adopted-update-boot','recovery-run-stage','recovery-run-boot','recovery-run-finish','calendar-firing','calendar-persistent','remote-rotation','root-api-stage','root-api-finish','coordinator-build-stage','coordinator-stage','coordinator-boot','coordinator-finish','fallback-retire-prepare','fallback-retire-finish','lifecycle63-api','root-retire-prepare','root-retire-finish','boot-retirement','boot-retirement-review','deferred-owed','deferred-resume','backup-rotation','backup-rotation-cut','backup-rotation-review','backup-deferral-review','backup-deferral','maintenance-retry','lifecycle-worker-cut-running','lifecycle-worker-cut-completed','lifecycle-worker-review','lifecycle-api','delivery-lifecycle','delivery-lifecycle-review','credential-review-controls','credential-review-cut','credential-review-resume','batch-hardening','batch-remote','workflow-prepare','recovery-workflow','recovery-workflow-lts','recovery-workflow-cut-stage','recovery-workflow-cut-publish','recovery-workflow-review','recovery-api-cut-running','recovery-api-cut-completed','recovery-api-cut-review','update-api-cut','update-api-cut-review','backend-kill','update-api','update-api-boot','recovery-api','backup-credentials','backup-schedule','flatpak-capture','application-backup','selective-backup','remote-backup','backup-api-cut-running','backup-api-cut-completed','backup-api-review','backup-api','journal-engine-prepare','journal-engine-cut-intent','journal-engine-cut-effect','journal-engine-review','rebind-references','retirement-context-prepare','recovery-retirement-context','mapped-references','backup-sources','process-references','backup-capture','generation-pins','backup-recapture','backup-legacy-fidelity','durable-cut-running','durable-cut-completed','durable-review','core-build','clean-builder','backend-api','backup-destination','activation-prepare','activation-boot','recovery-activation','recovery-activation-lts','recovery-activation-cut','staged-review-prepare','recovery-staged-review','staged-review-graph','recovery-references','publication-cut-kernel','publication-cut-artifacts','publication-cut-uefi','publication-cut-bios','publication-recover','image-prepare','recovery-image-confirm','setup','refresh','probe-modules','updates','boot-new','boot-usable','fault-pre','fault-post','fault-initrd','full-esp','boot-write','backups','backup-create','backup-fidelity','backup-retention','backup-break','defaults','resources','boot-observe','boot-identity','registry-prepare','registry-boot','rebind-update','rebind-cut','rebind-replay','rebind-select-old','rebind-boot','rebind-fallback-boot','ownership-prepare','ownership-update','ownership-boot','ownership-cut','ownership-pending','root-references','recovery-prepare','recovery-packaged','recovery-packaged-cut','recovery-packaged-pending','recovery-stage-boot','recovery-snapper','recovery-restic','boot-restored')
EXPECTED={'adopted-update':{'U5-adopted-update'},'adopted-update-boot':{'U5-adopted-update-boot'},'recovery-run-stage':{'R24-recovery-run-stage'},'recovery-run-finish':{'R24-recovery-run-finish'},'calendar-firing':{'S8-calendar-firing'},'calendar-persistent':{'S8-calendar-persistent'},'remote-rotation':{'R23-remote-rotation'},'root-api-stage':{'A10-root-api-stage'},'root-api-finish':{'A10-root-api-finish'},'coordinator-build-stage':{'R-coordinator-build-stage'},'coordinator-stage':{'R-coordinator-stage'},'coordinator-finish':{'R-coordinator-finish'},'fallback-retire-prepare':{'R-fallback-retire-prepare'},'fallback-retire-finish':{'R-fallback-retire-finish'},'lifecycle63-api':{'A9-lifecycle63'},'root-retire-prepare':{'R-root-retire-prepare'},'root-retire-finish':{'R-root-retire-finish'},'boot-retirement':{'R-boot-retirement'},'boot-retirement-review':{'R-boot-retirement-review'},'deferred-owed':{'R-deferred-owed'},'deferred-resume':{'R-deferred-resume'},'backup-rotation':{'R-backup-rotation'},'backup-rotation-review':{'R-backup-rotation-review'},'backup-deferral-review':{'R-backup-deferral-review'},'backup-deferral':{'R-backup-deferral'},'maintenance-retry':{'S7-maintenance-retry'},'lifecycle-worker-review':{'A8-lifecycle-review'},'lifecycle-api':{'A8-lifecycle'},'delivery-lifecycle':{'R22-delivery-lifecycle'},'delivery-lifecycle-review':{'R22-delivery-lifecycle'},'credential-review-controls':{'R21-credential-review'},'credential-review-resume':{'R21-credential-review'},'recovery-workflow-lts':{'B3-workflow'},'recovery-workflow-review':{'B3-workflow'},'batch-hardening':{'B3-batch'},'batch-remote':{'B3-remote'},'workflow-prepare':{'B3-prepare'},'recovery-workflow':{'B3-workflow'},'recovery-api-cut-review':{'A7-review'},'update-api-cut-review':{'A5-cut-review'},'backend-kill':{'A6-kill'},'update-api':{'A5-update'},'update-api-boot':{'A5-boot'},'recovery-api':{'A4-recovery'},'backup-credentials':{'R20-credentials'},'backup-schedule':{'R19-schedule'},'flatpak-capture':{'R18-flatpak-lock'},'application-backup':{'R17-appdata'},'selective-backup':{'R16-selective'},'remote-backup':{'R15-smb'},'backup-api-review':{'A3-review'},'backup-api':{'A3-backup'},'journal-engine-prepare':{'L11-prepare'},'journal-engine-review':{'L11-engine'},'rebind-references':{'L10-rebind-refs'},'retirement-context-prepare':{'L9-prepare'},'recovery-retirement-context':{'L9-exclusive'},'durable-review':{'A2-durable-review'},'core-build':{'B2-core-build'},'clean-builder':{'B1-clean-builder'},'backend-api':{'A1-backend'},'backup-destination':{'R12-destination'},'activation-prepare':{'R11-prepare'},'activation-boot':{'R11-boot'},'recovery-activation':{'R11-activation'},'recovery-activation-lts':{'R11-activation'},'staged-review-prepare':{'R10-prepare'},'recovery-staged-review':{'R10-review'},'staged-review-graph':{'R10-graph'},'recovery-references':{'R9-references'},'publication-recover':{'R8-recover'},'image-prepare':{'R7-publish'},'recovery-image-confirm':{'R7-confirm'},'recovery-packaged-pending':{'R6-pending'},'recovery-prepare':{'R6-prepare'},'recovery-packaged':{'R6-packaged-stage'},'recovery-stage-boot':{'R6-boot'},'root-references':{'L5-references'},'probe-modules':{'U1-view'},'updates':{'U1-U2-R1'},'boot-new':{'U2-boot'},'boot-usable':{'usable-boot'},'fault-pre':{'U3-pre'},'fault-post':{'U3-post'},
          'ownership-prepare':{'L4-birth'},'ownership-update':{'L4-update'},'ownership-boot':{'L4-boot'},'ownership-pending':{'L4-pending'},
          'defaults':{'S1','S2','S3','S4','S5','S6'},'resources':{'U2-resources'},'boot-observe':{'L1-observe'},'boot-identity':{'L1-boot'},'registry-prepare':{'L2-publisher-registry'},'registry-boot':{'L2-confirm-boot'},'rebind-update':{'L3-update'},'rebind-replay':{'L3-replay'},'rebind-select-old':{'L3-select-old'},'rebind-boot':{'L3-boot'},'rebind-fallback-boot':{'L3-boot'},'backup-create':{'R-fixture','R1-home','R2'},
          'mapped-references':{'L8-mappings'},'backup-sources':{'R14-sources'},'process-references':{'L7-process'},'backup-capture':{'R13-capture'},'generation-pins':{'L6-pins'},'backup-recapture':{'R2'},'backup-legacy-fidelity':{'R3'},'backup-fidelity':{'R3','R5-exclusions'},'backup-retention':{'R5-space-retention'},'backup-break':{'R4-broken-root'},
          'full-esp':{'U5-full-esp'},'boot-write':{'U5-write-repair'},'boot-restored':{'restored-boot'},
          'recovery-restic':{'R4-restic'},'recovery-snapper':{'U4-recovery'}}

CUT_MARKERS={'publication-cut-'+case:'ENZIMOS_PUBLICATION_CUT_READY '+boundary for case,boundary in
             (('kernel','artifact:kernel'),('artifacts','artifacts'),('uefi','uefi'),('bios','bios'))}
CUT_MARKERS.update({'backup-rotation-cut':'ENZIMOS_ROTATION_CUT_READY switch-2','lifecycle-worker-cut-running':'ENZIMOS_LIFECYCLE_API_CUT_READY running','lifecycle-worker-cut-completed':'ENZIMOS_LIFECYCLE_API_CUT_READY completed','credential-review-cut':'ENZIMOS_CREDENTIAL_CUT_READY key-added','recovery-workflow-cut-stage':'ENZIMOS_WORKFLOW_CUT_READY stage','recovery-workflow-cut-publish':'ENZIMOS_WORKFLOW_CUT_READY publish','recovery-api-cut-running':'ENZIMOS_RECOVERY_API_CUT_READY running','recovery-api-cut-completed':'ENZIMOS_RECOVERY_API_CUT_READY completed','update-api-cut':'ENZIMOS_UPDATE_API_CUT_READY linux-upgraded-service-frozen','backup-api-cut-running':'ENZIMOS_BACKUP_API_CUT_READY running','backup-api-cut-completed':'ENZIMOS_BACKUP_API_CUT_READY completed','journal-engine-cut-intent':'ENZIMOS_RETIREMENT_ENGINE_CUT_READY intent','journal-engine-cut-effect':'ENZIMOS_RETIREMENT_ENGINE_CUT_READY effect','durable-cut-running':'ENZIMOS_DURABLE_CUT_RUNNING','durable-cut-completed':'ENZIMOS_DURABLE_CUT_COMPLETED','recovery-activation-cut':'ENZIMOS_ACTIVATION_CUT_READY first-entry','recovery-packaged-cut':'ENZIMOS_RECOVERY_STAGE_CUT_READY root-recorded',
             'fault-initrd':'ENZIMOS_FOUNDATION_CUT_READY partial-initrd synced-process-group-stopped',
             'rebind-cut':'ENZIMOS_REBIND_CUT_READY synced-before-package-write',
             'ownership-cut':'ENZIMOS_BIRTH_CUT_READY root-recorded-before-publication'})


def command(out,inputs,case,mode,root_cap=ROOT_CAP):
    if case not in CASES or mode not in ('uefi','bios'):raise Invalid('unknown closed case/mode')
    args=base_command(out,'provision' if case in ('setup','refresh') else mode,inputs)
    # Rotation copies/re-encrypts and reads back every point on one throttled vCPU.
    cpu=1800 if case in ('setup','refresh') else 4200 if case=='backup-rotation' else 3000
    args=[f'--cpu={cpu}:{cpu}' if x.startswith('--cpu=') else f'--fsize={root_cap}:{root_cap}' if x.startswith('--fsize=') else str(inputs/'setup.img') if x==str(inputs/'provision.img') else x for x in args]
    args=[x+',discard=unmap' if x=='if=none,id=target,format=qcow2,file=/work/target.qcow2' else x for x in args]
    args.insert(args.index('/usr/bin/prlimit')+1,'--core=0:0')
    args+=['-object','iothread,id=labio,thread-pool-min=0,thread-pool-max=1']
    if case not in ('setup','refresh','recovery-workflow','recovery-workflow-lts','recovery-workflow-cut-stage','recovery-workflow-cut-publish','recovery-workflow-review','recovery-retirement-context','recovery-activation','recovery-activation-lts','recovery-activation-cut','activation-boot','recovery-staged-review','publication-recover','recovery-image-confirm','recovery-packaged','recovery-packaged-cut','recovery-packaged-pending','recovery-stage-boot','recovery-snapper','recovery-restic','boot-restored','boot-new','boot-usable','boot-identity','registry-boot','rebind-replay','rebind-select-old','rebind-boot','rebind-fallback-boot','ownership-boot','ownership-cut','ownership-pending'):
        args[args.index('--'):args.index('--')]=['--ro-bind',str(inputs/'payload.iso'),'/inputs/payload.iso']
        args+=['-drive','if=none,id=payload,format=raw,readonly=on,file=/inputs/payload.iso','-device','virtio-blk-pci,drive=payload,serial=enzimos-lab-payload']
    if (inputs/'patch.iso').is_file() and case not in ('recovery-workflow','recovery-workflow-lts','recovery-workflow-cut-stage','recovery-workflow-cut-publish','recovery-workflow-review','recovery-retirement-context','recovery-activation','recovery-activation-lts','recovery-activation-cut','activation-boot','recovery-staged-review','publication-recover','recovery-image-confirm','recovery-packaged','recovery-packaged-cut','recovery-packaged-pending','recovery-stage-boot','recovery-snapper','recovery-restic','boot-restored','boot-new','boot-usable','boot-identity','registry-boot','rebind-replay','rebind-select-old','rebind-boot','rebind-fallback-boot','ownership-boot','ownership-cut','ownership-pending'):
        args[args.index('--'):args.index('--')]=['--ro-bind',str(inputs/'patch.iso'),'/inputs/patch.iso']
        args+=['-drive','if=none,id=patch,format=raw,readonly=on,file=/inputs/patch.iso','-device','virtio-blk-pci,drive=patch,serial=enzimos-lab-patch']
    args+=['-drive','if=none,id=backup,format=qcow2,file=/work/backup.qcow2,discard=unmap','-device','virtio-blk-pci,drive=backup,serial=enzimos-lab-backup','-fw_cfg','name=opt/enzimos/case,string='+case,'-qmp','unix:/work/qmp.sock,server=on,wait=off']
    args=[x+',iothread=labio' if x.startswith('virtio-blk-pci,') else x for x in args]
    return args


def backup_info(out):
    raw=subprocess.run(sandbox(out)+['--','/usr/bin/qemu-img','info','-f','qcow2','--output=json','/work/backup.qcow2'],check=True,capture_output=True,timeout=15).stdout
    d=json.loads(raw)
    if d['format']!='qcow2' or d['virtual-size']!=2*1024**3 or d.get('backing-filename') or d.get('encrypted'):raise Invalid('unexpected backup image geometry/type')
    (out/'backup-info.json').write_bytes(raw)


def judge(text,code,case,response):
    if code!=0 or 'Kernel panic - not syncing' in text or 'ENZIMOS_FOUNDATION_FAILURE' in text:raise Invalid('foundation guest failed')
    if 'reboot: Power down' not in text:raise Invalid('guest poweroff not observed')
    if case in ('setup','refresh'):
        marker='expanded-packages signed-policy accounts storage' if case=='setup' else 'refreshed-fixture-only'
        if 'ENZIMOS_FOUNDATION_SETUP_PASS '+marker not in text:raise Invalid('setup completion absent')
        return {'status':'PASS-'+case}
    if not response:raise Invalid('ordinary console unlock missing')
    lines=[line.strip() for line in text.splitlines() if line.startswith('ENZIMOS_FOUNDATION_RESULT=')]
    if len(lines)!=1:raise Invalid('one exact guest result required')
    r=json.loads(lines[0].split('=',1)[1])
    if r.get('status')!='PASS' or r.get('case')!=case or not r.get('results'):raise Invalid('guest result mismatch')
    if case in EXPECTED and {v['case'] for v in r['results']}!=EXPECTED[case]:raise Invalid('incomplete case matrix subset')
    if any(v.get('status')!='PASS' for v in r['results']):raise Invalid('failed guest case')
    return r


def run(inputs_path,case,out,previous=None,mode='uefi',previous_inputs=None):
    if os.geteuid()==0 or case not in CASES or mode not in ('uefi','bios'):raise Invalid('unprivileged closed case required')
    if case in CUT_MARKERS:raise Invalid('controlled cuts require the explicit overlay runner')
    resources=constrain_job()
    inputs_path=Path(inputs_path).resolve(strict=True);inputs=inputs_path.parent;m=load(inputs_path);ih=digest(inputs_path)
    if m['status']!='PASS-foundation-inputs' or m['source_image_sha256']!=SOURCE_HASH:raise Invalid('fresh reviewed inputs required')
    for n,item in m['inputs'].items():
        p=inputs/n
        if n not in ('kernel','setup.img','recovery.img','payload.iso','patch.iso') or not 0<item['bytes']<=1024**3 or p.stat().st_size!=item['bytes'] or digest(p)!=item['sha256']:raise Invalid('input artifact changed')
    prior=None
    if previous is not None:
        previous=Path(previous).resolve(strict=True);prior=load(previous)
        if prior['status']!='PASS-foundation-phase':raise Invalid('successful source required')
        if case=='refresh':
            if previous_inputs is None:raise Invalid('refresh needs the prior immutable input manifest')
            old=load(Path(previous_inputs))
            if digest(Path(previous_inputs))!=prior['inputs_manifest_sha256'] or old['status']!='PASS-foundation-inputs':raise Invalid('prior input binding changed')
            for key in ('old_kernels','new_kernels','source_image_sha256'):
                if old[key]!=m[key]:raise Invalid('fixture refresh cannot change the Arch cohort/source identity')
        elif prior['inputs_manifest_sha256']!=ih:raise Invalid('same-input source required')
    if (case=='setup') != (prior is None):raise Invalid('setup alone starts at pinned baseline')
    rcap=2*1024**3 if case in ('setup','refresh','probe-modules','defaults','backups') and (not prior or prior.get('disk_bytes',ROOT_CAP)<2*1024**3-64*1024**2) else ROOT_CAP
    if case in ('updates','boot-new','fault-pre','fault-post','fault-initrd','full-esp','boot-write','recovery-snapper') and prior and prior.get('disk_bytes',ROOT_CAP)<5*1024**3//2-64*1024**2:
        rcap=5*1024**3//2
    bcap=FULL_BACKUP_CAP if case in ('backups','recovery-restic','boot-restored') or (prior and prior.get('backup_bytes',0)>SMALL_BACKUP_CAP) else SMALL_BACKUP_CAP
    if shutil.disk_usage(Path(out).absolute().parent).free<FREE_FLOOR+rcap+bcap+64*1024**2:raise Invalid('insufficient bounded copy/write headroom')
    out=new_output(out);process=None;started=time.monotonic()
    result={'status':'FAIL','case':case,'mode':('direct-kernel' if case in ('setup','refresh') else mode),'inputs_manifest_sha256':ih,'host_resource_policy':resources,'release_authorized':False,'ui_qualified':False,'secure_boot_qualified':False,'physical_power_loss_qualified':False,'host_networking':False,'guest_network_scope':'only internal namespaces and links; no QEMU NIC/backend','root_file_cap':rcap,'backup_file_cap':bcap,'guest_ram_mib':2048,'vcpus':1}
    try:
        source=previous.parent/'target.qcow2' if prior else Path(m['source_image'])
        expected=prior['disk_sha256'] if prior else SOURCE_HASH
        if source.stat().st_size>rcap or digest(source)!=expected:raise Invalid('source root changed')
        shutil.copyfile(source,out/'target.qcow2')
        if prior:
            bsource=previous.parent/'backup.qcow2'
            if bsource.stat().st_size>bcap or digest(bsource)!=prior['backup_sha256']:raise Invalid('source backup changed')
            shutil.copyfile(bsource,out/'backup.qcow2');result['previous_result_sha256']=digest(previous)
        else:subprocess.run(sandbox(out)+['--','/usr/bin/qemu-img','create','-f','qcow2','/work/backup.qcow2',str(2*1024**3)],check=True,stdout=subprocess.DEVNULL,timeout=15)
        disk_info(out);backup_info(out)
        if mode=='uefi':shutil.copyfile('/usr/share/edk2/x64/OVMF_VARS.4m.fd',out/'vars.fd')
        args=command(out,inputs,case,mode,rcap);(out/'command.json').write_text(json.dumps(args,indent=2)+'\n')
        response=ConsoleResponse(case in ('recovery-workflow','recovery-workflow-lts','recovery-workflow-cut-stage','recovery-workflow-cut-publish','recovery-workflow-review','recovery-retirement-context','recovery-activation','recovery-activation-lts','recovery-activation-cut','recovery-staged-review','recovery-image-confirm','recovery-restic','recovery-snapper','recovery-packaged','recovery-packaged-cut','recovery-packaged-pending'))
        with (out/'serial.log').open('wb') as serial,(out/'stderr.log').open('wb') as errors:
            process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=serial,stderr=errors,env={'PATH':'/usr/bin','LANG':'C.UTF-8'})
            deadline=time.monotonic()+(1850 if case in ('setup','refresh') else 3050)
            boot_deadline=time.monotonic()+700
            while process.poll() is None:
                if time.monotonic()>deadline or (out/'stderr.log').stat().st_size>MAX_LOG:raise Invalid('VM deadline/log bound')
                if shutil.disk_usage(out).free<FREE_FLOOR or (out/'target.qcow2').stat().st_size>rcap or (out/'backup.qcow2').stat().st_size>bcap:raise Invalid('VM space/file bound')
                text=read_log(out/'serial.log')
                if 'You are in emergency mode' in text or 'ENZIMOS_FOUNDATION_FAILURE' in text:raise Invalid('guest entered emergency/failure state')
                if case not in ('setup','refresh') and time.monotonic()>boot_deadline and 'ENZIMOS_FOUNDATION_CASE_START ' not in text:raise Invalid('no case start within boot budget')
                if case not in ('setup','refresh'):
                    value=response.next(text)
                    if value is not None:process.stdin.write(value);process.stdin.flush()
                time.sleep(0.25)
        text=read_log(out/'serial.log');guest=judge(text,process.returncode,case,response.sent)
        if digest(source)!=expected or digest(inputs_path)!=ih:raise Invalid('parent/input mutated')
        disk_info(out);backup_info(out)
        result.update(status='PASS-foundation-phase',guest_result=guest,checked_at=datetime.now(timezone.utc).isoformat(),disk_sha256=digest(out/'target.qcow2'),backup_sha256=digest(out/'backup.qcow2'),disk_bytes=(out/'target.qcow2').stat().st_size,backup_bytes=(out/'backup.qcow2').stat().st_size,serial_sha256=digest(out/'serial.log'))
        return result
    except BaseException as exc:
        result['failure']=str(exc);raise
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
        if process is not None:
            result['process_returncode']=process.returncode
            try:process.stdin.close()
            except OSError:pass
        result['elapsed_seconds']=round(time.monotonic()-started,3)
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inputs',type=Path,required=True);p.add_argument('--case',choices=CASES,required=True);p.add_argument('--mode',choices=('uefi','bios'),default='uefi');p.add_argument('--previous',type=Path);p.add_argument('--previous-inputs',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:print(json.dumps(run(a.inputs,a.case,a.output,a.previous,a.mode,a.previous_inputs),indent=2))
    except (Invalid,OSError,ValueError,KeyError,subprocess.SubprocessError) as exc:
        print(json.dumps({'status':'FAIL','error':str(exc)}),file=sys.stderr);raise SystemExit(2)
