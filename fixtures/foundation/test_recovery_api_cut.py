#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Internal worker cuts around real recovery-plan creation, not wire auth tests."""
import json
import os
from pathlib import Path
import sys
import subprocess
import time
import native

CONTROL=Path('/var/lib/enzimos-control');ID='7'*32;NATIVE_ID='api-'+ID


def modules():
    sys.path.insert(0,'/usr/lib/enzimos-backend')
    import operation_jobs,recovery_operation,generation_registry,recovery_stage
    return operation_jobs,recovery_operation,recovery_stage,operation_jobs.OperationStore(CONTROL/'backend-operations',generation_registry.storage_guard)


def boot_files():
    return {str(path):native.sha(path) for folder in ('/boot/loader/entries','/boot/limine') for path in Path(folder).iterdir() if path.is_file()}


def cut(check,payload,boundary):
    check(boundary in ('running','completed'),'closed recovery cut boundary')
    from test_recovery_api import install_backend,UNIT
    install_backend(check,payload);native.run(['systemctl','stop',UNIT])
    # Preserve the guest's real history pause control across the deliberate cut.
    # Cleanup must also stay masked across reboot; restore it after review. This
    # isolates scheduled writers, not the production recovery guards.
    pause=CONTROL/'home-history.disabled';check(not pause.exists(),'history already paused')
    units=('snapper-cleanup.timer','snapper-cleanup.service')
    states={unit:native.output(['systemctl','is-enabled',unit]) for unit in units}
    check(states=={'snapper-cleanup.timer':'enabled','snapper-cleanup.service':'static'},'unexpected cleanup unit setup')
    pause.touch(mode=0o600);native.run(['systemctl','stop','enzimos-home-history.service'])
    native.run(['systemctl','mask','--now',*units])
    jobs,adapter,stage,store=modules();manager=jobs.Manager(store,{'recovery-prepare':adapter.RecoveryOperation()})
    before={'schedule_states':states,'boundary':boundary,'boot_id':native.boot_id(),'inventory':native.output(['pacman','-Q']),
            'authority':native.authority_identity(),'roots':stage.subvolumes('/'),'boot':boot_files()}
    check(not stage.read_jobs(stage.jobs_directory()),'fresh recovery worker branch required')
    native.atomic_json(CONTROL/'recovery-api-cut.json',before)
    original=store.save
    def save(record,previous):
        if record['state']=='completed':
            native_jobs=stage.read_jobs(stage.jobs_directory())
            check(set(native_jobs)=={NATIVE_ID} and native_jobs[NATIVE_ID]['phase']=='planned','one durable native plan required before cut')
            check(stage.subvolumes('/')==before['roots'] and boot_files()==before['boot'],'recovery worker altered root/boot')
            native.atomic_json(CONTROL/'recovery-api-cut-created.json',{'result':record['result'],'native_job_sha256':native.sha(stage.jobs_directory()/(NATIVE_ID+'.json'))})
            if boundary=='completed':original(record,previous)
            os.sync();print('ENZIMOS_RECOVERY_API_CUT_READY '+boundary,flush=True)
            while True:time.sleep(1)
        original(record,previous)
    store.save=save
    planned=manager.plan(ID,1000,'recovery-prepare',{'birth':'fdn-success','generation':'old-fdn-success'})
    manager.submit(ID,1000,planned['plan_sha256']);manager.worker.join(180)
    raise AssertionError('recovery worker cut not reached: '+str(store.status(ID,1000)['state']))


def review(check):
    jobs,adapter,stage,store=modules();before=json.loads((CONTROL/'recovery-api-cut.json').read_text())
    created=json.loads((CONTROL/'recovery-api-cut-created.json').read_text())
    pause=CONTROL/'home-history.disabled';check(pause.is_file() and not pause.is_symlink(),'history pause not preserved')
    for unit in before['schedule_states']:
        observed=subprocess.run(['systemctl','is-enabled',unit],capture_output=True,text=True)
        check(observed.returncode==1 and observed.stdout.strip()=='masked','cleanup mask not preserved')
    check(native.boot_id()!=before['boot_id'],'later recovery worker review boot required')
    check(native.output(['pacman','-Q'])==before['inventory'] and native.authority_identity()==before['authority'],'worker cut changed packages/authority')
    check(stage.subvolumes('/')==before['roots'] and boot_files()==before['boot'],'worker cut changed subvolumes/boot')
    native_jobs=stage.read_jobs(stage.jobs_directory());path=stage.jobs_directory()/(NATIVE_ID+'.json')
    check(set(native_jobs)=={NATIVE_ID} and native_jobs[NATIVE_ID]['phase']=='planned' and native.sha(path)==created['native_job_sha256'],'durable native recovery plan changed')
    check(store.status(ID,1000)['state']==before['boundary'],'recovery cut ledger phase mismatch')
    manager=jobs.Manager(store,{'recovery-prepare':adapter.RecoveryOperation()});status=manager.status(ID,1000)
    if before['boundary']=='running':
        check(status['state']=='uncertain','interrupted recovery worker not uncertain')
        try:manager.submit(ID,1000,status['plan_sha256'])
        except jobs.storage.JobFailure as exc:check(str(exc)=='job-transition-refused','wrong recovery replay refusal')
        else:raise AssertionError('uncertain recovery worker replayed')
    else:
        check(status['state']=='completed' and status['result']==created['result'],'completed recovery receipt mismatch')
        check(manager.submit(ID,1000,status['plan_sha256'])==status,'completed recovery worker not deduplicated')
    try:native.assert_transition_idle()
    except native.Failure as exc:check('recovery staging requires explicit review' in str(exc),'wrong native pending-plan refusal')
    else:raise AssertionError('orphan/completed native recovery plan lost protection')
    check(manager.worker is None and native.sha(path)==created['native_job_sha256'],'review replayed or altered native plan')
    check(native.output(['pacman','-Q'])==before['inventory'] and native.authority_identity()==before['authority'] and stage.subvolumes('/')==before['roots'] and boot_files()==before['boot'],'review mutated protected state')
    native.run(['systemctl','unmask',*before['schedule_states']]);native.run(['systemctl','start','snapper-cleanup.timer'])
    check({unit:native.output(['systemctl','is-enabled',unit]) for unit in before['schedule_states']}==before['schedule_states'],'cleanup settings not restored')
    pause.unlink()
    return {'fixture_schedule_restored':True,'boundary':before['boundary'],'later_boot':True,'one_native_planned_job_preserved':True,
            'uncertain_never_replayed':before['boundary']=='running','completed_deduplicated':before['boundary']=='completed',
            'native_plan_blocks_conflicts':True,'subvolumes_boot_packages_authority_preserved':True,
            'wire_authorization_tested':False,'online_restore_or_activation':False,'physical_power_loss':False}
