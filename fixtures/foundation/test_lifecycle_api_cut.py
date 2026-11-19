#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Internal credential-completion worker cuts; separate from real wire authorization."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import native
import backup
import backup_credentials as c
from test_credential_review import material,pause_history,restore_history,PAUSE,UNITS

CONTROL=Path('/var/lib/enzimos-control');ID='c'*32;ENROLLMENT='worker-interrupted'


def modules():
    sys.path.insert(0,'/usr/lib/enzimos-backend')
    import operation_jobs as jobs
    import lifecycle_operation as adapter
    return jobs,adapter,jobs.OperationStore(CONTROL/'backend-operations',c.registry.storage_guard)


def cut(check,payload,boundary):
    check(boundary in ('running','completed'),'closed lifecycle cut boundary')
    from test_lifecycle_api import install_backend,UNIT
    install_backend(check,payload);native.run(['systemctl','stop',UNIT])
    native.run(['mount','/backup-repository']);config=backup.read_config();schedule=pause_history(check)
    c.NEXT.write_text('ENZIMOS-PUBLIC-LAB-WORKER-RECEIPT-PASSWORD\n');c.NEXT.chmod(0o600)
    save_native=c.registry.save_document
    def interrupt_receipt(path,value):
        if value.get('id')==ENROLLMENT and value.get('phase')=='complete':raise OSError('LAB pending credential receipt')
        return save_native(path,value)
    c.registry.save_document=interrupt_receipt
    try:
        try:c.enroll(ENROLLMENT)
        except OSError as exc:check(str(exc)=='LAB pending credential receipt','wrong pending receipt failure')
        else:raise AssertionError('pending credential receipt not created')
    finally:c.registry.save_document=save_native
    review=c.review(ENROLLMENT);pending=c.records(c.folder())[ENROLLMENT]
    jobs,adapter,store=modules();manager=jobs.Manager(store,{'credential-complete':adapter.LifecycleOperation('credential-complete')})
    before={'boundary':boundary,'boot_id':native.boot_id(),'schedule':schedule,'material':material(config),'pending':pending}
    native.atomic_json(CONTROL/'lifecycle-api-cut.json',before)
    save=store.save
    def cut_save(record,previous):
        if record['state']=='completed':
            value=c.records(c.folder())[ENROLLMENT]
            check(value==dict(pending,phase='complete',new_key=review['new_key']),'native receipt not completed before cut')
            check(material(config)==before['material'],'native completion changed protected material')
            native.atomic_json(CONTROL/'lifecycle-api-cut-created.json',{'result':record['result'],'native_sha256':native.sha(c.folder()/(ENROLLMENT+'.json'))})
            if boundary=='completed':save(record,previous)
            os.sync();print('ENZIMOS_LIFECYCLE_API_CUT_READY '+boundary,flush=True)
            while True:time.sleep(1)
        save(record,previous)
    store.save=cut_save
    plan=manager.plan(ID,1000,'credential-complete',{'id':ENROLLMENT,'review_sha256':review['review_sha256']})
    manager.submit(ID,1000,plan['plan_sha256']);manager.worker.join(240)
    raise AssertionError('lifecycle cut not reached: '+str(store.status(ID,1000)['state']))


def review(check):
    native.run(['mount','/backup-repository']);config=backup.read_config();jobs,adapter,store=modules()
    before=json.loads((CONTROL/'lifecycle-api-cut.json').read_text());created=json.loads((CONTROL/'lifecycle-api-cut-created.json').read_text())
    check(native.boot_id()!=before['boot_id'],'later lifecycle worker review boot required')
    check(PAUSE.is_file() and not PAUSE.is_symlink(),'history pause lost across cut')
    for unit in UNITS:
        result=subprocess.run(['systemctl','is-enabled',unit],capture_output=True,text=True)
        check(result.stdout.strip()=='masked','history mask lost across cut')
    path=c.folder()/(ENROLLMENT+'.json');check(native.sha(path)==created['native_sha256'],'native completion changed across cut')
    check(material(config)==before['material'],'worker cut changed protected material')
    check(store.status(ID,1000)['state']==before['boundary'],'wrong worker cut state')
    manager=jobs.Manager(store,{'credential-complete':adapter.LifecycleOperation('credential-complete')});status=manager.status(ID,1000)
    if before['boundary']=='running':
        check(status['state']=='uncertain','running lifecycle job not uncertain')
        try:manager.submit(ID,1000,status['plan_sha256'])
        except jobs.storage.JobFailure as exc:check(str(exc)=='job-transition-refused','wrong lifecycle replay refusal')
        else:raise AssertionError('uncertain lifecycle job replayed')
    else:
        check(status['state']=='completed' and status['result']==created['result'],'completed lifecycle result changed')
        check(manager.submit(ID,1000,status['plan_sha256'])==status,'completed lifecycle job not deduplicated')
    try:c.complete(ENROLLMENT,created['result']['review_sha256'])
    except native.Failure as exc:check('already complete' in str(exc),'wrong native completion retry refusal')
    else:raise AssertionError('native receipt completion replayed')
    check(manager.worker is None and native.sha(path)==created['native_sha256'] and material(config)==before['material'],'review changed native completion/material')
    restore_history(check,before['schedule'])
    return {'boundary':before['boundary'],'later_boot':True,'native_receipt_preserved':True,'native_retry_refused':True,
            'uncertain_never_replayed':before['boundary']=='running','completed_deduplicated':before['boundary']=='completed',
            'keys_points_packages_password_authority_preserved':True,'fixture_schedule_restored':True,'wire_authorization_tested':False,'physical_power_loss':False}
