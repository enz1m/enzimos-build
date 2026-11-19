#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only worker ledger cut after actual restic completion; no fault hook shipped."""
import json
import os
from pathlib import Path
import sys
import time
import native

CONTROL=Path('/var/lib/enzimos-control');IDENTIFIER='1'*32


def modules():
    sys.path.insert(0,'/usr/lib/enzimos-backend')
    import operation_jobs,backup_operation,generation_registry
    return operation_jobs,backup_operation,operation_jobs.OperationStore(CONTROL/'backend-operations',generation_registry.storage_guard)


def cut(check,boundary):
    check(boundary in ('running','completed'),'closed backup cut boundary')
    check(native.output(['pacman','-Q','enzimos-system-backend'])=='enzimos-system-backend 0.1.0-6','wrong worker candidate')
    native.run(['mount','/backup-repository'])
    jobs,adapter,store=modules();manager=jobs.Manager(store,{'backup-create':adapter.BackupOperation()})
    original=store.save
    import backup
    def snapshots():return sorted(row['id'] for row in backup.snapshots(backup.read_config()))
    native.atomic_json(CONTROL/'backup-api-cut.json',{'boundary':boundary,'boot_id':native.boot_id(),'inventory':native.output(['pacman','-Q']),
        'authority':native.authority_identity(),'before_snapshots':snapshots()})
    def save(record,previous):
        if record['state']=='completed':
            native.atomic_json(CONTROL/'backup-api-created.json',{'result':record['result'],'after_snapshots':snapshots()})
            if boundary=='completed':original(record,previous)
            os.sync();print('ENZIMOS_BACKUP_API_CUT_READY '+boundary,flush=True)
            while True:time.sleep(1)
        original(record,previous)
    store.save=save
    plan=manager.plan(IDENTIFIER,1000,'backup-create');manager.submit(IDENTIFIER,1000,plan['plan_sha256'])
    manager.worker.join(1400)
    raise AssertionError('backup worker cut not reached: '+str(store.status(IDENTIFIER,1000)['state']))


def review(check):
    native.run(['mount','/backup-repository']);jobs,adapter,store=modules()
    before=json.loads((CONTROL/'backup-api-cut.json').read_text());created=json.loads((CONTROL/'backup-api-created.json').read_text())
    check(native.boot_id()!=before['boot_id'],'later boot required')
    check(native.output(['pacman','-Q'])==before['inventory'] and native.authority_identity()==before['authority'],'worker cut changed packages/authority')
    import backup
    def snapshots():return sorted(row['id'] for row in backup.snapshots(backup.read_config()))
    check(snapshots()==created['after_snapshots'] and len(set(snapshots())-set(before['before_snapshots']))==1,'completed backup witness mismatch')
    original=store.status(IDENTIFIER,1000);check(original['state']==before['boundary'],'cut ledger state mismatch')
    manager=jobs.Manager(store,{'backup-create':adapter.BackupOperation()})
    status=manager.status(IDENTIFIER,1000)
    if before['boundary']=='running':
        check(status['state']=='uncertain','restarted running job not uncertain')
        try:manager.submit(IDENTIFIER,1000,status['plan_sha256'])
        except jobs.storage.JobFailure as exc:check(str(exc)=='job-transition-refused','wrong uncertain refusal')
        else:raise AssertionError('uncertain backup replayed')
    else:
        check(status['state']=='completed' and status['result']==created['result'],'completed worker receipt mismatch')
        check(manager.submit(IDENTIFIER,1000,status['plan_sha256'])==status,'completed worker not deduplicated')
    check(manager.worker is None and snapshots()==created['after_snapshots'],'review replayed backup')
    backup.restic(backup.read_config(),['check'])
    return {'boundary':before['boundary'],'later_boot':True,'one_actual_backup_before_cut':True,
            'uncertain_never_replayed':before['boundary']=='running','completed_deduplicated':before['boundary']=='completed',
            'repository_unchanged_and_checked':True,'packages_authority_preserved':True,'physical_power_loss':False}
