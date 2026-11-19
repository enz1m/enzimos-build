#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only interruption of installed job-store writes; no production fault hook."""
import json
import os
from pathlib import Path
import sys
import time
import native

ID='c'*32
CONTROL=Path('/var/lib/enzimos-control')


def count():return native.output(['snapper','--no-dbus','-c','home','--csvout','list','--columns','number'])


def cut(check,boundary):
    check(boundary in ('running','completed'),'closed cut boundary')
    check(native.output(['pacman','-Q','enzimos-system-backend'])=='enzimos-system-backend 0.1.0-4','installed durable package required')
    sys.path.insert(0,'/usr/lib/enzimos-backend');import job_store
    store=job_store.live_store();original=store.save
    native.atomic_json(CONTROL/'durable-cut.json',{'boundary':boundary,'inventory':native.output(['pacman','-Q']),
        'authority':native.authority_identity(),'before_snapshots':count(),'boot_id':native.boot_id()})
    def save(record,previous):
        if record['state']=='completed' and boundary=='running':
            # Mutation has returned, but the durable record still says running.
            native.atomic_json(CONTROL/'durable-created.json',{'snapshot':record['snapshot'],'after_snapshots':count()})
            os.sync();print('ENZIMOS_DURABLE_CUT_RUNNING',flush=True)
            while True:time.sleep(1)
        original(record,previous)
        if record['state']=='completed' and boundary=='completed':
            native.atomic_json(CONTROL/'durable-created.json',{'snapshot':record['snapshot'],'after_snapshots':count()})
            os.sync();print('ENZIMOS_DURABLE_CUT_COMPLETED',flush=True)
            while True:time.sleep(1)
    store.save=save
    import backup
    store.submit(ID,1000,lambda:backup.history(False))
    raise AssertionError('expected controller cut')


def review(check):
    sys.path.insert(0,'/usr/lib/enzimos-backend');import job_store
    before=json.loads((CONTROL/'durable-cut.json').read_text());created=json.loads((CONTROL/'durable-created.json').read_text())
    check(native.boot_id()!=before['boot_id'],'later actual boot required')
    check(native.output(['pacman','-Q'])==before['inventory'] and native.authority_identity()==before['authority'],'cut changed inventory/authority')
    check(count()==created['after_snapshots'] and count()!=before['before_snapshots'],'mutation witness mismatch')
    path=CONTROL/'backend-jobs'/(ID+'.json');original=path.read_bytes();store=job_store.live_store()
    record=store.status(ID,1000)
    def forbidden():raise AssertionError('interrupted operation replayed')
    if before['boundary']=='running':
        check(record['state']=='running','running cut state mismatch')
        try:store.submit(ID,1000,forbidden)
        except job_store.JobFailure as exc:check(str(exc)=='job-result-uncertain-no-replay','wrong interruption refusal')
        else:raise AssertionError('uncertain record accepted')
    else:
        result=store.submit(ID,1000,forbidden)
        check(result['state']=='completed' and result['snapshot']==created['snapshot'],'completed reply replay mismatch')
    check(path.read_bytes()==original and count()==created['after_snapshots'],'review/retry mutated store/history')
    return {'boundary':before['boundary'],'later_boot':True,'created_snapshot':created['snapshot'],
            'no_mutation_replay':True,'ledger_inventory_authority_preserved':True,
            'physical_power_loss_qualified':False}
