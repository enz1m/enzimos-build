#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Orphan publisher-born fallback root retirement: online plan/prepare, then (after
the offline coordinator phase) online finish with birth tombstone."""
import json
import os
from pathlib import Path
import subprocess
import time
import native
import generation_registry as registry
import root_ownership as birth
import root_retirement as retirement
from test_credential_review import pause_history,restore_history

import lab_versions
VERSION=lab_versions.native()
PROBE='fdn-owned-probe'
STATE=Path('/var/lib/enzimos-control/root-retirement-fixture.json')


def refused(check,expected,callable_):
    try:callable_()
    except (native.Failure,OSError) as exc:check(expected in str(exc),'wrong refusal: '+str(exc));return
    raise AssertionError('not refused: '+expected)


def births():
    c,folder=birth.private_directory();return birth.read_records(c,folder)


def inventory():
    return birth.parse_inventory(registry.bounded_query(['btrfs','subvolume','list','-a','-u','-q','/']))


def quiet_maintenance(check):
    # Scheduled trim/scrub share the operation lock; stop their timers for this boot
    # and let an already running pass finish (never steal the lock).
    for unit in ('enzimos-trim.service','enzimos-scrub.service'):
        subprocess.run(['systemctl','stop',unit.replace('.service','.timer')],capture_output=True,timeout=30)
        deadline=time.monotonic()+300
        while native.output(['systemctl','show','--value','--property=ActiveState',unit]) in ('active','activating','deactivating'):
            check(time.monotonic()<deadline,unit+' did not finish');time.sleep(1)


def prepare(check):
    history=pause_history(check);quiet_maintenance(check)
    records=births();check(PROBE in records and records[PROBE]['phase']=='ready','orphan probe birth missing')
    record=records[PROBE];root=record['root']['uuid']
    for user in ('enzimos-user','enzimos-admin'):
        result=subprocess.run(['runuser','-u',user,'--','python','/usr/lib/enzimos/root_retirement.py','plan','--root-uuid',root],capture_output=True,text=True)
        check(result.returncode!=0 and 'root authorization required' in result.stderr,'ordinary user may plan root retirement')
    live=registry.root_identity(native.config()['root_subvol'])['uuid']
    plan=retirement.plan(live);check(not plan['retirable'] and any('live-root' in r or 'not-a-publisher-born' in r for r in plan['protection']),'live root not protected')
    others=[name for name,row in records.items() if name!=PROBE and row['phase']=='ready']
    protected=[]
    for name in others:
        other=retirement.plan(records[name]['root']['uuid'])
        check(not other['retirable'],'generation-bound fallback root was retirable: '+name);protected.append({name:other['protection']})
    plan=retirement.plan(root)
    check(plan['retirable'],'orphan probe root protected: '+json.dumps(plan['protection']))
    check([row['role'] for row in plan['targets']]==['history-store','root-subvolume'],'root retirement target order')
    refused(check,'plan changed',lambda:retirement.prepare(root,'0'*64))
    prepared=retirement.prepare(root,plan['plan_sha256'])
    refused(check,'unfinished root retirement',lambda:native.select_generation('fdn-reg-b','linux'))
    refused(check,'has not completed offline deletion',lambda:retirement.finish(prepared['id']))
    request={'id':prepared['id'],'filesystem_uuid':native.config()['filesystem_uuid'],'control_subvol':native.config()['control_subvol'],
             'targets':plan['targets'],'plan_sha256':plan['plan_sha256']}
    native.atomic_json(STATE,{'boot_id':native.boot_id(),'request':request,'inventory':native.output(['pacman','-Q']),'authority':native.authority_identity(),'history':history})
    os.sync();print('ENZIMOS_ROOT_RETIREMENT_REQUEST='+json.dumps(request,separators=(',',':')),flush=True)
    return {'ordinary_users_denied':True,'live_root_protected':True,'generation_bound_roots_protected':protected,
            'orphan_root_retirable':True,'stale_digest_refused':True,'online_transitions_blocked':True,'deleted_online':False}


def finish(check):
    saved=json.loads(STATE.read_text());check(saved['boot_id']!=native.boot_id(),'later boot required');request=saved['request']
    quiet_maintenance(check)
    present=inventory()
    for row in request['targets']:check(row['path'] not in present and all(v['uuid']!=row['uuid'] for v in present.values()),'offline deletion not observed: '+row['path'])
    result=retirement.finish(request['id']);check(result['status']=='root-retirement-complete','finish result')
    record=births()[PROBE];check(record['phase']=='retired','birth record not tombstoned')
    status=birth.status();check(not status['drift'] and not status['pending'],'retired birth left drift/pending')
    refused(check,'not in the observed subvolume inventory',lambda:retirement.plan(request['targets'][-1]['uuid']))
    refused(check,'not a ready fallback birth',lambda:birth.retire_record(PROBE,{}))
    native.select_generation('fdn-reg-b','linux')
    check(native.output(['pacman','-Q'])==saved['inventory'] and native.authority_identity()==saved['authority'],'root retirement changed packages/authority')
    STATE.unlink();restore_history(check,saved['history'])
    return {'later_boot':True,'offline_deletion_observed':True,'birth_tombstoned':True,'no_drift_after_retirement':True,
            'online_transitions_restored':True,'packages_authority_preserved':True,'source_snapshot_left_to_snapper':True}


def qualify(check,selection):
    check(native.output(['pacman','-Q','enzimos-native-policy'])==VERSION,'wrong root retirement candidate')
    return prepare(check) if selection=='root-retire-prepare' else finish(check)
