#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Close the recovery lifecycle: retire the recovery's fallback chain and then the root an
adopted recovery replaced (payload-script; three runs around two loader-started offline
coordinator boots).

Run 1: conclude the adopted recovery (legacy + staged entries detached while a confirmed
registered generation on the adopted root runs), boot-retire generations still bound to the
old roots, prepare + stage the offline retirement of the recovery's fallback root/history.
Run 2 (after coordinator-boot): finish it (birth tombstoned), then prepare + stage the
superseded root with its nested old history (now unowned), deepest first.
Run 3 (after coordinator-boot): finish; the superseded root and its nested subvolumes are
gone, the activation is tombstoned and the adopted generation still confirms."""
import json
import os
from pathlib import Path
import native
import generation_registry as registry
import recovery_activation as activation
import recovery_image as image
import root_ownership as birth
import root_retirement as retirement
from test_credential_review import pause_history,restore_history
from test_root_retirement import quiet_maintenance,inventory,refused

STATE=Path('/var/lib/enzimos-control/superseded-root-fixture.json')


def adopted():
    rows=[(name,row) for name,row in activation.records().items() if row['phase']=='adopted']
    assert len(rows)==1,'exactly one adopted activation required'
    return rows[0]


def uuids():return {row['uuid'] for row in inventory().values()}


def retire_bound_generations(check,root_uuid,retired):
    import boot_retirement
    for _ in range(8):
        plan=retirement.plan(root_uuid)
        needing=[reason.split(':',1)[1] for reason in plan['protection'] if reason.startswith('required-by-generation:')]
        if not needing:return plan
        print('ENZIMOS_LAB_RETIRE_PLAN '+json.dumps(plan['protection']),flush=True)
        for generation in needing:
            generation_plan=boot_retirement.plan(generation)
            check(generation_plan['retirable'],'generation bound to a retired root is protected: '+generation+' '+json.dumps(generation_plan['protection']))
            result=boot_retirement.retire(generation,generation_plan['plan_sha256']);check(result['root_subvolume_retained'],'boot retirement');retired.append(generation)
    return retirement.plan(root_uuid)


def stage(check,root_uuid,retired,label):
    plan=retire_bound_generations(check,root_uuid,retired)
    check(plan['retirable'],label+' root protected: '+json.dumps(plan['protection']))
    prepared=retirement.prepare(root_uuid,plan['plan_sha256'])
    images=[key for key,value in image.records().items() if value['phase']=='ready'];check(images,'no ready recovery image for the coordinator')
    before={'loader':Path('/boot/loader/loader.conf').read_text(),'limine':Path('/boot/limine/limine.conf').read_text()}
    retirement.stage_coordinator(prepared['id'],images[0],'poweroff')
    return prepared['id'],plan['targets'],before


def finish_step(check,saved):
    check(saved['boot_id']!=native.boot_id(),'later boot required')
    check(registry.current_marker()==saved['marker'],'restored default did not boot the adopted generation')
    quiet_maintenance(check);present=uuids()
    for row in saved['targets']:check(row['uuid'] not in present,'retired subvolume still present: '+row['path'])
    check(retirement.finish(saved['id'])['status']=='root-retirement-complete','finish')
    check(Path('/boot/loader/loader.conf').read_text()==saved['before']['loader'] and Path('/boot/limine/limine.conf').read_text()==saved['before']['limine'],'loader metadata not restored')


def first(check):
    history=pause_history(check);quiet_maintenance(check)
    name,row=adopted();check('superseded' in row,'adoption did not record the superseded root')
    old=row['superseded']['identity'];check(old['uuid'] in uuids(),'superseded root not present')
    refused(check,'legacy-entries-attached',lambda:retirement.prepare(old['uuid'],retirement.plan(old['uuid']).get('plan_sha256','0'*64)))
    refused(check,'adopted recovery',lambda:activation.detach_legacy(name,'0'*64))
    concluded=activation.detach_legacy(name,row['intent']['intent_sha256']);check(concluded['status']=='recovery-concluded-entries-detached','conclude recovery')
    fallback=row['intent']['job']['plan']['source_birth']['root']
    retired=[];identifier,targets,before=stage(check,fallback['uuid'],retired,'recovery fallback')
    native.atomic_json(STATE,{'step':'fallback','boot_id':native.boot_id(),'id':identifier,'targets':targets,'before':before,'activation':name,'old':old,
                              'fallback_birth':row['intent']['job']['plan']['source_birth']['transaction'] if 'transaction' in row['intent']['job']['plan']['source_birth'] else None,
                              'marker':registry.current_marker(),'inventory':native.output(['pacman','-Q']),'history':history,'retired':retired})
    os.sync()
    return {'step':'fallback-staged','superseded_root_recorded_at_adoption':True,'recovery_concluded_entries_detached':True,
            'generations_retired_first':retired,'fallback_targets':len(targets),'deleted_online':False}


def second(check,saved):
    finish_step(check,saved);name=saved['activation'];old=saved['old']
    check(all(record['phase']!='ready' or record['root']['uuid']!=saved['targets'][-1]['uuid'] for record in birth.read_records(*birth.private_directory()).values()),'fallback birth not tombstoned')
    retired=saved['retired'];identifier,targets,before=stage(check,old['uuid'],retired,'superseded')
    check(targets[-1]['uuid']==old['uuid'] and len(targets)>=2,'superseded plan lacks its nested history')
    native.atomic_json(STATE,dict(saved,step='superseded',boot_id=native.boot_id(),id=identifier,targets=targets,before=before,retired=retired,fallback_targets=saved['targets']))
    os.sync()
    return {'step':'superseded-staged','fallback_chain_deleted_offline':True,'fallback_birth_tombstoned':True,'nested_history_targets':len(targets)-1,'deleted_online':False}


def third(check,saved):
    finish_step(check,saved)
    check(activation.records()[saved['activation']]['superseded']['retired'],'superseded root not tombstoned on the activation')
    check(registry.confirm_current()['generation']==saved['marker'],'adopted generation no longer confirms')
    check(native.output(['pacman','-Q'])==saved['inventory'],'packages changed')
    STATE.unlink();restore_history(check,saved['history'])
    return {'step':'complete','later_boot':True,'superseded_root_and_history_deleted_offline':True,'activation_tombstoned':True,
            'loader_restored':True,'adopted_generation_confirmed':True,'packages_preserved':True,'boot_generations_retired':saved['retired']}


def run(check,payload):
    if not STATE.exists():return first(check)
    saved=json.loads(STATE.read_text())
    return second(check,saved) if saved['step']=='fallback' else third(check,saved)
