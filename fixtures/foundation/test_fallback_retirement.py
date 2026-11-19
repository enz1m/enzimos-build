#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Full fallback lifecycle after a real update: boot-retire the old fallback generation,
then retire its now-orphan publisher-born fallback root offline, then verify later boots
and that completed rebind history no longer blocks further retirement."""
import json
import os
from pathlib import Path
import native
import generation_registry as registry
import root_ownership as birth
import root_retirement as retirement
import boot_retirement
import boot_inventory
from test_credential_review import pause_history,restore_history
from test_root_retirement import quiet_maintenance,births,inventory,refused

import lab_versions
VERSION=lab_versions.native()
STATE=Path('/var/lib/enzimos-control/fallback-retirement-fixture.json')


def fallback_pair(check):
    catalog=registry.status()['catalog']['generations'];records=births()
    roots={row['root']['uuid']:name for name,row in records.items() if row['phase']=='ready'}
    pairs=[(gen,roots[row['material']['root_identity']['uuid']]) for gen,row in catalog.items() if row['material']['root_identity']['uuid'] in roots]
    check(len(pairs)>=1,'no generation bound to a publisher-born fallback root: '+json.dumps(sorted(catalog)))
    return pairs[0]


def remove_legacy_entries(check,refs):
    import re
    uefi=[r[len('reference:entry:uefi:'):].rsplit(' (',1)[0] for r in refs if r.startswith('reference:entry:uefi:')]
    bios=[r[len('reference:entry:bios:'):].rsplit(' (',1)[0] for r in refs if r.startswith('reference:entry:bios:')]
    loader=Path('/boot/loader/loader.conf').read_text()
    check(not any(re.search(r'^default '+re.escape(name)+r'\s*$',loader,re.M) for name in uefi),'legacy UEFI entry is the default')
    with native.operation_lock():
        retired=set(registry.status()['catalog'].get('retired',{}))
        for name in uefi:
            # Publisher entries are named enzimos-<generation>-<flavor>.conf; legacy entries
            # may still carry a rebind-written marker, which must name a retired generation.
            path=Path('/boot/loader/entries')/name;text=path.read_text()
            markers=[w.split('=',1)[1] for w in text.split() if w.startswith('enzimos.generation=')]
            check(path.is_file() and not name.startswith('enzimos-') and all(m in retired for m in markers),'refusing to remove a publisher/live entry: '+name)
            path.unlink()
        limine=Path('/boot/limine/limine.conf');header,entries,selected=native.limine_menu(limine.read_text())
        chosen=entries[selected-1]['title'];check(chosen not in bios,'legacy BIOS entry is the default')
        keep=[e for e in entries if e['title'] not in bios];number=next(i for i,e in enumerate(keep,1) if e['title']==chosen)
        native.atomic_text(limine,re.sub(r'^default_entry:[ \t]*[0-9]+[ \t]*$',f'default_entry: {number}',header,flags=re.M)+''.join(e['text'] for e in keep));os.sync()
    return {'uefi':uefi,'bios':bios}


def prepare(check):
    history=pause_history(check);quiet_maintenance(check)
    generation,transaction=fallback_pair(check);record=births()[transaction];root=record['root']['uuid']
    before=retirement.plan(root)
    check(not before['retirable'] and any(r=='required-by-generation:'+generation for r in before['protection']),'bound fallback root not protected by its generation')
    plan=boot_retirement.plan(generation);check(plan['retirable'],'fallback generation not retirable: '+json.dumps(plan['protection']))
    boot_retirement.retire(generation,plan['plan_sha256'])
    check(generation in registry.status()['catalog']['retired'],'fallback generation not tombstoned')
    rootplan=retirement.plan(root)
    legacy=[]
    if not rootplan['retirable']:
        # Unowned legacy entries protect this root; only explicit fixture removal permits replanning.
        refs=[r for r in rootplan['protection'] if r.startswith('reference:entry:') and r.endswith('(loader-root)')]
        check(refs and len(refs)==len(rootplan['protection']),'fallback root protected by more than unowned loader entries: '+json.dumps(rootplan['protection']))
        legacy=remove_legacy_entries(check,refs)
        rootplan=retirement.plan(root)
    check(rootplan['retirable'],'orphaned fallback root still protected: '+json.dumps(rootplan['protection']))
    check([row['role'] for row in rootplan['targets']]==['history-store','root-subvolume'],'fallback target order')
    prepared=retirement.prepare(root,rootplan['plan_sha256'])
    refused(check,'unfinished root retirement',lambda:native.select_generation(sorted(registry.status()['catalog']['generations'])[0],'linux'))
    request={'id':prepared['id'],'filesystem_uuid':native.config()['filesystem_uuid'],'control_subvol':native.config()['control_subvol'],
             'targets':rootplan['targets'],'plan_sha256':rootplan['plan_sha256']}
    native.atomic_json(STATE,{'boot_id':native.boot_id(),'request':request,'generation':generation,'transaction':transaction,
                              'inventory':native.output(['pacman','-Q']),'authority':native.authority_identity(),'history':history})
    os.sync();print('ENZIMOS_ROOT_RETIREMENT_REQUEST='+json.dumps(request,separators=(',',':')),flush=True)
    return {'fallback_generation':generation,'bound_root_protected_before':True,'fallback_generation_boot_retired':True,
            'unowned_legacy_entries_protected_root':bool(legacy),'legacy_entries_removed_by_administrator':legacy,
            'completed_rebind_history_not_protecting':True,'orphaned_fallback_root_retirable':True,'online_transitions_blocked':True,'deleted_online':False}


def finish(check):
    saved=json.loads(STATE.read_text());check(saved['boot_id']!=native.boot_id(),'later boot required');request=saved['request']
    quiet_maintenance(check);present=inventory()
    for row in request['targets']:check(row['path'] not in present and all(v['uuid']!=row['uuid'] for v in present.values()),'offline deletion not observed: '+row['path'])
    check(retirement.finish(request['id'])['status']=='root-retirement-complete','fallback finish')
    check(births()[saved['transaction']]['phase']=='retired','fallback birth not tombstoned')
    report=boot_inventory.collect()
    drift=[b for b in report['blockers'] if b.startswith('recovery-root-identity-drift:') or b.startswith('referenced-artifact-missing-or-drift:')]
    check(not drift,'retired history still reported as drift: '+json.dumps(drift))
    check(native.output(['pacman','-Q'])==saved['inventory'] and native.authority_identity()==saved['authority'],'fallback retirement changed packages/authority')
    STATE.unlink();restore_history(check,saved['history'])
    return {'later_boot':True,'offline_deletion_observed':True,'birth_tombstoned':True,'retired_history_not_drift':True,
            'packages_authority_preserved':True,'rebind_journal_retained':True}


def qualify(check,selection):
    check(native.output(['pacman','-Q','enzimos-native-policy'])==VERSION,'wrong fallback retirement candidate')
    return prepare(check) if selection=='fallback-retire-prepare' else finish(check)
