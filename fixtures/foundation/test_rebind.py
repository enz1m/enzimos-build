#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only rebind/update/cut/replay checks; not a shipping recovery interface."""
import copy
import json
import os
from pathlib import Path
import time

import native
import generation_registry as registry
import root_rebind
from native import Failure,output,sha

CONTROL=Path('/var/lib/enzimos-control')
FIRST='fdn-reg-a'
CUT_ID='fdn-rebind-cut'
CUT='ENZIMOS_REBIND_CUT_READY synced-before-package-write'
HOME=Path('/home/enzimos-admin/rebind-home-marker')


def finished_update(update,check,kernels):
    registry.confirm_current()
    result=update()
    journal=root_rebind.load_journal(registry.CONTROL/'root-rebind-journal/fdn-success.json')
    check(journal['phase']=='complete' and set(journal['affected'])=={'fdn-reg-a','fdn-reg-b'},'registered root aliases were not rebound')
    for name in journal['affected']:
        check(journal['before_catalog']['generations'][name]['first_confirmation'] is not None,'missing pre-rebind observation')
        check(journal['after_catalog']['generations'][name]['first_confirmation'] is None,'old-root confirmation was reused for a different binding')
    state=registry.status()['catalog']
    check(all(state['generations'][name]['material']['root_identity']==journal['target'] for name in journal['affected']),'rebound registry root identity differs')
    check(state['generations']['fdn-success']['material']['root_identity']==journal['source'],'new generation is not the updated original root')
    k=kernels()
    native.atomic_json(CONTROL/'rebind-boots.json',{'new':'fdn-success','old':FIRST,'source':journal['source'],'target':journal['target'],
        'new_kernels':{'linux':k['NEW_REGULAR'],'linux-lts':k['NEW_LTS']},'old_kernels':journal['kernels'],'step':0})
    return {'update':result,'rebind_complete':True,'source_uuid':journal['source']['uuid'],'retained_uuid':journal['target']['uuid'],
            'historical_confirmations_preserved_in_journal':True,'new_binding_confirmations_cleared':True,'retirement_enabled':False}


def interrupted(check,kernels,module_trial):
    registry.confirm_current();before=output(['pacman','-Q']);HOME.write_text('before-rebind\n')
    reached=False
    def checkpoint(name,journal):
        nonlocal reached
        if reached or not name.startswith('file:loader/entries/enzimos-'):return
        reached=True
        check(journal['phase']=='prepared','journal was already complete')
        check(not Path('/var/lib/pacman/db.lck').exists(),'package transaction already started')
        check(output(['pacman','-Q'])==before,'packages changed before metadata interruption')
        module_trial();HOME.write_text('NEWER-HOME-SURVIVES-REBIND\n')
        native.atomic_json(CONTROL/'rebind-cut.json',{'id':CUT_ID,'inventory':before,'authority':native.authority_identity(),
            'source':journal['source'],'target':journal['target'],'kernels':journal['kernels'],'cut_boundary':name})
        os.sync();print(CUT,flush=True)
        while True:time.sleep(1)
    k=kernels()
    native.run_update('/etc/pacman-foundation.conf',CUT_ID,{'linux':k['NEW_REGULAR'],'linux-lts':k['NEW_LTS']},Path('/proc/cmdline').read_text().strip(),rebind_observer=checkpoint)
    raise AssertionError('rebind interruption checkpoint was not reached')


def replay(check,module_trial):
    info=json.loads((CONTROL/'rebind-cut.json').read_text());identifier=info['id']
    journal_path=registry.CONTROL/'root-rebind-journal'/(identifier+'.json')
    check(root_rebind.load_journal(journal_path)['phase']=='prepared','expected incomplete root rebind')
    check(output(['findmnt','-n','-o','FSROOT','/'])=='/'+info['target']['path'],'interruption did not boot the coherent retained root')
    before_catalog=sha(CONTROL/'generation-registry/catalog.json')
    for action in (registry.confirm_current,lambda:native.select_generation(FIRST,'linux'),lambda:native.run_update('/etc/pacman-foundation.conf','blocked-while-rebinding',{},Path('/proc/cmdline').read_text().strip())):
        try:action()
        except Failure as exc:check('rebinding is incomplete' in str(exc),'wrong pending-transition refusal')
        else:raise AssertionError('operation ignored pending rebind journal')
    loader=Path('/boot/loader/loader.conf');saved=loader.read_text();native.atomic_text(loader,saved+'# deliberate fixture drift\n')
    try:
        try:root_rebind.resume(identifier)
        except Failure as exc:check('state drift' in str(exc),'wrong drift refusal')
        else:raise AssertionError('replay overwrote changed boot state')
        check(loader.read_text()==saved+'# deliberate fixture drift\n' and sha(CONTROL/'generation-registry/catalog.json')==before_catalog,'drift refusal overwrote state')
    finally:native.atomic_text(loader,saved)
    boundaries=[]
    for stop in ('file:limine/limine.conf','catalog'):
        def interrupted_boundary(name,_):
            if name==stop:boundaries.append(name);raise OSError('LAB controlled post-write boundary')
        try:root_rebind.resume(identifier,interrupted_boundary)
        except OSError as exc:check('LAB controlled' in str(exc),'unexpected replay failure')
        else:raise AssertionError('post-write interruption not exercised')
        check(root_rebind.load_journal(journal_path)['phase']=='prepared','interrupted replay claimed completion')
    result=root_rebind.resume(identifier);check(result['status']=='rebind-complete','rebind replay did not complete')
    digest=sha(journal_path);check(root_rebind.resume(identifier)['status']=='already-complete' and sha(journal_path)==digest,'completed replay was not idempotent')
    check(output(['pacman','-Q'])==info['inventory'],'metadata replay changed packages')
    check(native.authority_identity()==info['authority'],'replay changed current authority')
    check(HOME.read_text()=='NEWER-HOME-SURVIVES-REBIND\n','newer home was lost')
    module_trial();registry.confirm_current()
    native.select_generation(FIRST,'linux')
    native.atomic_json(CONTROL/'rebind-fallback-boots.json',{'generation':FIRST,'root':info['target'],'kernels':info['kernels'],'step':0,'inventory':info['inventory']})
    return {'journal_replayed':True,'drift_rejected_without_overwrite':True,'interrupted_boundaries':boundaries,
            'pending_operations_blocked':True,'packages_replayed':False,'newer_home_and_current_authority_preserved':True,
            'retained_root_uuid':info['target']['uuid'],'retirement_enabled':False}


def select_old(check):
    info=json.loads((CONTROL/'rebind-boots.json').read_text())
    check(registry.current_marker()==info['new'],'selector must boot the updated generation')
    registry.confirm_current();native.select_generation(info['old'],'linux')
    info['step']=4;native.atomic_json(CONTROL/'rebind-boots.json',info)
    return {'selected_retained_generation':info['old'],'source_uuid':info['source']['uuid'],'retained_uuid':info['target']['uuid']}


def boot(check,module_trial,fallback=False):
    path=CONTROL/('rebind-fallback-boots.json' if fallback else 'rebind-boots.json');info=json.loads(path.read_text());step=info['step']
    limit=4 if fallback else 8;check(0<=step<limit,'rebind boot sequence complete')
    retained=fallback or step>=4;slot=step if fallback else step%4
    generation=info['generation'] if fallback else info['old'] if retained else info['new']
    root=info['root'] if fallback else info['target'] if retained else info['source']
    kernels=info['kernels'] if fallback else info['old_kernels'] if retained else info['new_kernels']
    mode=slot<2;flavor='linux-lts' if slot%2 else 'linux'
    check(os.uname().release==kernels[flavor] and Path('/sys/firmware/efi').exists()==mode,'wrong rebind kernel/loader')
    check(registry.current_marker()==generation,'wrong rebind generation marker')
    actual=registry.root_identity(native.config()['root_subvol']);check(actual==root,'wrong coherent root binding booted')
    confirmation=registry.confirm_current();module_trial()
    if fallback:
        check(output(['pacman','-Q'])==info['inventory'] and HOME.read_text()=='NEWER-HOME-SURVIVES-REBIND\n','retained root changed package state/home')
    next_flavor='linux-lts' if slot in (0,2) else 'linux'
    # New and retained matrices fork from one immutable updated parent, keeping
    # backing depth bounded rather than silently flattening or extending the limit.
    next_generation=generation if fallback or retained else info['new']
    native.select_generation(next_generation,next_flavor)
    info['step']=step+1;native.atomic_json(path,info)
    return {'generation':generation,'kernel':os.uname().release,'uefi':mode,'step':step,'root_uuid':root['uuid'],
            'confirmation':confirmation['confirmation'],'retirement_enabled':False}
