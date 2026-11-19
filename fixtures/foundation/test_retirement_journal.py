#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest persistent journal engine cuts using owned dummy metadata, never real roots."""
import copy
from pathlib import Path
import time
import os

import native
import generation_registry as registry
import retirement_journal as journal


def prepare(check):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-58','wrong journal engine candidate')
    root=registry.CONTROL/'retirement-engine-fixture';root.mkdir(mode=0o700)
    objects=root/'objects';objects.mkdir(mode=0o700)
    steps=[]
    for number,kind in enumerate(('uefi-entry','bios-menu','boot-file','catalog')):
        identifier='step'+str(number);before={'identity':identifier,'value':'before'};after={'identity':identifier,'value':'after'}
        registry.save_document(objects/(identifier+'.json'),before)
        steps.append({'id':identifier,'kind':kind,'before':registry.digest(before),'after':registry.digest(after)})
    c=registry.storage_guard()
    value={'schema':1,'id':'fixture','filesystem_uuid':c['filesystem_uuid'],'boot_uuid':native.output(['findmnt','-n','-o','UUID','/boot']),
           'created_boot':native.boot_id(),'observation_sha256':'a'*64,'protected_sha256':'b'*64,'steps':steps}
    value['intent_sha256']=registry.digest(value)
    for missing in ('uefi-entry','bios-menu','boot-file'):
        bad=copy.deepcopy(value);bad['steps']=[step for step in bad['steps'] if step['kind']!=missing]
        bad.pop('intent_sha256');bad['intent_sha256']=registry.digest(bad)
        try:journal.validate_intent(bad)
        except native.Failure:pass
        else:raise AssertionError('incomplete retirement intent accepted: '+missing)
    path=root/'journal.json'
    def save(record,previous):
        check(not path.exists() if previous is None else registry.decode(path.read_bytes())==previous,'fixture journal changed')
        registry.save_document(path,record)
    journal.start(value,lambda:{'fixture':registry.decode(path.read_bytes())} if path.exists() else {},save,lambda value:registry.storage_guard())
    (root/'creator-boot').write_text(native.boot_id())
    return {'persistent_engine_prepared':True,'incomplete_loader_or_resource_refused':True,'real_generation_removed':False}


def replay(check,selection):
    root=registry.CONTROL/'retirement-engine-fixture';path=root/'journal.json';objects=root/'objects'
    before_inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
    mutations=[]
    def cut(label):
        if selection=='journal-engine-cut-'+label:
            os.sync();print('ENZIMOS_RETIREMENT_ENGINE_CUT_READY '+label,flush=True)
            while True:time.sleep(1)
    def read(identifier):return registry.decode(path.read_bytes())
    def save(value,previous):
        check(read('fixture')==previous,'fixture state changed');registry.save_document(path,value)
        if value['inflight']==2:cut('intent')
    def observe(step):return registry.digest(registry.decode((objects/(step['id']+'.json')).read_bytes()))
    def apply(step):
        registry.save_document(objects/(step['id']+'.json'),{'identity':step['id'],'value':'after'})
        mutations.append(step['id'])
        if step['id']=='step2':cut('effect')
    old=read('fixture')
    if selection=='journal-engine-review':
        check(native.boot_id()!=(root/'creator-boot').read_text(),'later boot required')
        check(old['phase']=='executing' and old['inflight']==2,'wrong interruption boundary')
        def drift(value):
            changed=read('fixture');changed['intent']['protected_sha256']='c'*64
            registry.save_document(path,changed)
        # Keep the target in its before-state even on the after-effect branch,
        # so a stale replay really would invoke apply without the journal check.
        target=objects/'step2.json';original=registry.decode(target.read_bytes())
        registry.save_document(target,{'identity':'step2','value':'before'})
        try:
            try:journal.replay('fixture',read,save,drift,observe,apply)
            except native.Failure as exc:check('journal changed' in str(exc),'wrong journal drift refusal')
            else:raise AssertionError('changed journal was replayed')
            check(not mutations and observe(old['intent']['steps'][2])==old['intent']['steps'][2]['before'],'stale journal mutated target')
        finally:
            registry.save_document(target,original);registry.save_document(path,old)
        bad=objects/'step2.json';saved=bad.read_bytes();registry.save_document(bad,{'identity':'replacement','value':'foreign'})
        journal_before=path.read_bytes()
        try:
            try:journal.replay('fixture',read,save,lambda value:registry.storage_guard(),observe,apply)
            except native.Failure as exc:check('outcome unknown' in str(exc),'wrong replacement refusal')
            else:raise AssertionError('journal replay adopted replacement')
            check(path.read_bytes()==journal_before and not mutations,'replacement refusal changed state')
        finally:bad.write_bytes(saved)
    expected=['step2','step3'] if observe(old['intent']['steps'][2])==old['intent']['steps'][2]['before'] else ['step3']
    result=journal.replay('fixture',read,save,lambda value:registry.storage_guard(),observe,apply)
    if selection=='journal-engine-review':check(mutations==expected,'completed side effect was replayed or an unfinished step skipped')
    if selection.startswith('journal-engine-cut-'):raise AssertionError('cut not reached')
    check(read('fixture')['phase']=='complete','journal not completed')
    after=path.read_bytes();count=len(mutations)
    check(journal.replay('fixture',read,save,lambda value:registry.storage_guard(),observe,apply)['status']=='retirement-already-complete','not idempotent')
    check(path.read_bytes()==after and len(mutations)==count,'completed replay mutated again')
    check(before_inventory==native.output(['pacman','-Q']) and authority==native.authority_identity(),'engine test changed packages/authority')
    return {'persistent_engine_completed':True,'changed_identity_refused':True,'completed_replay_idempotent':True,
            'durable_journal_drift_refused_before_effect':True,
            'packages_authority_preserved':True,'mutations':mutations,'real_generation_removed':False,'retirement_enabled':False}
