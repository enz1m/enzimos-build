#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Disposable guest pin creation/drift/refusal; no retirement or pin removal API."""
import copy
import json
from pathlib import Path
import subprocess

import boot_inventory
import generation_registry as registry
import native
import recovery_references as refs


def qualify(check):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-36','wrong pin candidate')
    catalog_path=registry.CONTROL/'generation-registry/catalog.json'
    catalog_bytes=catalog_path.read_bytes();catalog=registry.status()['catalog']
    names=sorted(name for name,value in catalog['generations'].items() if value['state']=='ready')
    check(names,'real published generations required');name=names[0]
    inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
    result=refs.pin('fixture-keep',name);value=result['pin'];folder=refs.pin_directory();path=folder/'fixture-keep.json';before=path.read_bytes()
    def refuse(action,fragment):
        try:action()
        except native.Failure as exc:check(fragment in str(exc),'wrong pin refusal: '+str(exc))
        else:raise AssertionError('unsafe generation pin accepted')
    refuse(lambda:refs.pin('fixture-keep',name),'no automatic replacement')
    check(path.read_bytes()==before,'duplicate changed pin')
    observation=boot_inventory.collect();graph=observation['recovery_references']
    check(graph is not None and 'pin:fixture-keep' in graph['nodes'],'real pin omitted from graph')
    check('user-pin-inventory-unavailable' not in graph['blockers'],'pin inventory not observed')
    artifact='/enzimos/generations/'+name+'/vmlinuz-linux'
    check(graph['nodes']['boot:'+artifact]['bytes_match'],'pin material bytes not verified')
    edges={(row['source'],row['target'],row['reason']) for row in graph['edges']}
    check(('pin:fixture-keep','root:'+value['material']['root_identity']['uuid'],'keep-root') in edges,'pin lost root identity')
    # Retained pin material cannot be erased by a changed or missing catalog row.
    for missing in (False,True):
        changed=copy.deepcopy(catalog)
        if missing:del changed['generations'][name]
        else:changed['generations'][name]['material']['inventory_sha256']='f'*64
        registry.save_document(catalog_path,changed)
        try:
            drift=boot_inventory.collect()['recovery_references']
            check(drift is not None and 'pinned-generation-missing-or-drift:fixture-keep' in drift['blockers'],'pin drift silently ignored')
            check('boot:'+artifact in drift['nodes'] and 'pin:fixture-keep' in drift['nodes'],'pin dependencies lost with catalog')
        finally:catalog_path.write_bytes(catalog_bytes)
    pending=folder/'.fixture-keep-test.tmp';pending.write_text('unfinished');pending.chmod(0o600)
    try:
        refuse(refs.pins_status,'interrupted')
        blocked=boot_inventory.collect()
        check(blocked['recovery_references'] is None and any('generation pins require review' in p for p in blocked['blockers']),'orphan pin did not block collection')
    finally:pending.unlink()
    entry=Path('/boot/loader/entries')/('enzimos-'+name+'-linux.conf');body=entry.read_bytes()
    entry.write_bytes(body.replace(b'title ',b'title CHANGED ',1))
    try:refuse(lambda:refs.pin('drift',name),'boot material drift')
    finally:entry.write_bytes(body)
    check(not (folder/'drift.json').exists(),'refused pin was written')
    for action in (['pins'],['pin','--id','ordinary','--generation',name]):
        denied=subprocess.run(['runuser','-u','enzimos-user','--','python','/usr/lib/enzimos/recovery_references.py',*action],capture_output=True,text=True)
        check(denied.returncode!=0 and 'root authorization required' in denied.stderr,'ordinary user read or changed pins')
    check(path.read_bytes()==before and catalog_path.read_bytes()==catalog_bytes,'controls changed pin/catalog')
    check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'pin controls changed inventory/authority')
    check(not graph['complete'] and not graph['execution_available'] and all(not row['deletion_authorized'] for row in graph['nodes'].values()),'pins granted deletion')
    return {'uefi':Path('/sys/firmware/efi').exists(),'created_material_bound_pin':True,'root_artifact_links_observed':True,
            'missing_changed_catalog_stays_protected':True,'duplicate_pin_refused':True,'drift_pin_refused':True,
            'orphan_pin_blocks':True,'ordinary_access_refused':True,'catalog_pin_packages_authority_preserved':True,
            'complete':False,'retirement_enabled':False}
