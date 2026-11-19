#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Disposable-guest publisher records/confirmation tests; no retirement."""
import json
from pathlib import Path
import re
import subprocess
import native
import generation_registry as registry
from native import output,sha,Failure

CONTROL=Path('/var/lib/enzimos-control')
FIRST='fdn-reg-a'
SECOND='fdn-reg-b'


def prepare(check):
    status=registry.status();check(not status['catalog']['generations'],'fresh registry fixture required')
    kernels=native.installed_kernels();before_inventory=output(['pacman','-Q'])
    try:registry.confirm_current()
    except Failure as exc:check('running-generation marker' in str(exc),'unexpected unmarked-boot refusal')
    else:raise AssertionError('unmarked legacy boot confirmed a managed generation')
    with native.operation_lock():
        for generation in (FIRST,SECOND):native.publish_boot('/boot',generation,kernels,Path('/proc/cmdline').read_text().strip())
        # Reorder complete existing entries, preserving the previously selected title.
        path=Path('/boot/limine/limine.conf');header,entries,selected=native.limine_menu(path.read_text())
        selected_title=entries[selected-1]['title'];moved=[e for e in entries if e['title'].startswith('enzimOS '+SECOND+' ')]
        reordered=moved+[e for e in entries if e not in moved]
        number=next(i for i,e in enumerate(reordered,1) if e['title']==selected_title)
        native.atomic_text(path,re.sub(r'^default_entry: .*$',f'default_entry: {number}',header,flags=re.M)+''.join(e['text'] for e in reordered))
    state=registry.status();records=state['catalog']['generations']
    check(set(records)=={FIRST,SECOND} and all(r['state']=='ready' and r['first_confirmation'] is None for r in records.values()),'publication fabricated a boot confirmation')
    catalog=CONTROL/'generation-registry/catalog.json';before_catalog=sha(catalog)
    unprivileged=subprocess.run(['runuser','-u','enzimos-user','--','python','/usr/lib/enzimos/generation_registry.py','confirm-current'],capture_output=True,text=True)
    check(unprivileged.returncode!=0 and 'root authorization required' in unprivileged.stderr,'ordinary user could confirm a generation')
    supplied=subprocess.run(['python','/usr/lib/enzimos/generation_registry.py','confirm-current','--generation',SECOND],capture_output=True,text=True)
    check(supplied.returncode==2 and sha(catalog)==before_catalog,'caller-supplied generation was accepted or changed the registry')
    before_boot={str(p):sha(p) for p in Path('/boot').rglob('*') if p.is_file()}
    try:registry.assert_update_safe()
    except Failure as exc:check('coherent rebinding' in str(exc),'wrong changing-update refusal')
    else:raise AssertionError('package-write guard ignored a registered mutable-root binding')
    check(output(['pacman','-Q'])==before_inventory,'refused changing update changed installed packages')
    check(not (native.STATE/'boot-stage/fdn-unsafe-second-update').exists(),'refused update allocated a stage')
    check(all(sha(p)==value for p,value in before_boot.items()),'refused update changed boot resources')
    native.select_generation(FIRST,'linux')
    native.atomic_json(CONTROL/'registry-boots.json',{'first':FIRST,'second':SECOND,'kernels':kernels,'inventory':before_inventory,'step':0})
    return {'published_unconfirmed':2,'caller_confirmation_rejected':True,'unprivileged_confirmation_rejected':True,
            'package_write_guard_refused_registered_live_root':True,
            'control_subvolume':output(['findmnt','-n','-o','FSROOT','--mountpoint',CONTROL]),
            'registry_mode':oct(catalog.stat().st_mode & 0o777),'retirement_enabled':False}
