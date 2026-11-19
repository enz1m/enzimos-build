#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real guest read-only observation and shifted-menu selection; no retirement."""
import json
from pathlib import Path
import re
import native
import boot_inventory
from native import output,sha

CONTROL=Path('/var/lib/enzimos-control')
GENERATION='fdn-identity'


def prepare(check):
    before={str(p):sha(p) for p in Path('/boot').rglob('*') if p.is_file()}
    observation=boot_inventory.collect()
    check(observation['complete'] is False and observation['execution_available'] is False,'observation enabled retirement')
    check(observation['uefi_default_candidates'] and observation['bios_default_title'],'loader defaults unobserved')
    check(observation['mount_namespaces']['namespaces'],'mount namespace observation missing')
    check(all(sha(path)==value for path,value in before.items()),'read-only collection changed boot files')
    native.atomic_json(CONTROL/'boot-observation-before.json',observation)
    kernels=native.installed_kernels()
    with native.operation_lock():
        native.publish_boot('/boot',GENERATION,kernels,Path('/proc/cmdline').read_text().strip())
        path=Path('/boot/limine/limine.conf');header,entries,selected=native.limine_menu(path.read_text())
        selected_title=entries[selected-1]['title']
        moved=[e for e in entries if e['title'].startswith('enzimOS '+GENERATION+' ')]
        remaining=[e for e in entries if e not in moved]
        reordered=moved+remaining
        current=next(i for i,e in enumerate(reordered,1) if e['title']==selected_title)
        native.atomic_text(path,re.sub(r'^default_entry: .*$',f'default_entry: {current}',header,flags=re.M)+''.join(e['text'] for e in reordered))
        published=json.loads((Path('/boot/enzimos/generations')/GENERATION/'PUBLISHED.json').read_text())
        actual=native.limine_number(path.read_text(),'enzimOS '+GENERATION+' linux')
        check(actual!=published['bios_first_entry'],'test did not shift the historical numeric index')
        native.select_generation(GENERATION,'linux-lts')
        check(native.limine_menu(path.read_text())[2]==native.limine_number(path.read_text(),'enzimOS '+GENERATION+' linux-lts'),'LTS selection used stale ordinal')
        native.select_generation(GENERATION,'linux')
        check(native.limine_menu(path.read_text())[2]==actual,'regular selection used stale ordinal')
    native.atomic_json(CONTROL/'identity-boots.json',{'generation':GENERATION,'kernels':kernels,'inventory':output(['pacman','-Q']),'step':0})
    return {'read_only_observation':True,'retirement_enabled':False,'historical_bios_position':published['bios_first_entry'],
            'resolved_bios_position':actual,'both_flavors_selected_by_identity':True,
            'namespace_count':len(observation['mount_namespaces']['namespaces']),'blockers':observation['blockers']}
