#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real boot-generation retirement on the guest ESP: protections, a killed run with
explicit resume, and a later boot through the retained default entry."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import native
import boot_retirement as retirement
import generation_registry as registry
import recovery_references
from test_credential_review import pause_history,restore_history
from test_root_retirement import quiet_maintenance

import lab_versions
VERSION=lab_versions.native()
STATE=Path('/var/lib/enzimos-control/boot-retirement-fixture.json')
NEW=('br-c','br-d')
HELPER='''
import os,signal,sys
sys.path.insert(0,'/usr/lib/enzimos');import boot_retirement as r
def hook(step):
    if step==sys.argv[3]:os.kill(os.getpid(),signal.SIGKILL)
r.retire(sys.argv[1],sys.argv[2],step_hook=hook)
'''


def refused(check,expected,callable_):
    try:callable_()
    except (native.Failure,OSError) as exc:
        check(expected in str(exc),'wrong refusal: '+str(exc));return str(exc)
    raise AssertionError('not refused: '+expected)


def catalog():return registry.status()['catalog']


def running():
    markers=[w.split('=',1)[1] for w in Path('/proc/cmdline').read_text().split() if w.startswith('enzimos.generation=')]
    return markers[0] if len(markers)==1 else None


def boot_view(generation):
    folder=Path('/boot/enzimos/generations')/generation
    uefi=[p.name for p in Path('/boot/loader/entries').iterdir() if p.name.startswith(f'enzimos-{generation}-')]
    _,entries,selected=native.limine_menu(Path('/boot/limine/limine.conf').read_text())
    return {'directory':folder.exists(),'uefi':sorted(uefi),'bios':sorted(e['title'] for e in entries if e['title'].startswith(f'enzimOS {generation} ')),
            'bios_default':entries[selected-1]['title']}


def protected(check,generation,reason):
    plan=retirement.plan(generation)
    check(not plan['retirable'] and any(reason in item for item in plan['protection']),'expected protection '+reason+': '+json.dumps(plan['protection']))
    return plan


def root_exists(identity):
    listing=native.output(['btrfs','subvolume','list','-u','/'])
    return any(line.endswith(' path '+identity['path']) and ' uuid '+identity['uuid'] in line for line in listing.splitlines())


def retire_checked(check,generation,kill_after=None):
    plan=retirement.plan(generation)
    check(plan['retirable'],'candidate unexpectedly protected: '+json.dumps(plan['protection']))
    record=catalog()['generations'][generation];before=boot_view(generation)
    check(before['directory'] and len(before['uefi'])==2 and len(before['bios'])==2,'candidate not fully published')
    refused(check,'plan changed',lambda:retirement.retire(generation,'0'*64))
    killed=False
    if kill_after is not None:
        result=subprocess.run(['python','-I','-B','-c',HELPER,generation,plan['plan_sha256'],kill_after],capture_output=True,text=True)
        check(result.returncode==-signal.SIGKILL,'retirement helper not killed: '+result.stderr[-300:])
        status=retirement.status()['journals']['boot-'+generation];check(status['phase']=='executing','killed retirement phase')
        # Every other boot transition refuses while the journal is incomplete.
        refused(check,'incomplete boot retirement',lambda:native.select_generation(NEW[-1],'linux'))
        refused(check,'incomplete boot retirement',lambda:retirement.plan(NEW[0]))
        result=retirement.resume('boot-'+generation);killed=True
    else:result=retirement.retire(generation,plan['plan_sha256'])
    check(result['status']=='retirement-complete' and result['root_subvolume_retained'],'retirement result')
    after=boot_view(generation);current=catalog()
    check(not after['directory'] and after['uefi']==[] and after['bios']==[] and after['bios_default']==before['bios_default'],'boot objects remain or BIOS default moved')
    check(generation not in current['generations'] and current['retired'][generation]['ordinal']==record['ordinal'],'catalog tombstone missing')
    check(root_exists(record['material']['root_identity']),'root subvolume was touched')
    refused(check,'not a publisher-registered generation',lambda:retirement.plan(generation))
    return {'plan_steps':len(plan['steps']),'killed_and_resumed':killed,'disclosed':plan['disclosed_unobservable']}


def fit(size):
    """How many fixture generations publish_boot will admit now (artifacts + 16 MiB each)."""
    free=shutil.disk_usage('/boot').free
    return free,2 if free>=2*(size+16*1024**2)+4*1024**2 else 1 if free>=size+20*1024**2 else 0


def selected_generation():
    names=[name for name in sorted(catalog()['generations']) if native.generation_selected(name)]
    return names[0] if names else None


def controls(check,mode):
    history=pause_history(check);quiet_maintenance(check)
    inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
    existing=catalog()['generations'];old=sorted(name for name in existing if name not in NEW)
    live=running();kernels=native.installed_kernels();options=Path('/proc/cmdline').read_text().strip()
    # After a real update the ESP-root kernels belong to the legacy entries, not the
    # running root; stage fresh aliases from the running generation's verified files.
    stage=Path('/boot/enzimos/generations')/live if live else Path('/boot')
    size=sum(os.path.getsize(stage/n) for f in kernels for n in (f'vmlinuz-{f}',f'initramfs-{f}.img'))
    print('ENZIMOS_BOOT_RETIREMENT_FIXTURE '+json.dumps({'generations':{n:{'ordinal':r['ordinal'],'state':r['state'],'confirmed':r['first_confirmation'] is not None} for n,r in existing.items()},
          'running':live,'selected':selected_generation(),'esp_free':shutil.disk_usage('/boot').free,'generation_bytes':size,'stage':str(stage)}),flush=True)
    check(len(old)>=2,'fixture lineage needs two older publisher generations: '+str(sorted(existing)))
    for user in ('enzimos-user','enzimos-admin'):
        result=subprocess.run(['runuser','-u',user,'--','python','/usr/lib/enzimos/boot_retirement.py','plan','--generation',old[0]],capture_output=True,text=True)
        check(result.returncode!=0 and 'root authorization required' in result.stderr,'ordinary user may plan retirement')
    free,count=fit(size);published=[]
    def publish(names):
        with native.operation_lock():
            for name in names:native.publish_boot(stage,name,kernels,options);published.append(name)
        native.select_generation(published[-1],'linux')
    if count:publish(NEW[-count:])
    default=selected_generation()
    if default:protected(check,default,'selected-by-loader-default')
    if live in old:protected(check,live,'running-generation')
    def candidates():
        rows=catalog()['generations'];chosen=selected_generation()
        newer=lambda name:sum(row['ordinal']>rows[name]['ordinal'] and row['state']=='ready' for row in rows.values())
        return [name for name in sorted(rows,key=lambda n:rows[n]['ordinal']) if name in old and name not in (live,chosen) and newer(name)>=2]
    eligible=candidates()
    check(eligible,'no old generation with two newer ready generations (ESP free '+str(free)+', published '+str(published)+')')
    # A full ESP requires retirement to free space before publication.
    first=retire_checked(check,eligible[0],kill_after='bios' if mode=='uefi' else 'file-READY.json')
    freed=shutil.disk_usage('/boot').free-free
    remaining=[name for name in NEW if name not in published]
    _,more=fit(size)
    if remaining and more:publish(remaining[-more:] if len(remaining)>more else remaining)
    check(published,'no fixture generation could be published even after retirement')
    protected(check,published[-1],'created-this-boot');protected(check,published[-1],'selected-by-loader-default')
    # Pins are permanent; pin a fixture generation so older ones stay retirable later.
    pin_target=published[0];recovery_references.pin('br-keep',pin_target);protected(check,pin_target,'reference:pin:br-keep')
    check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'retirement changed packages/authority')
    native.atomic_json(STATE,{'boot_id':native.boot_id(),'retired':eligible[0],'remaining_old':[n for n in old if n!=eligible[0]],
                              'default':published[-1],'inventory':inventory,'history':history})
    os.sync()
    return {'published_fixture_generations':published,'esp_free_before':free,'esp_freed_by_retirement':freed,'fixture_generation_bytes':size,
            'pinned':pin_target,'ordinary_users_denied':True,'default_protected':True,'fresh_protected':True,'pin_protected':True,
            'running_protected':live in old,'retired':eligible[0],**first,'packages_authority_preserved':True,
            'root_subvolumes_deleted':False,'efi_variables_observed':Path('/sys/firmware/efi').is_dir()}


def review(check):
    saved=json.loads(STATE.read_text());check(saved['boot_id']!=native.boot_id(),'later boot required');quiet_maintenance(check)
    check(running()==saved['default'],'retained default generation did not boot: '+str(running()))
    confirmed=registry.confirm_current();check(confirmed['generation']==saved['default'],'retained default not confirmable')
    check(saved['retired'] in catalog()['retired'],'tombstone lost across boot')
    generations=catalog()['generations']
    remaining=[name for name in saved['remaining_old'] if name in generations]
    newer=lambda name:sum(row['ordinal']>generations[name]['ordinal'] and row['state']=='ready' for row in generations.values())
    eligible=[name for name in remaining if newer(name)>=2]
    for name in remaining:
        if name not in eligible:protected(check,name,'fewer-than-two-newer-ready-generations')
    result=retire_checked(check,eligible[0]) if eligible else {}
    check(native.output(['pacman','-Q'])==saved['inventory'],'packages changed')
    STATE.unlink();restore_history(check,saved['history'])
    return {'later_boot':True,'booted_retained_default':True,'retained_default_confirmed':True,'tombstone_persisted':True,
            'second_retirement':bool(eligible),'retention_protected':[n for n in remaining if n not in eligible],**result,'root_subvolumes_deleted':False}


def qualify(check,selection):
    check(native.output(['pacman','-Q','enzimos-native-policy'])==VERSION,'wrong boot retirement candidate')
    mode='uefi' if Path('/sys/firmware/efi').is_dir() else 'bios'
    return controls(check,mode) if selection=='boot-retirement' else review(check)
