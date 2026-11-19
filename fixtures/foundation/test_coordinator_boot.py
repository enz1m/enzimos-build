#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Loader-started offline root retirement: publish a recovery image, create and prepare
an orphan fallback root, stage the coordinator entry (both loader defaults), then finish
after the firmware/loader ran the coordinator and the defaults were restored."""
import json
import os
from pathlib import Path
import shutil
import native
import generation_registry as registry
import recovery_image as image
import root_ownership as birth
import root_retirement as retirement
from test_credential_review import pause_history,restore_history
from test_root_retirement import quiet_maintenance,births,inventory,refused

import lab_versions
VERSION=lab_versions.native()
PROBE='fdn-coordinator-probe'
STATE=Path('/var/lib/enzimos-control/coordinator-boot-fixture.json')


def publish_image(payload):
    payload=Path(payload);manifest=json.loads((payload/'recovery-image-manifest.json').read_text())
    identifier=image.image_id(manifest['identity'])
    if identifier in image.records():return identifier
    image.INPUT.mkdir(mode=0o700,parents=True,exist_ok=True)
    shutil.copyfile(payload/'recovery-image-manifest.json',image.INPUT/'manifest.json')
    shutil.copyfile('/boot/enzimos-recovery/kernel',image.INPUT/'kernel');shutil.copyfile('/boot/enzimos-recovery/initrd.img',image.INPUT/'initrd.img')
    line=native.entry_fields(Path('/boot/loader/entries/recovery.conf').read_text(),None)['options']
    return image.publish(line)['id']


def build_image(check):
    """Native68+: the packaged builder makes a NEW coordinator image on this system."""
    import recovery_build
    modules=Path('/usr/lib/modules');release=os.uname().release
    if not (modules/release/'vmlinuz').is_file():release=sorted(p.name for p in modules.iterdir() if (p/'vmlinuz').is_file())[-1]
    line=native.entry_fields(Path('/boot/loader/entries/recovery.conf').read_text(),None)['options']
    before=set(image.records())
    refused(check,'invalid generation identifier',lambda:recovery_build.build('../escape',line))
    image.INPUT.mkdir(mode=0o700,parents=True)
    try:refused(check,'stale recovery publication input',lambda:recovery_build.build(release,line))
    finally:image.INPUT.rmdir()
    check(set(image.records())==before,'refused builds recorded an image')
    result=recovery_build.build(release,line);identifier=result['id']
    check(result['status']=='recovery-image-built-and-published' and result['general_recovery_environment'] is False and result['selection_changed'] is False,'builder scope')
    check(result['default_init']=='refuse-and-power-off' and result['policy_files_checked']>=37,'built image stream checks')
    record=image.records()[identifier];identity=record['inputs']['identity']
    check(record['phase']=='ready' and identity['kernel_release']==release and 'recovery_build.py' in identity['policy_files'],'built image record')
    body=Path('/boot/enzimos/recovery-images',identifier,'initrd.img').read_bytes()
    check(body.endswith(recovery_build.newc(recovery_build.DESCRIPTOR,json.dumps(identity,sort_keys=True).encode()+b'\n')),'descriptor member not appended')
    check(not image.INPUT.exists(),'publication input not removed')
    return identifier,{'packaged_image_built':True,'builder_refusals_recorded_nothing':True,'descriptor_appended':True,
                       'image_kernel':release,'image_bytes':result['initrd_bytes'],'general_recovery_environment':False}


def uefi_staged(check,entry,loader_before):
    """Firmware one-shot (EFI variables observable) or, without them, default emulation."""
    if entry.get('uefi_mode')=='one-shot':
        import boot_inventory
        variable=Path('/sys/firmware/efi/efivars/LoaderEntryOneShot-'+boot_inventory.GUID)
        check(variable.exists() and boot_inventory.efi_string(variable.read_bytes())==entry['uefi_entry'],'UEFI one-shot variable not set to the coordinator entry')
        check(Path('/boot/loader/loader.conf').read_text()==loader_before,'one-shot staging changed the UEFI default')
        return {'uefi_one_shot_variable_set':True,'uefi_default_unchanged':True}
    check(f"default {entry['uefi_entry']}" in Path('/boot/loader/loader.conf').read_text(),'UEFI default not staged')
    return {'uefi_one_shot_variable_set':False,'uefi_default_unchanged':False}


def stage(check,payload,built=False):
    history=pause_history(check);quiet_maintenance(check)
    if built:identifier,extra=build_image(check)
    else:identifier,extra=publish_image(payload),{}
    # Baseline after recovery publication (which adds its own entries): finish must restore exactly this.
    before={'loader':Path('/boot/loader/loader.conf').read_text(),'limine':Path('/boot/limine/limine.conf').read_text()}
    with native.operation_lock():birth.create_fallback(PROBE)
    record=births()[PROBE];root=record['root']['uuid']
    plan=retirement.plan(root);check(plan['retirable'],'fresh orphan root protected: '+json.dumps(plan['protection']))
    prepared=retirement.prepare(root,plan['plan_sha256'])
    refused(check,'ready published recovery image required',lambda:retirement.stage_coordinator(prepared['id'],'ri-'+'0'*64,'poweroff'))
    staged=retirement.stage_coordinator(prepared['id'],identifier,'poweroff')
    entry=retirement.records()[prepared['id']]['coordinator']
    extra.update(uefi_staged(check,entry,before['loader']))
    _,entries,selected=native.limine_menu(Path('/boot/limine/limine.conf').read_text())
    check(entries[selected-1]['title']==entry['bios_title'],'BIOS default not staged')
    refused(check,'unfinished root retirement',lambda:native.select_generation(sorted(registry.status()['catalog']['generations'])[0],'linux'))
    markers=[w.split('=',1)[1] for w in Path('/proc/cmdline').read_text().split() if w.startswith('enzimos.generation=')]
    native.atomic_json(STATE,{'boot_id':native.boot_id(),'id':prepared['id'],'targets':plan['targets'],'before':before,'running':markers,
                              'inventory':native.output(['pacman','-Q']),'authority':native.authority_identity(),'history':history,'image':identifier})
    os.sync()
    return {**extra,'recovery_image':identifier,'orphan_created_with_birth_record':True,'prepared':True,'coordinator_staged':True,
            'unready_image_refused':True,'both_defaults_staged':True,'online_transitions_blocked':True,'deleted_online':False}


def finish(check):
    saved=json.loads(STATE.read_text());check(saved['boot_id']!=native.boot_id(),'later boot required')
    markers=[w.split('=',1)[1] for w in Path('/proc/cmdline').read_text().split() if w.startswith('enzimos.generation=')]
    check(markers==saved['running'],'restored default did not boot the previous entry')
    quiet_maintenance(check);present=inventory()
    for row in saved['targets']:check(row['path'] not in present and all(v['uuid']!=row['uuid'] for v in present.values()),'coordinator deletion not observed: '+row['path'])
    check(retirement.records()[saved['id']]['coordinator']['image']==saved.get('image',retirement.records()[saved['id']]['coordinator']['image']),'coordinator used another image')
    check(retirement.finish(saved['id'])['status']=='root-retirement-complete','coordinator finish')
    check(births()[PROBE]['phase']=='retired','birth not tombstoned')
    check(Path('/boot/loader/loader.conf').read_text()==saved['before']['loader'] and Path('/boot/limine/limine.conf').read_text()==saved['before']['limine'],'loader metadata not restored exactly')
    check(native.output(['pacman','-Q'])==saved['inventory'] and native.authority_identity()==saved['authority'],'coordinator path changed packages/authority')
    STATE.unlink();restore_history(check,saved['history'])
    return {'later_boot':True,'previous_default_booted':True,'offline_deletion_observed':True,'birth_tombstoned':True,
            'coordinator_entries_removed':True,'loader_metadata_restored_exactly':True,'packages_authority_preserved':True}


def qualify(check,selection,payload=None):
    check(native.output(['pacman','-Q','enzimos-native-policy'])==VERSION,'wrong coordinator boot candidate')
    if selection in ('coordinator-stage','coordinator-build-stage'):return stage(check,payload,selection=='coordinator-build-stage')
    return finish(check)
