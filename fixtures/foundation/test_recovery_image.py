#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only new-image publication controls; fixed disk setup stays in the lab."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import native
import recovery_image as image

CONTROL=Path('/var/lib/enzimos-control')


def prepare(payload,check):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-27','wrong recovery image candidate')
    payload=Path(payload);manifest=json.loads((payload/'recovery-image-manifest.json').read_text())
    identifier=image.image_id(manifest['identity'])
    image.INPUT.mkdir(mode=0o700,parents=True,exist_ok=False)
    shutil.copyfile(payload/'recovery-image-manifest.json',image.INPUT/'manifest.json')
    # Refresh installed exactly these bytes. Publication creates NEW resources,
    # never adopts the old fixture path or replaces its still-usable recovery entry.
    shutil.copyfile('/boot/enzimos-recovery/kernel',image.INPUT/'kernel')
    shutil.copyfile('/boot/enzimos-recovery/initrd.img',image.INPUT/'initrd.img')
    line=native.entry_fields(Path('/boot/loader/entries/recovery.conf').read_text(),None)['options']
    default_before=Path('/boot/loader/loader.conf').read_bytes();bios_before=Path('/boot/limine/limine.conf').read_text()
    rejected=subprocess.run(['runuser','-u','enzimos-user','--','python','/usr/lib/enzimos/recovery_image.py','publish','--options',line],capture_output=True,text=True)
    check(rejected.returncode!=0 and 'root authorization required' in rejected.stderr,'ordinary user published recovery')
    # Preflight failure cannot create a registry intent or image destination.
    wrong=dict(manifest);wrong['files']=dict(manifest['files']);wrong['files']['kernel']=dict(manifest['files']['kernel'],sha256='f'*64)
    (image.INPUT/'manifest.json').write_text(json.dumps(wrong))
    try:image.publish(line)
    except native.Failure as exc:check('kernel descriptor mismatch' in str(exc),'wrong source mismatch refusal')
    else:raise AssertionError('incorrect recovery input accepted')
    check(not image.records() and not (Path('/boot/enzimos/recovery-images')/identifier).exists(),'failed preflight created state')
    (image.INPUT/'manifest.json').write_text(json.dumps(manifest))
    result=image.publish(line);check(result['id']==identifier,'publisher identifier mismatch')
    record_path=image.directory()/(identifier+'.json');before=native.sha(record_path)
    check(Path('/boot/loader/loader.conf').read_bytes()==default_before and native.limine_menu(Path('/boot/limine/limine.conf').read_text())[2]==native.limine_menu(bios_before)[2],'publisher changed defaults')
    try:image.publish(line)
    except native.Failure as exc:check('no adoption or replacement' in str(exc),'wrong duplicate publication refusal')
    else:raise AssertionError('existing image adopted')
    try:image.confirm_current()
    except native.Failure as exc:check('initramfs recovery' in str(exc) or 'RAM-root' in str(exc),'wrong installed confirmation refusal')
    else:raise AssertionError('installed system confirmed recovery')
    check(native.sha(record_path)==before and not image.records()[identifier]['observations'],'refusals confirmed or changed record')
    home=Path('/home/enzimos-admin/foundation-home-marker');home.write_text('NEWER-HOME-IMAGE-CONFIRMATION\n')
    native.atomic_json(CONTROL/'image-test.json',{'id':identifier,'record_sha256':before,'inventory':native.output(['pacman','-Q']),
                       'authority':native.authority_identity(),'old_recovery_sha256':native.sha('/boot/enzimos-recovery/initrd.img')})
    # Selection remains fixture-only, by stable identities on both loaders.
    native.atomic_text('/boot/loader/loader.conf',f'default {identifier}.conf\ntimeout 0\neditor no\n')
    path=Path('/boot/limine/limine.conf');text=path.read_text();number=native.limine_number(text,'enzimOS recovery '+identifier)
    native.atomic_text(path,re.sub(r'^default_entry: .*$',f'default_entry: {number}',text,flags=re.M))
    return {'publication':result,'defaults_preserved_by_publisher':True,'unprivileged_refused':True,
            'bad_source_refused_without_state':True,'duplicate_not_adopted':True,'installed_confirmation_refused':True,
            'selected_by':'lab-fixture-only','retirement_enabled':False}
