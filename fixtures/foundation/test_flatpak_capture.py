#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Contend actual Flatpak uninstall against packaged deployment locks, then capture."""
import json
import os
from pathlib import Path
import subprocess
import time
import native
import backup
import flatpak_capture


def qualify(check):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-52','wrong Flatpak capture candidate')
    native.run(['mount','/backup-repository']);reference='org.enzimos.BackupProbe//test'
    before=native.output(['flatpak','info','--system','--show-commit',reference]);authority=native.authority_identity();inventory=native.output(['pacman','-Q'])
    with flatpak_capture.system_capture():
        child=subprocess.Popen(['flatpak','uninstall','--system','--noninteractive',reference],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        try:
            time.sleep(3);check(child.poll() is None,'real Flatpak transaction did not block')
            check(native.output(['flatpak','info','--system','--show-commit',reference])==before,'locked deployment changed')
        finally:
            os.killpg(child.pid,15);child.communicate(timeout=10)
        try:
            with flatpak_capture.system_capture():pass
        except native.Failure as exc:check('lock busy' in str(exc),'wrong repeated lock refusal')
        else:raise AssertionError('second lock owner admitted')
    with flatpak_capture.system_capture():pass
    capture_calls=[];original=backup.snap
    def snap(*args,**kwargs):
        try:
            with flatpak_capture.system_capture():pass
        except native.Failure as exc:check('lock busy' in str(exc),'capture lock not held')
        else:raise AssertionError('snapshot occurred without system Flatpak locks')
        capture_calls.append(args[0]);return original(*args,**kwargs)
    original_restic=backup.restic;released=[]
    def restic(config,args,**kwargs):
        if args[:1]==['backup']:
            with flatpak_capture.system_capture():released.append(True)
        return original_restic(config,args,**kwargs)
    backup.snap=snap;backup.restic=restic
    try:result=backup.backup()
    finally:backup.snap=original;backup.restic=original_restic
    check(capture_calls==['root','home','appdata'] and released==[True],'capture/transfer lock boundary wrong')
    check(native.output(['flatpak','info','--system','--show-commit',reference])==before,'backup changed live deployment')
    check(native.authority_identity()==authority and native.output(['pacman','-Q'])==inventory,'Flatpak capture changed packages/authority')
    backup.restic(backup.read_config(),['check'])
    return {'real_flatpak_uninstall_blocked':True,'deployment_preserved':True,'lock_contention_refused':True,
            'all_source_snapshots_under_locks':True,'transfer_after_release':True,'repository_checked':True,
            'packages_authority_preserved':True,'user_installations_or_raw_ostree_serialized':False}
