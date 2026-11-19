#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Actual restic single-file export, no writes into a user's live destination."""
import json
import os
from pathlib import Path
import subprocess
import backup
import backup_selective as selective
import native


def qualify(check):
    pause=Path('/var/lib/enzimos-control/home-history.disabled');check(not pause.exists(),'fixture history already paused')
    pause.touch(mode=0o600)
    native.run(['systemctl','stop','enzimos-home-history.service'])
    try:return run_export(check)
    finally:pause.unlink()


def run_export(check):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-52','wrong selective candidate')
    native.run(['mount','/backup-repository']);config=backup.read_config();rows=backup.snapshots(config)
    snapshot=next(row['id'] for row in rows if row['id'].startswith(Path('/var/lib/enzimos-control/backup-snapshot').read_text()))
    # This branch was recaptured after the original history test changed its
    # home marker. Use the separately preserved, known hidden-file fixture.
    path='/backup-source/home/enzimos-admin/.var/app/org.enzimos.Fixture/hidden-data'
    live=Path('/home/enzimos-admin/.var/app/org.enzimos.Fixture/hidden-data')
    check(live.read_bytes()==b'hidden-home-in-backup\n','hidden-file fixture changed')
    live.write_bytes(b'NEWER-LIVE-HIDDEN-DATA\n');current=live.read_bytes();inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
    with native.operation_lock():
        try:selective.export('blocked-export',snapshot,path)
        except native.Failure as exc:check('owns the lock' in str(exc),'wrong lock refusal')
        else:raise AssertionError('selective export ignored lock')
    result=selective.export('file-preview',snapshot,path)
    folder=Path('/var/lib/enzimos-control/restore-exports/file-preview');content=folder/'content.bin'
    check(content.read_bytes()==b'hidden-home-in-backup\n','wrong historical file bytes')
    check(content.stat().st_uid==0 and content.stat().st_mode&0o777==0o600,'export restored unsafe historic mode/owner')
    check(folder.stat().st_mode&0o777==0o700,'private export directory mode')
    def refuse(identifier,name):
        try:selective.export(identifier,snapshot,name)
        except native.Failure:return
        raise AssertionError('selective invalid operation succeeded')
    before=content.read_bytes();refuse('file-preview',path);check(content.read_bytes()==before,'duplicate export overwrote stage')
    refuse('directory','/backup-source/home/enzimos-admin/.local')
    refuse('escape','/backup-source/home/enzimos-admin/../enzimos-user/data')
    refuse('system','/backup-source/system/etc/shadow')
    for user in ('enzimos-admin','enzimos-user'):
        denied=subprocess.run(['runuser','-u',user,'--','python','/usr/lib/enzimos/backup_selective.py','--id','user-probe','--snapshot',snapshot,'--path',path],capture_output=True,text=True)
        check(denied.returncode!=0 and 'root authorization required' in denied.stderr,'ordinary user bypassed export authorization')
        check(subprocess.run(['runuser','-u',user,'--','test','-r',str(content)]).returncode!=0,'ordinary user read private export')
    check(live.read_bytes()==current and native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'selective export changed live state')
    check(result['live_home_written'] is False and result['metadata_restored'] is False and result['per_user_authorized'] is False,'export overclaim')
    return {'actual_historical_bytes':True,'private_root_stage':True,'duplicate_stage_preserved':True,'nonfile_and_traversal_refused':True,
            'ordinary_users_denied':True,'operation_lock_refused':True,'live_home_packages_authority_preserved':True,'per_user_restore_api':False,'historical_metadata_applied':False}
