#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only native pacman contention during real snapshot-backed capture."""
import json
from pathlib import Path
import subprocess

import backup
import native


def qualify(check):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-37','wrong package capture candidate')
    native.run(['mount','/backup-repository'])
    before=native.output(['pacman','-Q']);authority=native.authority_identity();lock=Path('/var/lib/pacman/db.lck')
    check(not lock.exists(),'preexisting package transaction')
    # A second ordinary signed pacman install must fail at libalpm's native lock,
    # before any transaction/hook. Never remove or overwrite another owner's lock.
    package=Path('/var/lib/enzimos-control/native-policy.pkg.tar.zst')
    with backup.package_capture_lock():
        inode=lock.stat().st_ino
        competing=subprocess.run(['pacman','-U','--noconfirm',str(package)],capture_output=True,text=True)
        check(competing.returncode!=0 and 'unable to lock database' in competing.stderr,'competing pacman not refused by actual lock')
        try:
            with backup.package_capture_lock():raise AssertionError('second native lock acquired')
        except native.Failure as exc:check('capture lock unavailable' in str(exc),'wrong second lock failure')
        check(lock.stat().st_ino==inode,'failed contender removed/replaced existing lock')
    check(not lock.exists(),'owned package lock not released')
    real_snap=backup.snap;real_restic=backup.restic;events=[]
    def snapshot(*args,**kwargs):
        check(lock.exists(),'source snapshot captured outside package lock');events.append('snapshot')
        return real_snap(*args,**kwargs)
    def restic(c,args,**kwargs):
        if args[0]=='backup':check(not lock.exists(),'bulk transfer holds package lock');events.append('transfer')
        return real_restic(c,args,**kwargs)
    backup.snap=snapshot;backup.restic=restic
    try:summary=backup.backup()
    finally:backup.snap=real_snap;backup.restic=real_restic
    check(events.count('snapshot')==3 and events[-1]=='transfer','capture/transfer order missing')
    c=backup.read_config();identifier=summary['snapshot_id']
    listing=backup.restic(c,['ls','--json',identifier],capture=True).stdout
    paths=[json.loads(line).get('path') for line in listing.splitlines()]
    check('/backup-source/system/var/lib/pacman/db.lck' not in paths,'captured lock would block future restored updates')
    check('/backup-source/system/etc/enzimos/backup.password' not in paths,'credential exclusion regressed')
    backup.restic(c,['check','--read-data'])
    check(native.output(['pacman','-Q'])==before and native.authority_identity()==authority,'contention changed installed packages/authority')
    check(not lock.exists(),'capture left package lock after success')
    return {'real_pacman_transaction_refused':True,'contender_preserved_existing_lock':True,'snapshot_capture_locked':True,
            'transfer_released_lock':True,'captured_lock_and_credential_excluded':True,'encrypted_repository_checked':True,
            'packages_current_authority_preserved':True,'flatpak_atomic_capture_qualified':False}
