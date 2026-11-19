#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Combined disposable-guest controls for batched policy53 (no UI/app execution)."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import native
import backup
import backup_attempts
import backup_databases
import backup_delivery
import backup_schedule
import backup_selective
import boot_inventory

CONTROL=Path('/var/lib/enzimos-control')


def qualify(check,payload):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-53','wrong batch candidate')
    native.run(['mount','/backup-repository'])
    pause=CONTROL/'home-history.disabled';check(not pause.exists(),'history already paused');pause.touch(mode=0o600)
    native.run(['systemctl','stop','enzimos-home-history.service'])
    inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
    def refuse(action,fragment):
        try:action()
        except (native.Failure,OSError) as exc:check(fragment in str(exc),'unexpected batch refusal: '+str(exc));return
        raise AssertionError('batch negative control succeeded')
    try:
        config=backup.read_config();snapshot=max(backup.snapshots(config),key=lambda row:row['time'])['id']
        path='/backup-source/home/enzimos-admin/.var/app/org.enzimos.Fixture/hidden-data'
        result=backup_selective.export('batch-export',snapshot,path)
        content=(CONTROL/'restore-exports/batch-export/content.bin').read_bytes()
        grant=backup_delivery.grant('batch-user-file','batch-export',1001)
        refuse(lambda:backup_delivery.deliver('batch-user-file','f'*64),'stale')
        result=backup_delivery.deliver('batch-user-file',grant['grant_sha256'])
        target=Path('/home/enzimos-user')/result['filename']
        check(target.read_bytes()==content and target.stat().st_uid==1001 and target.stat().st_mode&0o777==0o600,'delivery bytes/owner/mode mismatch')
        check(subprocess.run(['runuser','-u','enzimos-admin','--','test','-r',target]).returncode!=0,'other user read delivered private bytes')
        refuse(lambda:backup_delivery.deliver('batch-user-file',grant['grant_sha256']),'stale')
        second=backup_delivery.grant('batch-existing','batch-export',1001);existing=Path('/home/enzimos-user')/second['filename']
        existing.write_bytes(b'PRESERVE-EXISTING');os.chown(existing,1001,1001)
        refuse(lambda:backup_delivery.deliver('batch-existing',second['grant_sha256']),'delivery incomplete')
        check(existing.read_bytes()==b'PRESERVE-EXISTING','delivery overwrote existing file')
        third=backup_delivery.grant('batch-stale','batch-export',1001)
        old=native.boot_id;native.boot_id=lambda:'00000000-0000-0000-0000-000000000000'
        try:refuse(lambda:backup_delivery.deliver('batch-stale',third['grant_sha256']),'boot changed')
        finally:native.boot_id=old
        dbroot=Path('/var/lib/enzimos-batch-db');dbroot.mkdir(mode=0o700);database=dbroot/'state.sqlite'
        with sqlite3.connect(database) as db:
            db.execute('PRAGMA journal_mode=WAL');db.execute('create table balances(value integer)');db.executemany('insert into balances values (?)',[(40,),(60,)])
        backup_databases.CONFIG.write_text(json.dumps({'schema':1,'sqlite':[{'name':'state','path':str(database)}]}));backup_databases.CONFIG.chmod(0o600)
        # Real automatic entry follows explicit opt-in, not a claimed calendar tick.
        backup_schedule.enable();summary=backup.backup(True);attempts=backup_attempts.records()
        check(len(attempts)==1 and next(iter(attempts.values()))['state']=='completed','automatic attempt completion missing')
        full=next(row['id'] for row in backup.snapshots(config) if row['id'].startswith(summary['snapshot_id']))
        data=backup.restic(config,['dump',full,'/backup-source/inventory/scope.json'],capture=True).stdout
        scope=json.loads(data)['sqlite_exports'];check(scope['configured'] and not scope['global_atomicity'],'database export scope missing')
        exported=Path('/run/batch-restored.sqlite')
        env=dict(PATH='/usr/bin',LANG='C.UTF-8',RESTIC_REPOSITORY=config['repository'],RESTIC_PASSWORD_FILE=config['password_file'])
        with exported.open('wb') as stream:subprocess.run(['restic','--no-cache','dump',full,'/backup-source/inventory/databases/state.sqlite'],stdout=stream,env=env,check=True)
        with sqlite3.connect(exported) as db:check(db.execute('PRAGMA integrity_check').fetchall()==[('ok',)] and db.execute('select sum(value) from balances').fetchone()==(100,),'exported database invariant failed')
        original=backup.source_layout;backup.source_layout=lambda c:(_ for _ in ()).throw(native.Failure('injected capture failure'))
        try:refuse(lambda:backup.backup(True),'injected capture failure')
        finally:backup.source_layout=original
        check(any(row['state']=='uncertain' for row in backup_attempts.records().values()),'failed attempt not uncertain')
        refuse(lambda:backup.backup(True),'no retry')
        backup_schedule.disable();check(backup.backup(True)=={'status':'disabled-no-source-scan'},'disabled backup scanned after failure')
        report=boot_inventory.collect();check(not report['complete'] and not report['execution_available'],'batch enabled retirement')
        check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'batch changed packages/authority')
        return {'private_current_user_delivery':True,'existing_file_preserved':True,'stale_grant_refused':True,
                'sqlite_export_restored_and_checked':True,'automatic_attempt_completed':True,'failed_attempt_uncertain_no_retry':True,
                'disable_no_scan':True,'calendar_firing_qualified':False,'retirement_enabled':False,'packages_authority_preserved':True}
    finally:pause.unlink()
