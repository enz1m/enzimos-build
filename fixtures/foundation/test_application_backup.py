#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real SQLite WAL and OSTree/Flatpak deployment consistency inside the guest."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import threading
import time
import native
import backup

BASE=Path('/var/lib/enzimos-persistent/application-test')


def qualify(check,payload):
    payload=Path(payload);native.run(['mount','/backup-repository']);authority=native.authority_identity()
    # Normal signed dependency checking; do not install a desktop or start UI.
    plan=json.loads((payload/'clean-builder-plan.json').read_text());expected={row['name']:row['version'] for row in plan['packages']}
    check('flatpak' in expected and len(expected)<128,'closed application dependency increment required')
    keys=Path('/run/app-backup-admission');keys.mkdir(mode=0o700)
    for name in ('pubring.gpg','trustdb.gpg','gpg.conf'):shutil.copyfile(payload/'builder-public-keys'/name,keys/name)
    config=Path('/run/app-backup-pacman.conf');config.write_text('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n')
    packages=[]
    for row in plan['packages']:
        p=payload/'builder-packages'/row['url'].rsplit('/',1)[-1];check(native.sha(p)==row['sha256_from_metadata'],'application package bytes changed');packages.append(p)
    native.run(['pacman','--config',config,'--gpgdir',keys,'--noconfirm','-U',*packages])
    check(native.authority_identity()==authority,'application install changed authority')
    BASE.mkdir(mode=0o700);database=BASE/'ledger.sqlite'
    db=sqlite3.connect(database);db.executescript('PRAGMA journal_mode=WAL; CREATE TABLE balance(id INTEGER PRIMARY KEY, amount INTEGER); INSERT INTO balance VALUES(1,100),(2,100); CREATE TABLE sequence(n INTEGER); INSERT INTO sequence VALUES(0);');db.commit()
    stopped=threading.Event();ready=threading.Event();failures=[]
    def writer():
        connection=sqlite3.connect(database)
        try:
            while not stopped.is_set():
                connection.execute('BEGIN IMMEDIATE');connection.execute('UPDATE balance SET amount=amount-1 WHERE id=1');connection.execute('UPDATE balance SET amount=amount+1 WHERE id=2');connection.execute('UPDATE sequence SET n=n+1');connection.commit();ready.set();time.sleep(.02)
        except Exception as exc:failures.append(type(exc).__name__)
        finally:connection.close()
    thread=threading.Thread(target=writer);thread.start();check(ready.wait(5),'database writer did not start')
    export=BASE/'online-export.sqlite';output=sqlite3.connect(export)
    # Supported SQLite online backup API; no raw copy of a live WAL database.
    deadline=time.monotonic()+30
    def progress(status,remaining,total):check(time.monotonic()<deadline,'database export deadline')
    try:db.backup(output,pages=32,progress=progress,sleep=.01)
    finally:output.close();stopped.set();thread.join(5);db.close()
    check(not thread.is_alive() and not failures,'database writer failed')
    check_database=sqlite3.connect(export)
    check(check_database.execute('PRAGMA integrity_check').fetchone()==('ok',),'online SQLite export corrupt')
    check(check_database.execute('SELECT sum(amount) FROM balance').fetchone()==(200,),'online export crossed transaction')
    sequence=check_database.execute('SELECT n FROM sequence').fetchone()[0];check(sequence>0,'export missed all committed writes');check_database.close()
    # A real system Flatpak deployment from an original local fixture. A tiny
    # original runtime contains no third-party payload and is never launched.
    repo=BASE/'flatpak-repo';runtime=BASE/'runtime';(runtime/'usr').mkdir(parents=True);(runtime/'files').mkdir()
    (runtime/'metadata').write_text('[Runtime]\nname=org.enzimos.BackupRuntime\nruntime=org.enzimos.BackupRuntime/x86_64/test\n')
    (runtime/'usr/enzimos-runtime-marker').write_text('runtime-v1\n')
    native.run(['flatpak','build-finish',runtime])
    app=BASE/'application';(app/'files/bin').mkdir(parents=True)
    (app/'metadata').write_text('[Application]\nname=org.enzimos.BackupProbe\nruntime=org.enzimos.BackupRuntime/x86_64/test\ncommand=probe\n')
    (app/'files/bin/probe').write_text('#!/bin/sh\nprintf "backup fixture\\n"\n');(app/'files/bin/probe').chmod(0o755)
    native.run(['flatpak','build-finish',app])
    # Fresh LAB signing key in guest RAM: local Flatpak content remains verified.
    signing=Path('/run/app-backup-flatpak-signing');signing.mkdir(mode=0o700)
    native.run(['gpg','--homedir',signing,'--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key','enzimOS DISPOSABLE Flatpak backup','ed25519','sign','1d'])
    fingerprint=next(line.split(':')[9] for line in native.output(['gpg','--homedir',signing,'--with-colons','--list-keys']).splitlines() if line.startswith('fpr:'))
    for build,extra in ((runtime,['--runtime']),(app,[])):
        native.run(['flatpak','build-export',*extra,'--arch=x86_64','--gpg-sign='+fingerprint,'--gpg-homedir='+str(signing),repo,build,'test'])
    public=Path('/run/app-backup-flatpak-public.gpg');public.write_bytes(subprocess.check_output(['gpg','--homedir',str(signing),'--export']))
    native.run(['flatpak','build-update-repo','--gpg-sign='+fingerprint,'--gpg-homedir='+str(signing),repo])
    native.run(['flatpak','remote-add','--system','--no-enumerate','--gpg-import='+str(public),'enzimos-backup-lab',str(repo)])
    native.run(['flatpak','install','--system','--noninteractive','enzimos-backup-lab','org.enzimos.BackupRuntime//test','org.enzimos.BackupProbe//test'])
    app_commit=native.output(['flatpak','info','--system','--show-commit','org.enzimos.BackupProbe//test'])
    runtime_commit=native.output(['flatpak','info','--system','--show-commit','org.enzimos.BackupRuntime//test'])
    check(len(app_commit)==64 and len(runtime_commit)==64,'real Flatpak commits unavailable')
    # Stop writers before the current generic source capture: this test qualifies
    # quiescent actual deployment fidelity, not an unimplemented global Flatpak lock.
    inventory=native.output(['pacman','-Q']);result=backup.backup();point=result['snapshot_id']
    native.atomic_json(Path('/var/lib/enzimos-control/application-backup.json'),{'snapshot_prefix':point,'sqlite_sequence':sequence,
        'sqlite_sha256':native.sha(export),'app_commit':app_commit,'runtime_commit':runtime_commit,'inventory':inventory})
    backup.restic(backup.read_config(),['check','--read-data'])
    # Byte restoration is staged using restic dump, not an assumed path inventory.
    c=backup.read_config();restored=BASE/'restored-export.sqlite'
    env=dict(PATH='/usr/bin',LANG='C.UTF-8',HOME='/nonexistent',RESTIC_REPOSITORY=c['repository'],RESTIC_PASSWORD_FILE=c['password_file'],GOMAXPROCS='1')
    with restored.open('xb') as stream:subprocess.run(['restic','--no-cache','dump',point,'/backup-source/additional/appdata/application-test/online-export.sqlite'],stdout=stream,env=env,check=True)
    check(native.sha(restored)==native.sha(export),'backed-up database bytes differ')
    restored_db=sqlite3.connect(restored);check(restored_db.execute('PRAGMA integrity_check').fetchone()==('ok',),'restored SQLite corruption');check(restored_db.execute('SELECT sum(amount) FROM balance').fetchone()==(200,),'restored DB transaction mismatch');restored_db.close()
    # Full Flatpak installation copied from backup into a private new directory;
    # use an explicit installation path, never change live deployment selectors.
    flatpak_stage=BASE/'restored-flatpak';flatpak_stage.mkdir()
    subprocess.run(['restic','--no-cache','restore',point,'--target',str(flatpak_stage),'--include','/backup-source/system/var/lib/flatpak','--verify'],env=env,check=True)
    installation=flatpak_stage/'backup-source/system/var/lib/flatpak'
    native.run(['ostree','--repo='+str(installation/'repo'),'fsck'])
    restored_env=dict(os.environ,FLATPAK_SYSTEM_DIR=str(installation),FLATPAK_SYSTEM_CACHE_DIR='/run/flatpak-restore-cache')
    for ref,expected_commit in (('org.enzimos.BackupProbe//test',app_commit),('org.enzimos.BackupRuntime//test',runtime_commit)):
        observed=subprocess.check_output(['flatpak','info','--system','--show-commit',ref],env=restored_env,text=True).strip();check(observed==expected_commit,'restored Flatpak deployment commit differs')
    check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'application backup changed inventory/authority')
    return {'sqlite_online_backup_under_writer':True,'sqlite_transaction_consistent_after_restic_restore':True,
            'actual_signed_flatpak_app_and_runtime':True,'restored_ostree_fsck':True,'exact_deployment_commits_restored':True,
            'flatpak_concurrent_transaction_lock':False,'apps_executed':False,'ui_qualified':False,'authority_preserved':True}
