#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real automatic backup admission retry; entered failures never replay."""
import json
from pathlib import Path
import subprocess
import time
import backup
import backup_attempts
import backup_schedule as schedule
import native
from test_credential_review import pause_history,restore_history


def qualify(check):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-60','wrong backup deferral candidate')
    inventory=native.output(['pacman','-Q']);authority=native.authority_identity();history=pause_history(check)
    unit='enzimos-backup.service';dropin=Path('/run/systemd/system')/(unit+'.d')/'90-lab-retry-delay.conf'
    config_path=Path('/etc/enzimos/backup.json');original=config_path.read_bytes();db_lock=Path('/var/lib/pacman/db.lck');owned_lock=False
    def state():return dict(line.split('=',1) for line in native.output(['systemctl','show',unit,'--property=ActiveState,SubState,ExecMainStatus,NRestarts,InvocationID']).splitlines())
    def wait(predicate,label,seconds=240):
        end=time.monotonic()+seconds
        while not predicate():check(time.monotonic()<end,'backup retry timeout: '+label);time.sleep(.5)
    def deferred():
        text=native.output(['journalctl','-b','--unit',unit,'--output=json','--no-pager']);check(len(text)<512*1024,'backup journal bound')
        return sum('"status": "deferred"' in json.loads(line).get('MESSAGE','') for line in text.splitlines())
    def points():return {row['id'] for row in backup.snapshots(backup.read_config())}
    def start():native.run(['systemctl','reset-failed',unit]);native.run(['systemctl','start','--no-block',unit])
    def failure(label):
        wait(lambda:state()['ActiveState']=='failed',label);failed=state();time.sleep(2.5)
        check(failed==state() and failed['ExecMainStatus'] not in ('0','75'),'entered/error backup retried')
    try:
        check(not schedule.marker().exists(),'unexpected prior opt-in')
        native.run(['mount','/backup-repository']);config=backup.read_config()
        if not Path(config['repository'],'config').exists():backup.initialize()
        before=points();attempts=backup_attempts.records();check(not attempts,'unexpected prior automatic attempts')
        check(native.output(['systemctl','show',unit,'--value','--property=RestartUSec'])=='15min','wrong packaged retry delay')
        check(native.output(['systemctl','show',unit,'--value','--property=Restart'])=='no','generic backup retries enabled')
        check(native.output(['systemctl','show',unit,'--value','--property=RestartMode'])=='direct','wrong restart mode')
        dropin.parent.mkdir(parents=True);dropin.write_text('[Service]\nRestartSec=1s\n');native.run(['systemctl','daemon-reload'])
        schedule.enable()
        with native.operation_lock():
            seen=deferred();start();wait(lambda:deferred()>=seen+2,'busy twice')
            check(state()['ExecMainStatus']=='75' and not backup_attempts.records(),'busy attempt entered durable backup')
            check(points()==before,'busy backup changed repository')
            schedule.disable();seen=deferred();wait(lambda:state()['ActiveState']=='inactive','revocation cancels next entry')
            time.sleep(2.5);check(deferred()==seen and not backup_attempts.records(),'disabled work retried or entered')
        schedule.enable()
        with native.operation_lock():
            seen=deferred();start();wait(lambda:deferred()>seen,'explicit stop busy');native.run(['systemctl','stop',unit]);stopped=state()
        time.sleep(2.5);check(state()==stopped and points()==before and not backup_attempts.records(),'stopped backup entered')
        with native.operation_lock():
            seen=deferred();start();wait(lambda:deferred()>seen,'release busy')
        # One vCPU, Nice=10 and idle I/O make a full encrypted backup slow; bound, not speed.
        released=time.monotonic();wait(lambda:state()['ActiveState'] in ('inactive','failed'),'one backup completion',1500)
        backup_seconds=round(time.monotonic()-released,1)
        check(state()['ExecMainStatus']=='0' and state()['ActiveState']=='inactive','backup after release failed')
        completed=backup_attempts.records();after=points()
        check(len(completed)==1 and all(row['state']=='completed' for row in completed.values()) and len(after-before)==1,'backup did not complete exactly once')
        time.sleep(2.5);check(backup_attempts.records()==completed and points()==after,'success retried')
        backup.restic(backup.read_config(),['check','--read-data'])
        changed=json.loads(original);changed['keep_last']=7 if changed.get('keep_last')!=7 else 8;config_path.write_text(json.dumps(changed))
        try:start();failure('config drift');check(backup_attempts.records()==completed,'config drift entered backup')
        finally:config_path.write_bytes(original)
        # A real error after the durable attempt is entered must remain uncertain.
        check(not db_lock.exists(),'package database already locked');db_lock.write_text('ENZIMOS disposable failure control\n');owned_lock=True
        start();failure('entered package lock failure');uncertain=backup_attempts.records()
        check(len(uncertain)==2 and sum(row['state']=='uncertain' for row in uncertain.values())==1,'entered error lost uncertain receipt')
        db_lock.unlink();owned_lock=False
        start();failure('uncertain retry refusal');check(backup_attempts.records()==uncertain and points()==after,'uncertain backup replayed')
        check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'backup changed packages/authority')
        return {'busy_before_attempt':True,'revocation_prevents_retry_entry':True,'explicit_stop_cancels_retry':True,
                'one_encrypted_backup_after_release':True,'repository_data_checked':True,'config_drift_no_retry':True,
                'entered_failure_no_retry':True,'uncertain_attempt_preserved_no_replay':True,'packages_authority_preserved':True,
                'production_retry_seconds':900,'backup_after_release_seconds':backup_seconds,'test_retry_seconds':1,'retry_survives_reboot':False,'calendar_firing_qualified':False}
    finally:
        native.run(['systemctl','stop',unit]);schedule.disable();config_path.write_bytes(original)
        if owned_lock:db_lock.unlink()
        if dropin.exists():dropin.unlink();dropin.parent.rmdir()
        native.run(['systemctl','daemon-reload']);native.run(['systemctl','reset-failed',unit]);restore_history(check,history)


def review(check):
    """Later boot must retain the entered failure and refuse automatic replay."""
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-60','wrong backup review candidate')
    history=pause_history(check);inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
    unit='enzimos-backup.service'
    try:
        native.run(['mount','/backup-repository']);records=backup_attempts.records()
        check(len(records)==2 and sorted(row['state'] for row in records.values())==['completed','uncertain'],'wrong retained attempt set')
        check(all(row['boot_id']!=native.boot_id() for row in records.values()),'review did not cross boot')
        before={row['id'] for row in backup.snapshots(backup.read_config())}
        check(not schedule.marker().exists(),'disabled schedule unexpectedly enabled after boot')
        check(backup.backup(True)=={'status':'disabled-no-source-scan'},'disabled backup entered after boot')
        schedule.enable();native.run(['systemctl','reset-failed',unit]);native.run(['systemctl','start','--no-block',unit])
        deadline=time.monotonic()+90
        def state():return dict(line.split('=',1) for line in native.output(['systemctl','show',unit,'--property=ActiveState,SubState,ExecMainStatus,NRestarts,InvocationID']).splitlines())
        while state()['ActiveState']!='failed':check(time.monotonic()<deadline,'uncertain review did not refuse');time.sleep(.5)
        failed=state();time.sleep(2.5)
        check(failed==state() and failed['ExecMainStatus'] not in ('0','75') and failed['NRestarts']=='0','uncertain review scheduled replay')
        check(backup_attempts.records()==records and {row['id'] for row in backup.snapshots(backup.read_config())}==before,'retained uncertain backup replayed')
        check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'review changed packages/authority')
        return {'past_boot_attempts':True,'disabled_no_entry':True,'uncertain_service_refused':True,
                'attempts_unchanged':True,'repository_points_unchanged':True,'packages_authority_preserved':True,
                'automatic_replay':False,'calendar_firing_qualified':False}
    finally:
        native.run(['systemctl','stop',unit]);schedule.disable();native.run(['systemctl','reset-failed',unit]);restore_history(check,history)
