#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real lock-contention deferral recorded durably, then honoured once after reboot."""
import json
import os
from pathlib import Path
import subprocess
import time
import native
import backup
import backup_attempts
import backup_schedule as schedule
import deferred
from test_credential_review import pause_history,restore_history

import lab_versions
VERSION=lab_versions.native()
STATE=Path('/var/lib/enzimos-control/deferred-work-fixture.json')
DROPIN=Path('/etc/systemd/system/enzimos-deferred.timer.d/90-lab-boot-delay.conf')
# Test-only: owed trim and backup start together and contend for the shared lock;
# a 5 s restart (production 15 min) resolves that inside the fixture window.
RETRY=[Path('/etc/systemd/system')/(unit+'.d')/'90-lab-retry.conf' for unit in ('enzimos-trim.service','enzimos-backup.service')]
TIMERS=('enzimos-trim.timer','enzimos-scrub.timer','enzimos-backup.timer')


def enabled(unit):
    # `systemctl is-enabled` exits nonzero for disabled units; read its word, not its status.
    result=subprocess.run(['systemctl','is-enabled',unit],capture_output=True,text=True,timeout=30)
    word=result.stdout.strip();assert word in ('enabled','disabled','static','masked','linked','indirect','generated'),word
    return word


def mount_destination():
    # A fixture must borrow an existing mount rather than stack another one.
    if not os.path.ismount('/backup-repository'):native.run(['mount','/backup-repository'])


def state(unit):
    return dict(line.split('=',1) for line in native.output(['systemctl','show',unit,'--property=ActiveState,SubState,ExecMainStatus,NRestarts,ExecMainStartTimestampMonotonic']).splitlines())


def wait(check,predicate,label,seconds=240):
    end=time.monotonic()+seconds
    while not predicate():
        if time.monotonic()>=end:
            for unit in ('enzimos-trim.service','enzimos-backup.service','enzimos-deferred.service'):
                print(subprocess.run(['systemctl','status','--no-pager',unit],capture_output=True,text=True).stdout[-1500:],flush=True)
                print(subprocess.run(['journalctl','-b','--no-pager','-n','40','-u',unit],capture_output=True,text=True).stdout[-3000:],flush=True)
        check(time.monotonic()<end,'deferred work timeout: '+label);time.sleep(.5)


def owed(check):
    history=pause_history(check)
    check(enabled('enzimos-deferred.timer')=='enabled','owed-work timer not enabled by upgrade')
    timers={unit:enabled(unit) for unit in TIMERS}
    check(not deferred.markers(),'unexpected prior owed work')
    mount_destination();config=backup.read_config()
    if not Path(config['repository'],'config').exists():backup.initialize()
    check(not backup_attempts.records(),'unexpected prior automatic attempts')
    schedule.enable()
    # Isolate attribution: only the owed-work check may start these after reboot.
    native.run(['systemctl','disable','--now',*TIMERS])
    with native.operation_lock():
        for unit in ('enzimos-trim.service','enzimos-backup.service'):
            # reset-failed exits nonzero for a unit that is not loaded (timer disabled); hygiene only.
            subprocess.run(['systemctl','reset-failed',unit],capture_output=True,timeout=30);native.run(['systemctl','start','--no-block',unit])
            wait(check,lambda:state(unit)['ExecMainStatus']=='75','deferral of '+unit)
        wait(check,lambda:set(deferred.markers())=={'trim','backup'},'durable owed markers')
        # Explicit stop cancels only this boot's restart; the owed run persists.
        native.run(['systemctl','stop','enzimos-trim.service','enzimos-backup.service'])
    time.sleep(2.5)
    marks=deferred.markers();check(set(marks)=={'trim','backup'} and all(row['last_boot_id']==native.boot_id() for row in marks.values()),'owed markers lost on stop')
    check(not backup_attempts.records(),'busy automatic backup entered')
    # A same-boot resume leaves this boot's own deferrals to the unit restart policy.
    check(deferred.resume()['started']==[],'same-boot resume started work')
    DROPIN.parent.mkdir(parents=True,exist_ok=True);DROPIN.write_text('[Timer]\nOnBootSec=\nOnBootSec=1min\n')
    for path in RETRY:path.parent.mkdir(parents=True,exist_ok=True);path.write_text('[Service]\nRestartSec=5s\n')
    native.run(['systemctl','daemon-reload'])
    native.atomic_json(STATE,{'boot_id':native.boot_id(),'markers':marks,'timers':timers,'history':history,
                              'points':sorted(row['id'] for row in backup.snapshots(config))})
    os.sync()
    return {'lock_refusals_recorded_durably':True,'explicit_stop_keeps_owed_run':True,'busy_backup_not_entered':True,
            'same_boot_resume_noop':True,'timers_isolated_for_attribution':True}


def resumed(check):
    saved=json.loads(STATE.read_text());check(saved['boot_id']!=native.boot_id(),'later boot required')
    mount_destination();config=backup.read_config()
    unit='enzimos-deferred.service'
    wait(check,lambda:state(unit)['ActiveState']=='inactive' and state(unit)['ExecMainStatus']=='0' and 'deferred-work-resumed' in native.output(['journalctl','-b','-u',unit,'--no-pager']),'boot owed-work check',420)
    log=native.output(['journalctl','-b','-u',unit,'--no-pager','-o','cat'])
    started=[json.loads(line)['started'] for line in log.splitlines() if line.startswith('{') and 'deferred-work-resumed' in line]
    check(started==[['backup','trim']],'owed-work check did not start exactly the owed units once')
    for service in ('enzimos-trim.service','enzimos-backup.service'):
        # systemd garbage-collects a finished static oneshot unit (its properties reset),
        # so completion is read from this boot's journal, not from unit properties.
        journal=lambda:native.output(['journalctl','-b','--no-pager','-o','cat','-u',service])
        wait(check,lambda:'Deactivated successfully.' in journal() or 'Failed with result' in journal(),service+' completion',1800)
        text=journal();check('Deactivated successfully.' in text and 'Failed with result' not in text,'owed '+service+' failed')
    check(deferred.markers()=={},'completed owed runs left markers')
    attempts=backup_attempts.records();points=sorted(row['id'] for row in backup.snapshots(config))
    check(len(attempts)==1 and all(row['state']=='completed' for row in attempts.values()) and len(set(points)-set(saved['points']))==1,'owed backup did not complete exactly once')
    # A second check this boot has nothing owed.
    check(deferred.resume()['started']==[],'resume repeated completed work')
    # Explicit clear removes an owed run without starting anything; revoked opt-in voids backup.
    deferred.record('scrub');check(deferred.clear('scrub') and deferred.markers()=={},'explicit owed-run clear')
    deferred.record('backup');schedule.disable()
    check(backup.backup(True)=={'status':'disabled-no-source-scan'} and deferred.markers()=={},'revoked opt-in kept owed backup')
    DROPIN.unlink();DROPIN.parent.rmdir()
    for path in RETRY:path.unlink();path.parent.rmdir()
    native.run(['systemctl','daemon-reload'])
    for timer,value in saved['timers'].items():
        if value=='enabled':native.run(['systemctl','enable',timer])
    STATE.unlink();restore_history(check,saved['history'])
    return {'later_boot':True,'owed_units_started_once':True,'owed_trim_completed':True,'owed_backup_completed_once':True,
            'markers_cleared_on_entry':True,'explicit_clear':True,'revoked_opt_in_voids_owed_backup':True,
            'guards_bypassed':False,'failures_retried':False,'physical_power_loss':False}


def qualify(check,selection):
    check(native.output(['pacman','-Q','enzimos-native-policy'])==VERSION,'wrong deferred-work candidate')
    return owed(check) if selection=='deferred-owed' else resumed(check)
