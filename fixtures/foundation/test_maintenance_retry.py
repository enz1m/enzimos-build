#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only systemd maintenance retry/stop/error controls on owned storage."""
import json
from pathlib import Path
import subprocess
import time
import native
from test_credential_review import pause_history,restore_history


def qualify(check):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-59','wrong maintenance candidate')
    inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
    config=Path('/etc/enzimos/storage.json');before=config.read_bytes()
    schedule=pause_history(check)
    units=('enzimos-trim.service','enzimos-scrub.service')
    timers=('enzimos-trim.timer','enzimos-scrub.timer')
    active={u:subprocess.run(['systemctl','is-active','--quiet',u]).returncode==0 for u in timers}
    dropins=[];details={}
    def state(unit):
        raw=native.output(['systemctl','show',unit,'--property=ActiveState,SubState,ExecMainStatus,NRestarts,InvocationID'])
        return dict(line.split('=',1) for line in raw.splitlines())
    def wait(predicate,label,seconds=150):
        end=time.monotonic()+seconds
        while not predicate():
            check(time.monotonic()<end,'maintenance timeout: '+label);time.sleep(.5)
    def messages(unit):
        result=native.output(['journalctl','-b','--unit',unit,'--output=json','--no-pager'])
        check(len(result)<256*1024,'maintenance journal bound')
        return [row.get('MESSAGE','') for row in (json.loads(line) for line in result.splitlines())]
    def count(unit,status):
        return sum(isinstance(row,str) and '"status": "'+status+'"' in row for row in messages(unit))
    try:
        native.run(['systemctl','stop',*timers])
        for unit in units:
            wait(lambda:state(unit)['SubState'] in ('dead','failed','auto-restart'),unit+' existing maintenance')
            if state(unit)['SubState']=='auto-restart':native.run(['systemctl','stop',unit])
            check(native.output(['systemctl','show',unit,'--value','--property=RestartUSec'])=='15min','packaged retry delay differs')
            check(native.output(['systemctl','show',unit,'--value','--property=Restart'])=='no','generic failures would retry')
            check(native.output(['systemctl','show',unit,'--value','--property=RestartMode'])=='direct','deferred maintenance enters failed state')
            directory=Path('/run/systemd/system')/(unit+'.d');directory.mkdir(mode=0o755,parents=True)
            path=directory/'90-lab-retry-delay.conf';path.write_text('[Service]\nRestartSec=1s\n');dropins.append(path)
        native.run(['systemctl','daemon-reload'])
        for unit in units:
            native.run(['systemctl','reset-failed',unit])
            start_deferred=count(unit,'deferred');start_completed=count(unit,'completed')
            with native.operation_lock():
                native.run(['systemctl','start','--no-block',unit])
                wait(lambda:count(unit,'deferred')>=start_deferred+2,unit+' two busy attempts')
                current=state(unit)
                check(current['ExecMainStatus']=='75' and current['ActiveState']=='activating','busy service not deferred')
                check(count(unit,'completed')==start_completed,'busy maintenance completed an effect')
                try:
                    with native.operation_lock():pass
                except native.OperationBusy:pass
                else:raise AssertionError('retry released another owner lock')
            wait(lambda:state(unit)['ActiveState']=='inactive' and count(unit,'completed')==start_completed+1,unit+' completion after release')
            check(state(unit)['ExecMainStatus']=='0','maintenance after release failed')
            # Explicit stop must cancel automatic retries, including after release.
            start_deferred=count(unit,'deferred')
            native.run(['systemctl','reset-failed',unit])
            with native.operation_lock():
                native.run(['systemctl','start','--no-block',unit])
                wait(lambda:count(unit,'deferred')>start_deferred,unit+' stop control busy')
                native.run(['systemctl','stop',unit]);stopped=state(unit);seen=count(unit,'deferred')
                time.sleep(2.5)
                check(state(unit)==stopped and count(unit,'deferred')==seen,'stopped maintenance retried while busy')
            time.sleep(2.5)
            check(state(unit)==stopped and count(unit,'completed')==start_completed+1,'stopped maintenance ran after release')
            # A storage binding error is a failure, never TEMPFAIL/retry.
            changed=json.loads(before);changed['filesystem_uuid']='00000000-0000-0000-0000-000000000000'
            native.run(['systemctl','reset-failed',unit])
            config.write_text(json.dumps(changed)+'\n')
            try:
                native.run(['systemctl','start','--no-block',unit])
                wait(lambda:state(unit)['ActiveState']=='failed',unit+' foreign storage refusal')
                failed=state(unit);time.sleep(2.5)
                check(failed['ExecMainStatus'] not in ('0','75') and state(unit)==failed,'storage error automatically retried')
                check(count(unit,'completed')==start_completed+1,'foreign storage reached maintenance effect')
            finally:config.write_bytes(before)
            native.run(['systemctl','reset-failed',unit])
            details[unit]={'busy_deferred':True,'repeated_busy_lock_preserved':True,'one_completion_after_release':True,
                           'explicit_stop_cancels_retry':True,'wrong_filesystem_failed_without_retry':True}
        check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'maintenance changed packages/authority')
        return {'units':details,'packages_authority_preserved':True,'production_retry_seconds':900,
                'test_retry_seconds':1,'retirement_enabled':False}
    finally:
        native.run(['systemctl','stop',*units]);config.write_bytes(before)
        for path in dropins:path.unlink();path.parent.rmdir()
        native.run(['systemctl','daemon-reload']);native.run(['systemctl','reset-failed',*units])
        restore_history(check,schedule)
        for unit in timers:
            if active[unit]:native.run(['systemctl','start',unit])
