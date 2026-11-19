#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Packaged maintenance/history timers fire from their real OnCalendar schedules.

calendar-firing: with chronyd stopped, the guest clock jumps to just before each timer's
next elapse (hourly home history, weekly trim, monthly scrub) and the service must
complete from that timer; the clock is then restored and trim's persistent stamp is
backdated. calendar-persistent: the next boot must catch up the missed trim run
(Persistent=true). Lab-only drop-ins set RandomizedDelaySec=0; OnCalendar/Persistent
are the packaged values. Guest clock only; no host time, NTP or RTC change.
"""
import json
import os
from pathlib import Path
import subprocess
import time
import native

import lab_versions
VERSION=lab_versions.native()
ORDER=(('enzimos-home-history.timer','enzimos-home-history.service'),('enzimos-trim.timer','enzimos-trim.service'),('enzimos-scrub.timer','enzimos-scrub.service'))
DROPINS=[Path('/etc/systemd/system')/(timer+'.d')/'90-lab-no-random-delay.conf' for timer,_ in ORDER]
STAMP=Path('/var/lib/systemd/timers/stamp-enzimos-trim.timer')
STATE=Path('/var/lib/enzimos-control/calendar-fixture.json')


def show(unit,prop):
    return native.output(['systemctl','show','--timestamp=unix','--value','--property='+prop,unit])


def unix(value):
    if not value or value=='n/a':return None
    return int(value.lstrip('@').split('.')[0])


def completions(service):
    """Successful start jobs of this unit in this boot's journal (static units are GC'd)."""
    rows=subprocess.run(['journalctl','-b','--no-pager','-o','json','-u',service],capture_output=True,text=True,timeout=60).stdout.splitlines()
    done=failed=0
    for line in rows:
        item=json.loads(line)
        if item.get('JOB_TYPE')=='start' and item.get('JOB_RESULT')=='done':done+=1
        if 'Failed with result' in item.get('MESSAGE',''):failed+=1
    return done,failed


def wait(check,predicate,label,seconds):
    end=time.monotonic()+seconds
    while not predicate():
        if time.monotonic()>=end:print(subprocess.run(['journalctl','-b','--no-pager','-n','60'],capture_output=True,text=True).stdout[-4000:],flush=True)
        check(time.monotonic()<end,'calendar timeout: '+label);time.sleep(1)


def firing(check):
    for timer,_ in ORDER:check(native.output(['systemctl','is-enabled',timer])=='enabled','packaged timer not enabled: '+timer)
    for path in DROPINS:path.parent.mkdir(exist_ok=True);path.write_text('[Timer]\nRandomizedDelaySec=0\n')
    native.run(['systemctl','daemon-reload'])
    # Timers share the operation lock (contention defers trim/scrub by design). Test each in
    # isolation: only the timer under test is active, every service idle before the jump.
    for timer,_ in ORDER:native.run(['systemctl','stop',timer])
    chrony=subprocess.run(['systemctl','is-active','--quiet','chronyd']).returncode==0
    native.run(['systemctl','stop','chronyd'])
    wall=time.time();mono=time.monotonic();fired={}
    try:
        for timer,service in ORDER:
            # A started Persistent= timer may catch up at once; let that run finish first so
            # only a trigger at the calendar elapse itself can satisfy the checks below.
            idle=lambda:show(service,'ActiveState') not in ('active','activating','deactivating')
            quiet=lambda:all(show(other,'ActiveState') not in ('active','activating','deactivating') for _,other in ORDER)
            for other,_ in ORDER:
                if other!=timer:native.run(['systemctl','stop',other])
            wait(check,quiet,'all maintenance/history services idle',1800)
            native.run(['systemctl','start',timer]);wait(check,quiet,service+' catch-up settled',1800)
            target=unix(show(timer,'NextElapseUSecRealtime'));check(target is not None and target>time.time(),'no future elapse: '+timer)
            before=completions(service)
            native.run(['date','-u','-s','@'+str(target-15)])
            triggered=lambda:(unix(show(timer,'LastTriggerUSec')) or 0)>=target-1
            wait(check,lambda:triggered() and idle() and sum(completions(service))>sum(before),service+' from its calendar',1800)
            check(completions(service)[1]==before[1],service+' failed when its calendar fired')
            last=unix(show(timer,'LastTriggerUSec'))
            check(last is not None and last>=target-1,'trigger not attributed to the calendar elapse: %s last=%s target=%s'%(timer,last,target))
            after=unix(show(timer,'NextElapseUSecRealtime'));check(after is not None and after>target,'next elapse did not advance: '+timer)
            fired[timer]={'elapse':target,'last_trigger':last,'next':after}
    finally:
        native.run(['date','-u','-s','@'+str(int(wall+time.monotonic()-mono))])
        if chrony:native.run(['systemctl','start','chronyd'])
        for timer,_ in ORDER:native.run(['systemctl','start',timer])
    # Persistent catch-up: trim last ran "10 days ago" and is left for the next boot.
    native.run(['systemctl','stop','enzimos-trim.timer']);check(STAMP.is_file(),'trim persistent stamp missing')
    backdated=int(time.time())-10*86400;os.utime(STAMP,(backdated,backdated))
    native.atomic_json(STATE,{'boot_id':native.boot_id(),'backdated':backdated,'fired':fired});os.sync()
    return {'calendar_elapses_fired':sorted(fired),'hourly_weekly_monthly':True,'next_elapse_advanced':True,'clock_restored':True,
            'persistent_stamp_backdated':True,'randomized_delay_zeroed_for_lab':True,'host_clock_changed':False}


def persistent(check):
    saved=json.loads(STATE.read_text());check(saved['boot_id']!=native.boot_id(),'later boot required')
    boot=int(time.time()-time.monotonic())
    wait(check,lambda:completions('enzimos-trim.service')[0]>=1,'persistent trim catch-up at boot',1200)
    last=unix(show('enzimos-trim.timer','LastTriggerUSec'))
    check(last is not None and last>=boot-5 and last>saved['backdated'],'catch-up not triggered by the persistent timer this boot')
    check(completions('enzimos-trim.service')[1]==0 or completions('enzimos-trim.service')[0]>=1,'catch-up trim failed')
    for path in DROPINS:
        path.unlink();path.parent.rmdir()
    native.run(['systemctl','daemon-reload']);STATE.unlink()
    return {'later_boot':True,'missed_weekly_run_caught_up_at_boot':True,'lab_dropins_removed':True}


def qualify(check,selection):
    check(native.output(['pacman','-Q','enzimos-native-policy'])==VERSION,'wrong calendar candidate')
    return firing(check) if selection=='calendar-firing' else persistent(check)
