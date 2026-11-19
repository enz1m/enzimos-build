#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Actual systemd cgroup termination of a real authorized backup worker."""
import json
import os
from pathlib import Path
import subprocess
import time
import native

CONTROL=Path('/var/lib/enzimos-control');UNIT='enzimos-system-backend.service';ID='7'*32


def qualify(check,payload):
    check(native.output(['pacman','-Q','enzimos-system-backend'])=='enzimos-system-backend 0.1.0-12','wrong service-kill backend')
    native.run(['mount','/backup-repository']);native.run(['install','-m','0644',Path(payload)/'backup_api_client.py','/usr/lib/enzimos-lab/backup_api_client.py'])
    native.run(['systemctl','start',UNIT]);inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
    def authenticated(mode,kill=False):
        unit='enzimos-kill-api-'+mode;native.run(['systemctl','mask','--runtime','--now','getty@tty2.service','autovt@tty2.service']);native.run(['chvt','2'])
        log=Path('/run')/(unit+'.log');args=['systemd-run','--quiet','--wait','--collect','--unit='+unit,'--uid=enzimos-admin','--property=PAMName=login','--property=TTYPath=/dev/tty2',
              '--property=StandardInput=tty-force','--property=StandardOutput=append:'+str(log),'--property=StandardError=append:'+str(log),'--setenv=XDG_SESSION_TYPE=tty','--setenv=XDG_SESSION_CLASS=user',
              '/usr/bin/python','-I','-B','/usr/lib/enzimos-lab/backup_api_client.py',mode]
        child=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        if kill:
            path=CONTROL/'backend-operations'/(ID+'.json');deadline=time.monotonic()+150;seen=False
            while time.monotonic()<deadline:
                if path.exists():
                    record=json.loads(path.read_text())
                    if record['state']=='running' and record['progress']=='transferring':seen=True;break
                time.sleep(.1)
            check(seen,'backup worker did not reach actual transfer')
            native.run(['systemctl','kill','--kill-whom=all','--signal=KILL',UNIT])
        stdout,stderr=child.communicate(timeout=150);text=log.read_text();print('ENZIMOS_KILL_API_TRANSCRIPT\n'+text+stderr,flush=True)
        check(child.returncode==0,'service kill client failed');lines=[line for line in text.splitlines() if line.startswith('ENZIMOS_BACKUP_API_CLIENT=')]
        check(len(lines)==1,'service kill client result missing');return json.loads(lines[0].split('=',1)[1])
    submitted=authenticated('kill-submit',True)
    deadline=time.monotonic()+20
    while subprocess.run(['systemctl','is-active','--quiet',UNIT]).returncode==0 and time.monotonic()<deadline:time.sleep(.2)
    processes=native.output(['ps','-eo','comm']);check(not any(line.strip()=='restic' for line in processes.splitlines()),'service kill left restic process')
    record=json.loads((CONTROL/'backend-operations'/(ID+'.json')).read_text());check(record['state']=='running','killed job was falsely complete')
    # No automatic repository unlock or partial stage deletion. Hash its current
    # files after process death; restart/status must not touch this outcome.
    repository=Path('/backup-repository/restic');before={str(p.relative_to(repository)):native.sha(p) for p in repository.rglob('*') if p.is_file()}
    native.run(['systemctl','reset-failed',UNIT]);native.run(['systemctl','start',UNIT]);review=authenticated('kill-review')
    after={str(p.relative_to(repository)):native.sha(p) for p in repository.rglob('*') if p.is_file()};check(after==before,'uncertain worker replay changed repository')
    check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'service kill changed packages/authority')
    native.run(['systemctl','stop',UNIT])
    return {'real_authorized_backup_reached_transfer':True,'whole_service_cgroup_killed':True,'restic_child_gone':True,
            'restart_marks_uncertain':True,'authorized_status_and_retry_refusal':True,'repository_bytes_unchanged_after_restart':True,
            'packages_authority_preserved':True,'automatic_unlock_or_stage_cleanup':False,'physical_power_loss':False}
