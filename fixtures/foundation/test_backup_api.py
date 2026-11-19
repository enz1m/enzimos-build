#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real polkit + encrypted local restic worker; no API fault injection or host bus."""
import json
import os
from pathlib import Path
import subprocess
import native

CONTROL=Path('/var/lib/enzimos-control');UNIT='enzimos-system-backend.service'


def qualify(check,payload):
    payload=Path(payload);package=payload/'system-backend.pkg.tar.zst'
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-57','wrong backup API native candidate')
    check(native.sha(package)==json.loads((payload/'backend-build.json').read_text())['sha256'],'backend package changed')
    key=Path('/run/backup-api-signing');key.mkdir(mode=0o700)
    native.run(['gpg','--homedir',key,'--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key','enzimOS DISPOSABLE backup API','ed25519','sign','1d'])
    native.run(['gpg','--homedir',key,'--batch','--detach-sign','--output','/run/backend.pkg.tar.zst.sig',package])
    exported=subprocess.check_output(['gpg','--homedir',str(key),'--batch','--export'])
    subprocess.run(['gpg','--homedir','/etc/pacman.d/gnupg','--batch','--no-autostart','--import'],input=exported,check=True)
    fingerprint=next(line.split(':')[9] for line in native.output(['gpg','--homedir',key,'--with-colons','--list-keys']).splitlines() if line.startswith('fpr:'))
    native.run(['gpg','--homedir','/etc/pacman.d/gnupg','--batch','--no-autostart','--import-ownertrust'],input=fingerprint+':5:\n')
    native.run(['cp',package,'/run/backend.pkg.tar.zst']);native.run(['pacman','--noconfirm','-U','/run/backend.pkg.tar.zst'])
    check(native.output(['pacman','-Q','enzimos-system-backend'])=='enzimos-system-backend 0.1.0-12','wrong backup API backend candidate')
    check(subprocess.run(['systemctl','is-active','--quiet',UNIT]).returncode!=0,'installation autoactivated backend')
    native.run(['systemctl','daemon-reload']);native.run(['busctl','call','org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','ReloadConfig'])
    native.run(['systemctl','start',UNIT])
    native.run(['install','-m','0644',payload/'backup_api_client.py','/usr/lib/enzimos-lab/backup_api_client.py'])
    inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
    import backup
    # The fixture's fstab deliberately uses noauto: attach only the declared
    # private second disk for this explicit test, never through the API.
    native.run(['mount','/backup-repository'])
    def snapshots():return {row['id'] for row in backup.snapshots(backup.read_config())}
    before=snapshots();check(before,'existing encrypted repository required')
    for user,mode in (('enzimos-user','deny-user'),('enzimos-admin','deny-admin')):
        result=subprocess.run(['runuser','-u',user,'--','python','-I','-B','/usr/lib/enzimos-lab/backup_api_client.py',mode],capture_output=True,text=True,timeout=150)
        print(result.stdout+result.stderr,flush=True);check(result.returncode==0,'inactive/ordinary backup API denial failed')
    def authenticated(mode):
        unit='enzimos-backup-api-'+mode
        native.run(['systemctl','mask','--runtime','--now','getty@tty2.service','autovt@tty2.service']);native.run(['chvt','2'])
        log=Path('/run')/(unit+'.log')
        args=['systemd-run','--quiet','--wait','--collect','--unit='+unit,'--uid=enzimos-admin','--property=PAMName=login','--property=TTYPath=/dev/tty2',
              '--property=StandardInput=tty-force','--property=StandardOutput=append:'+str(log),'--property=StandardError=append:'+str(log),
              '--setenv=XDG_SESSION_TYPE=tty','--setenv=XDG_SESSION_CLASS=user','/usr/bin/python','-I','-B','/usr/lib/enzimos-lab/backup_api_client.py',mode]
        if mode=='locked-session':
            import time
            child=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            deadline=time.monotonic()+100;session=None
            while time.monotonic()<deadline and child.poll() is None:
                if log.exists():
                    lines=[line for line in log.read_text().splitlines() if line.startswith('ENZIMOS_BACKUP_API_LOCK_READY ')]
                    if lines:session=lines[-1].split()[-1];break
                time.sleep(.1)
            check(session is not None,'lock-ready session absent')
            path=native.output(['busctl','call','org.freedesktop.login1','/org/freedesktop/login1','org.freedesktop.login1.Manager','GetSession','s',session]).split('"')[1]
            native.run(['busctl','call','org.freedesktop.login1',path,'org.freedesktop.login1.Session','SetLockedHint','b','true'])
            try:stdout,stderr=child.communicate(timeout=60)
            finally:
                subprocess.run(['busctl','call','org.freedesktop.login1',path,'org.freedesktop.login1.Session','SetLockedHint','b','false'],capture_output=True)
            result=subprocess.CompletedProcess(args,child.returncode,stdout,stderr)
        else:result=subprocess.run(args,capture_output=True,text=True,timeout=1500)
        text=log.read_text();print('ENZIMOS_BACKUP_API_TRANSCRIPT\n'+text+result.stderr,flush=True)
        if result.returncode:
            print(native.output(['journalctl','-b','--no-pager','-n','70','-u',UNIT]),flush=True)
        check(result.returncode==0,'authenticated backup API failed')
        lines=[line for line in text.splitlines() if line.startswith('ENZIMOS_BACKUP_API_CLIENT=')];check(len(lines)==1,'backup API result absent')
        return json.loads(lines[0].split('=',1)[1])
    locked=authenticated('locked-session');disconnected=authenticated('disconnect-auth')
    check(not (CONTROL/'backend-operations'/('6'*32+'.json')).exists(),'disconnected request created a job')
    cancelled=authenticated('auth-cancel');planned=authenticated('plan-cancel')
    check(snapshots()==before,'denial/plan/cancellation changed repository')
    completed=authenticated('run');after=snapshots();check(len(after-before)==1 and before<=after,'backup job did not create exactly one retained snapshot')
    native.run(['systemctl','restart',UNIT]);repeated=authenticated('completed')
    check(snapshots()==after,'completed job replay created another snapshot')
    backup.restic(backup.read_config(),['check'])
    check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'API changed package/authority state')
    check(not (CONTROL/'backup.enabled').exists(),'backup API enabled scheduler')
    native.run(['systemctl','stop',UNIT])
    return {'real_active_admin_authorization':True,'ordinary_inactive_denied':True,'locked_session_refused':True,'disconnected_sender_no_job':True,'auth_cancel_and_preentry_cancel':True,
            'stale_plan_refused':True,'progress_observed':completed['result']['observed_progress'],'postentry_cancel_refused':True,
            'concurrent_submission_refused':True,'single_real_encrypted_backup':True,'completed_restart_deduplicated':True,
            'repository_checked':True,'packages_authority_preserved':True,'scheduler_enabled':False,
            'password_prompts':sum(row['password_prompts'] for row in (cancelled,planned,completed,repeated)),
            'general_update_recovery_api':False}
