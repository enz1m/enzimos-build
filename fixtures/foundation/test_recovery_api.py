#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real authorization prepares packaged recovery metadata only, never online restore."""
import json
from pathlib import Path
import subprocess
import native
import generation_registry as registry

UNIT='enzimos-system-backend.service';CONTROL=registry.CONTROL


def install_backend(check,payload):
    payload=Path(payload);package=payload/'system-backend.pkg.tar.zst'
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-57','wrong recovery API native candidate')
    check(native.sha(package)==json.loads((payload/'backend-build.json').read_text())['sha256'],'recovery API package mismatch')
    key=Path('/run/recovery-api-signing');key.mkdir(mode=0o700)
    native.run(['gpg','--homedir',key,'--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key','enzimOS DISPOSABLE recovery API','ed25519','sign','1d'])
    native.run(['gpg','--homedir',key,'--batch','--detach-sign','--output','/run/backend.pkg.tar.zst.sig',package])
    subprocess.run(['gpg','--homedir','/etc/pacman.d/gnupg','--batch','--no-autostart','--import'],input=subprocess.check_output(['gpg','--homedir',str(key),'--batch','--export']),check=True)
    fingerprint=next(line.split(':')[9] for line in native.output(['gpg','--homedir',key,'--with-colons','--list-keys']).splitlines() if line.startswith('fpr:'))
    native.run(['gpg','--homedir','/etc/pacman.d/gnupg','--batch','--no-autostart','--import-ownertrust'],input=fingerprint+':5:\n')
    native.run(['cp',package,'/run/backend.pkg.tar.zst']);native.run(['pacman','--noconfirm','-U','/run/backend.pkg.tar.zst'])
    check(native.output(['pacman','-Q','enzimos-system-backend'])=='enzimos-system-backend 0.1.0-12','wrong recovery backend')
    check(subprocess.run(['systemctl','is-active','--quiet',UNIT]).returncode!=0,'install activated recovery backend')
    native.run(['systemctl','daemon-reload']);native.run(['busctl','call','org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','ReloadConfig']);native.run(['systemctl','start',UNIT])
    native.run(['install','-m','0644',payload/'recovery_api_client.py','/usr/lib/enzimos-lab/recovery_api_client.py'])


def qualify(check,payload):
    install_backend(check,payload)
    inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
    from recovery_stage import jobs_directory,read_jobs,subvolumes
    before=read_jobs(jobs_directory());roots=subvolumes('/');check(not before,'fresh recovery plan branch required')
    boot_files={str(p):native.sha(p) for folder in ('/boot/loader/entries','/boot/limine') for p in Path(folder).iterdir() if p.is_file()}
    for user,mode in (('enzimos-user','deny-user'),('enzimos-admin','deny-admin')):
        result=subprocess.run(['runuser','-u',user,'--','python','-I','-B','/usr/lib/enzimos-lab/recovery_api_client.py',mode],capture_output=True,text=True,timeout=150)
        print(result.stdout+result.stderr,flush=True);check(result.returncode==0,'recovery authorization denial failed')
    def authenticated(mode):
        unit='enzimos-recovery-api-'+mode;native.run(['systemctl','mask','--runtime','--now','getty@tty2.service','autovt@tty2.service']);native.run(['chvt','2'])
        log=Path('/run')/(unit+'.log')
        result=subprocess.run(['systemd-run','--quiet','--wait','--collect','--unit='+unit,'--uid=enzimos-admin','--property=PAMName=login','--property=TTYPath=/dev/tty2',
            '--property=StandardInput=tty-force','--property=StandardOutput=append:'+str(log),'--property=StandardError=append:'+str(log),'--setenv=XDG_SESSION_TYPE=tty','--setenv=XDG_SESSION_CLASS=user',
            '/usr/bin/python','-I','-B','/usr/lib/enzimos-lab/recovery_api_client.py',mode],capture_output=True,text=True,timeout=500)
        text=log.read_text();print('ENZIMOS_RECOVERY_API_TRANSCRIPT\n'+text+result.stderr,flush=True)
        if result.returncode:print(native.output(['journalctl','-b','--no-pager','-n','60','-u',UNIT]),flush=True)
        check(result.returncode==0,'authenticated recovery API failed');lines=[line for line in text.splitlines() if line.startswith('ENZIMOS_RECOVERY_API_CLIENT=')]
        check(len(lines)==1,'recovery client result missing');return json.loads(lines[0].split('=',1)[1])
    cancelled=authenticated('plan-cancel');check(read_jobs(jobs_directory())==before,'cancelled draft prepared recovery')
    prepared=authenticated('prepare');jobs=read_jobs(jobs_directory());identifier='api-'+'3'*32
    check(set(jobs)=={identifier} and jobs[identifier]['phase']=='planned','one packaged recovery plan required')
    saved=(jobs_directory()/(identifier+'.json')).read_bytes()
    native.run(['systemctl','restart',UNIT]);completed=authenticated('completed')
    check((jobs_directory()/(identifier+'.json')).read_bytes()==saved,'completed retry rewrote recovery plan')
    try:native.assert_transition_idle()
    except native.Failure as exc:check('recovery staging requires explicit review' in str(exc),'prepared recovery did not block conflicting transition')
    else:raise AssertionError('planned recovery ignored')
    check(subvolumes('/')==roots,'recovery planning created/deleted subvolume')
    check({str(p):native.sha(p) for folder in ('/boot/loader/entries','/boot/limine') for p in Path(folder).iterdir() if p.is_file()}==boot_files,'recovery API changed boot selection/material')
    check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'recovery API changed packages/authority')
    native.run(['systemctl','stop',UNIT])
    return {'real_active_admin_authorization':True,'ordinary_inactive_denied':True,'draft_cancel_no_recovery_plan':True,
            'stale_digest_refused':True,'one_packaged_recovery_plan':True,'completed_restart_deduplicated':True,
            'subvolumes_boot_packages_authority_preserved':True,'planned_recovery_blocks_conflicts':True,
            'online_restore_or_activation':False,'password_prompts':sum(row['password_prompts'] for row in (cancelled,prepared,completed))}
