#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real polkit authorization for boot retirement and compromise-rotation review/advance."""
import json
import os
from pathlib import Path
import subprocess
import native
import generation_registry as registry
import backup
import backup_rotation as rotation
import boot_retirement
import boot_inventory
from test_credential_review import pause_history,restore_history

UNIT='enzimos-system-backend.service';CONTROL=registry.CONTROL
import lab_versions
NATIVE=lab_versions.native();BACKEND=lab_versions.backend()
ROTATION='rot-api';PASSWORD='ENZIMOS-PUBLIC-LAB-ROTATION-API\n'


def install_backend(check,payload):
    payload=Path(payload);package=payload/'system-backend.pkg.tar.zst'
    check(native.output(['pacman','-Q','enzimos-native-policy'])==NATIVE,'wrong lifecycle63 native candidate')
    check(native.sha(package)==json.loads((payload/'backend-build.json').read_text())['sha256'],'lifecycle63 backend package mismatch')
    key=Path('/run/lifecycle63-signing');key.mkdir(mode=0o700)
    native.run(['gpg','--homedir',key,'--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key','enzimOS DISPOSABLE lifecycle63 API','ed25519','sign','1d'])
    native.run(['gpg','--homedir',key,'--batch','--detach-sign','--output','/run/backend.pkg.tar.zst.sig',package])
    subprocess.run(['gpg','--homedir','/etc/pacman.d/gnupg','--batch','--no-autostart','--import'],input=subprocess.check_output(['gpg','--homedir',str(key),'--batch','--export']),check=True)
    fingerprint=next(line.split(':')[9] for line in native.output(['gpg','--homedir',key,'--with-colons','--list-keys']).splitlines() if line.startswith('fpr:'))
    native.run(['gpg','--homedir','/etc/pacman.d/gnupg','--batch','--no-autostart','--import-ownertrust'],input=fingerprint+':5:\n')
    native.run(['cp',package,'/run/backend.pkg.tar.zst']);native.run(['pacman','--noconfirm','-U','/run/backend.pkg.tar.zst'])
    check(native.output(['pacman','-Q','enzimos-system-backend'])==BACKEND,'wrong lifecycle63 backend')
    check(subprocess.run(['systemctl','is-active','--quiet',UNIT]).returncode!=0,'install activated backend')
    native.run(['systemctl','daemon-reload']);native.run(['busctl','call','org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','ReloadConfig']);native.run(['systemctl','start',UNIT])
    native.run(['install','-m','0644',payload/'lifecycle63_api_client.py','/usr/lib/enzimos-lab/lifecycle63_api_client.py'])


def write_secret(path,text):
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'w') as stream:stream.write(text);stream.flush();os.fsync(stream.fileno())


def candidate(check):
    def scan():
        catalog=registry.status()['catalog']['generations'];plans={}
        for name in sorted(catalog,key=lambda n:catalog[n]['ordinal']):
            plans[name]=boot_retirement.plan(name)
            if plans[name]['retirable']:return name,plans[name],plans
        return None,None,plans
    name,plan,plans=scan()
    if name is None:
        # Too few newer generations: publish up to two fresh aliases (ESP permitting)
        # and select the newest, so an older generation gains two newer ones.
        kernels=native.installed_kernels();options=Path('/proc/cmdline').read_text().strip()
        markers=[w.split('=',1)[1] for w in options.split() if w.startswith('enzimos.generation=')]
        stage=Path('/boot/enzimos/generations')/markers[0] if len(markers)==1 else Path('/boot')
        size=sum(os.path.getsize(stage/n) for f in kernels for n in (f'vmlinuz-{f}',f'initramfs-{f}.img'))
        published=[]
        with native.operation_lock():
            for fresh in ('api-c','api-d'):
                if __import__('shutil').disk_usage('/boot').free>=size+20*1024**2:native.publish_boot(stage,fresh,kernels,options);published.append(fresh)
        check(published,'no ESP room for fixture generations')
        native.select_generation(published[-1],'linux');name,plan,plans=scan()
    check(name is not None,'no retirable boot generation: '+json.dumps({n:p['protection'] for n,p in plans.items()}))
    return name,plan


def qualify(check,payload):
    install_backend(check,payload)
    native.run(['mount','/backup-repository']);config=backup.read_config();history=pause_history(check)
    try:
        if not Path(config['repository'],'config').exists():backup.initialize()
        if not backup.snapshots(config):backup.backup(False)
        old_password=Path(config['password_file']).read_bytes()
        write_secret(rotation.ROTATION_PASSWORD,PASSWORD)
        prepared=rotation.prepare(ROTATION);check(prepared['status']=='rotation-copied-verified','rotation copy for API')
        generation,plan=candidate(check)
        Path('/run/lifecycle63-selections.json').write_text(json.dumps({'9':{'generation':generation,'plan_sha256':plan['plan_sha256']},
            '10':{'id':ROTATION},'11':{'id':ROTATION,'review_sha256':'0'*64,'action':'switch'}}))
        Path('/run/lifecycle63-selections.json').chmod(0o644)
        inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
        def authenticated(mode):
            unit='enzimos-lifecycle63-api-'+mode;native.run(['systemctl','mask','--runtime','--now','getty@tty2.service','autovt@tty2.service']);native.run(['chvt','2'])
            log=Path('/run')/(unit+'.log')
            result=subprocess.run(['systemd-run','--quiet','--wait','--collect','--unit='+unit,'--uid=enzimos-admin','--property=PAMName=login','--property=TTYPath=/dev/tty2',
                '--property=StandardInput=tty-force','--property=StandardOutput=append:'+str(log),'--property=StandardError=append:'+str(log),'--setenv=XDG_SESSION_TYPE=tty','--setenv=XDG_SESSION_CLASS=user',
                '/usr/bin/python','-I','-B','/usr/lib/enzimos-lab/lifecycle63_api_client.py',mode],capture_output=True,text=True,timeout=1800)
            text=log.read_text();print('ENZIMOS_LIFECYCLE63_API_TRANSCRIPT\n'+text+result.stderr,flush=True)
            if result.returncode:print(native.output(['journalctl','-b','--no-pager','-n','80','-u',UNIT]),flush=True)
            check(result.returncode==0,'authenticated lifecycle63 API failed')
            lines=[line for line in text.splitlines() if line.startswith('ENZIMOS_LIFECYCLE63_API_CLIENT=')]
            check(len(lines)==1,'lifecycle63 client result missing');return json.loads(lines[0].split('=',1)[1])
        for user,mode in (('enzimos-user','deny-user'),('enzimos-admin','deny-admin')):
            result=subprocess.run(['runuser','-u',user,'--','python','-I','-B','/usr/lib/enzimos-lab/lifecycle63_api_client.py',mode],capture_output=True,text=True,timeout=150)
            print(result.stdout+result.stderr,flush=True);check(result.returncode==0,'lifecycle63 authorization denial failed')
        cancelled=authenticated('auth-cancel');check(not list((CONTROL/'backend-operations').glob('*.json')),'cancelled auth created job')
        check(generation in registry.status()['catalog']['generations'] and rotation.records(rotation.folder())[ROTATION]['phase']=='copied','denied requests changed native state')
        executed=authenticated('execute')
        catalog=registry.status()['catalog'];check(generation not in catalog['generations'] and generation in catalog['retired'],'API boot retirement not recorded')
        check(rotation.records(rotation.folder())[ROTATION]['phase']=='complete','API rotation not complete')
        check(not os.path.lexists(rotation.RETIRED) and not os.path.lexists(rotation.RETIRED_PASSWORD),'retired repository material remains')
        old=Path('/run/enzimos/lab-old-password');write_secret(old,old_password.decode())
        check(rotation.refuses(rotation.guard.REPOSITORY,old),'old password opens repository after API rotation');old.unlink()
        saved={str(p):native.sha(p) for p in (CONTROL/'backend-operations').glob('*.json')}
        native.run(['systemctl','restart',UNIT]);completed=authenticated('completed')
        check(all(native.sha(Path(p))==v for p,v in saved.items()),'restart changed ledger records')
        check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'lifecycle63 API changed packages/authority')
        # Regression: a real backend ledger must not break the reference observation.
        report=boot_inventory.collect();check(not report['complete'] and not report['execution_available'],'observation claimed retirement authority')
        check(any(item.startswith('backend-operation-retirement-not-qualified:') for item in report['blockers']),'backend ledger not observed')
        return {'real_active_admin_authorization':True,'ordinary_inactive_denied':True,'auth_cancel_no_job':True,'draft_cancellations':True,
                'stale_digest_refused':True,'boot_generation_retired_via_api':generation,'rotation_reviewed_switched_discarded_via_api':True,
                'old_password_refused_after_api_rotation':True,'completed_restart_deduplicated':True,'packages_authority_preserved':True,
                'reference_observation_with_backend_ledger':True,'password_prompts':cancelled['password_prompts']+executed['password_prompts']+completed['password_prompts'],
                'root_subvolumes_deleted':False,'rotation_prepare_via_api':False}
    finally:
        native.run(['systemctl','stop',UNIT])
        if rotation.ROTATION_PASSWORD.exists():rotation.ROTATION_PASSWORD.unlink()
        restore_history(check,history)
