#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real authorization for delivery cancellation and credential receipt lifecycle."""
import json
from pathlib import Path
import subprocess
import native
import generation_registry as registry

UNIT='enzimos-system-backend.service';CONTROL=registry.CONTROL


def install_backend(check,payload):
    payload=Path(payload);package=payload/'system-backend.pkg.tar.zst'
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-57','wrong lifecycle API native candidate')
    check(native.sha(package)==json.loads((payload/'backend-build.json').read_text())['sha256'],'lifecycle API package mismatch')
    key=Path('/run/lifecycle-api-signing');key.mkdir(mode=0o700)
    native.run(['gpg','--homedir',key,'--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key','enzimOS DISPOSABLE lifecycle API','ed25519','sign','1d'])
    native.run(['gpg','--homedir',key,'--batch','--detach-sign','--output','/run/backend.pkg.tar.zst.sig',package])
    subprocess.run(['gpg','--homedir','/etc/pacman.d/gnupg','--batch','--no-autostart','--import'],input=subprocess.check_output(['gpg','--homedir',str(key),'--batch','--export']),check=True)
    fingerprint=next(line.split(':')[9] for line in native.output(['gpg','--homedir',key,'--with-colons','--list-keys']).splitlines() if line.startswith('fpr:'))
    native.run(['gpg','--homedir','/etc/pacman.d/gnupg','--batch','--no-autostart','--import-ownertrust'],input=fingerprint+':5:\n')
    native.run(['cp',package,'/run/backend.pkg.tar.zst']);native.run(['pacman','--noconfirm','-U','/run/backend.pkg.tar.zst'])
    check(native.output(['pacman','-Q','enzimos-system-backend'])=='enzimos-system-backend 0.1.0-12','wrong recovery backend')
    check(subprocess.run(['systemctl','is-active','--quiet',UNIT]).returncode!=0,'install activated recovery backend')
    native.run(['systemctl','daemon-reload']);native.run(['busctl','call','org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','ReloadConfig']);native.run(['systemctl','start',UNIT])
    native.run(['install','-m','0644',payload/'lifecycle_api_client.py','/usr/lib/enzimos-lab/lifecycle_api_client.py'])


def qualify(check,payload):
    import copy
    import backup
    import backup_credentials as c
    import backup_delivery as d
    import backup_selective
    import boot_inventory
    from test_credential_review import pause_history,restore_history
    from test_credential_review import material
    install_backend(check,payload)
    native.run(['mount','/backup-repository']);config=backup.read_config();schedule=pause_history(check)
    try:
        snapshot=max(backup.snapshots(config),key=lambda row:row['time'])['id']
        backup_selective.export('api-private-export',snapshot,'/backup-source/home/enzimos-admin/.var/app/org.enzimos.Fixture/hidden-data')
        granted=d.grant('api-unused-grant','api-private-export',1001);grant_path=d.directory()/'api-unused-grant.json';grant_before=registry.decode(grant_path.read_bytes())
        c.NEXT.write_text('ENZIMOS-PUBLIC-LAB-LIFECYCLE-API-PASSWORD\n');c.NEXT.chmod(0o600)
        original=c.registry.save_document
        def save(path,value):
            if value.get('id')=='api-interrupted' and value.get('phase')=='complete':raise OSError('LAB interrupted receipt')
            return original(path,value)
        c.registry.save_document=save
        try:
            try:c.enroll('api-interrupted')
            except OSError as exc:check(str(exc)=='LAB interrupted receipt','wrong fixture receipt failure')
            else:raise AssertionError('receipt interruption absent')
        finally:c.registry.save_document=original
        pending=copy.deepcopy(c.records(c.folder())['api-interrupted']);protected=material(config)
        Path('/run/lifecycle-selections.json').write_text(json.dumps({'6':{'id':'api-unused-grant','grant_sha256':granted['grant_sha256']},'7':{'id':'api-interrupted'},'8':{'id':'api-interrupted','review_sha256':'0'*64}}))
        Path('/run/lifecycle-selections.json').chmod(0o644)
        def authenticated(mode):
            unit='enzimos-lifecycle-api-'+mode;native.run(['systemctl','mask','--runtime','--now','getty@tty2.service','autovt@tty2.service']);native.run(['chvt','2'])
            log=Path('/run')/(unit+'.log')
            result=subprocess.run(['systemd-run','--quiet','--wait','--collect','--unit='+unit,'--uid=enzimos-admin','--property=PAMName=login','--property=TTYPath=/dev/tty2',
                '--property=StandardInput=tty-force','--property=StandardOutput=append:'+str(log),'--property=StandardError=append:'+str(log),'--setenv=XDG_SESSION_TYPE=tty','--setenv=XDG_SESSION_CLASS=user',
                '/usr/bin/python','-I','-B','/usr/lib/enzimos-lab/lifecycle_api_client.py',mode],capture_output=True,text=True,timeout=900)
            text=log.read_text();print('ENZIMOS_LIFECYCLE_API_TRANSCRIPT\n'+text+result.stderr,flush=True)
            if result.returncode:print(native.output(['journalctl','-b','--no-pager','-n','60','-u',UNIT]),flush=True)
            check(result.returncode==0,'authenticated lifecycle API failed');lines=[line for line in text.splitlines() if line.startswith('ENZIMOS_LIFECYCLE_API_CLIENT=')]
            check(len(lines)==1,'lifecycle client result missing');return json.loads(lines[0].split('=',1)[1])
        for user,mode in (('enzimos-user','deny-user'),('enzimos-admin','deny-admin')):
            result=subprocess.run(['runuser','-u',user,'--','python','-I','-B','/usr/lib/enzimos-lab/lifecycle_api_client.py',mode],capture_output=True,text=True,timeout=150)
            print(result.stdout+result.stderr,flush=True);check(result.returncode==0,'lifecycle authorization denial failed')
        cancelled=authenticated('auth-cancel');check(not list((CONTROL/'backend-operations').glob('*.json')),'cancelled auth created job')
        check(c.records(c.folder())['api-interrupted']==pending and registry.decode(grant_path.read_bytes())==grant_before,'denied request changed native record')
        executed=authenticated('execute');result=executed['result'];new_key=result['credential-complete']['new_key']
        check(c.records(c.folder())['api-interrupted']==dict(pending,phase='complete',new_key=new_key),'credential receipt not exactly completed')
        check(registry.decode(grant_path.read_bytes())==dict(grant_before,phase='cancelled'),'delivery grant not exactly cancelled')
        check(not (Path('/home/enzimos-user')/granted['filename']).exists(),'cancellation created recipient output')
        saved={str(path):native.sha(path) for path in (grant_path,c.folder()/'api-interrupted.json')}
        native.run(['systemctl','restart',UNIT]);completed=authenticated('completed')
        check(completed['result']==result and all(native.sha(Path(path))==value for path,value in saved.items()),'restart deduplication changed native receipts')
        check(material(config)==protected,'lifecycle API changed keys/points/packages/password/authority')
        report=boot_inventory.collect();check(not report['complete'] and not report['execution_available'],'lifecycle API enabled retirement')
        return {'real_active_admin_authorization':True,'ordinary_inactive_denied':True,'auth_cancel_no_job':True,'three_draft_cancellations':True,
                'stale_digest_refused':True,'grant_cancelled_without_output':True,'credential_review_then_receipt_completed':True,
                'completed_restart_deduplicated':True,'keys_points_packages_password_authority_preserved':True,'retirement_enabled':False,
                'key_creation_replayed':False,'delivery_executed':False,'password_prompts':sum(row['password_prompts'] for row in (cancelled,executed,completed))}
    finally:
        native.run(['systemctl','stop',UNIT]);restore_history(check,schedule)
