#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real authorized full pacman update while live; explicit read-only cohort admission."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import threading
import time
import native

UNIT='enzimos-system-backend.service';CONTROL=Path('/var/lib/enzimos-control');GENERATION='api-'+'5'*32


def qualify(check,payload,module_trial,cut=False):
    payload=Path(payload);package=payload/'system-backend.pkg.tar.zst'
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-57','wrong update API native candidate')
    check(native.sha(package)==json.loads((payload/'backend-build.json').read_text())['sha256'],'backend package changed')
    key=Path('/run/update-api-signing');key.mkdir(mode=0o700)
    native.run(['gpg','--homedir',key,'--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key','enzimOS DISPOSABLE update API','ed25519','sign','1d'])
    native.run(['gpg','--homedir',key,'--batch','--detach-sign','--output','/run/backend.pkg.tar.zst.sig',package])
    subprocess.run(['gpg','--homedir','/etc/pacman.d/gnupg','--batch','--no-autostart','--import'],input=subprocess.check_output(['gpg','--homedir',str(key),'--batch','--export']),check=True)
    fingerprint=next(line.split(':')[9] for line in native.output(['gpg','--homedir',key,'--with-colons','--list-keys']).splitlines() if line.startswith('fpr:'))
    native.run(['gpg','--homedir','/etc/pacman.d/gnupg','--batch','--no-autostart','--import-ownertrust'],input=fingerprint+':5:\n')
    native.run(['cp',package,'/run/backend.pkg.tar.zst']);native.run(['pacman','--noconfirm','-U','/run/backend.pkg.tar.zst'])
    check(native.output(['pacman','-Q','enzimos-system-backend'])=='enzimos-system-backend 0.1.0-12','wrong update backend')
    check(subprocess.run(['systemctl','is-active','--quiet',UNIT]).returncode!=0,'update backend autoactivated')
    native.run(['systemctl','daemon-reload']);native.run(['busctl','call','org.freedesktop.DBus','/org/freedesktop/DBus','org.freedesktop.DBus','ReloadConfig'])
    import sys
    sys.path.insert(0,'/usr/lib/enzimos-backend');import update_operation
    cohort=update_operation.COHORT;cohort.mkdir(mode=0o700);target=cohort/'packages';target.mkdir(mode=0o700)
    expected=dict(line.split(' ',1) for line in (CONTROL/'new-packages.txt').read_text().splitlines())
    admitted=set()
    for name,version in expected.items():
        # This dated fixture preserves epoch in its downloaded filenames.
        # Admit the one exact existing form, never a broad name/version glob.
        matches=[]
        for archive_version in {version,version.split(':')[-1]}:
            for arch in ('x86_64','any'):
                filename=name+'-'+archive_version+'-'+arch+'.pkg.tar.zst'
                if (Path('/payload/packages')/filename).is_file():matches.append(filename)
        check(len(matches)==1,'ambiguous new package filename')
        admitted.update((matches[0],matches[0]+'.sig'))
    check(len(admitted)==2*len(expected),'new cohort filenames incomplete')
    files={}
    for path in Path('/payload/packages').iterdir():
        if path.name in admitted or path.name=='verified.db':
            destination=target/path.name;shutil.copyfile(path,destination);destination.chmod(0o600)
            files[path.name]={'bytes':destination.stat().st_size,'sha256':native.sha(destination)}
    check(files and 'verified.db' in files,'cohort package source unavailable')
    # This new fixture uses the separately reverified September25 cohort. The
    # prior fixture and expired admission remain immutable in their archives.
    native.atomic_json(cohort/'admission.json',{'schema':1,'files':files,'expires_at':'2026-09-26T08:40:21.278510+00:00','signature_policy':'Required TrustedOnly'})
    update_operation.CONFIG.write_text(update_operation.configuration());update_operation.CONFIG.chmod(0o600)
    native.run(['systemctl','start',UNIT]);native.run(['install','-m','0644',payload/'update_api_client.py','/usr/lib/enzimos-lab/update_api_client.py'])
    before=native.output(['pacman','-Q']);authority=native.authority_identity();boot_id=native.boot_id();running=os.uname().release
    home=Path('/home/enzimos-admin/update-api-marker');home.write_text('NEWER-HOME-LIVE-API\n');os.chown(home,1000,1000)
    for user,mode in (('enzimos-user','deny-user'),('enzimos-admin','deny-admin')):
        result=subprocess.run(['runuser','-u',user,'--','python','-I','-B','/usr/lib/enzimos-lab/update_api_client.py',mode],capture_output=True,text=True,timeout=150)
        print(result.stdout+result.stderr,flush=True);check(result.returncode==0,'ordinary/inactive update API denial failed')
    def authenticated(mode):
        unit='enzimos-update-api-'+mode;native.run(['systemctl','mask','--runtime','--now','getty@tty2.service','autovt@tty2.service']);native.run(['chvt','2'])
        log=Path('/run')/(unit+'.log')
        result=subprocess.run(['systemd-run','--quiet','--wait','--collect','--unit='+unit,'--uid=enzimos-admin','--property=PAMName=login','--property=TTYPath=/dev/tty2',
            '--property=StandardInput=tty-force','--property=StandardOutput=append:'+str(log),'--property=StandardError=append:'+str(log),'--setenv=XDG_SESSION_TYPE=tty','--setenv=XDG_SESSION_CLASS=user',
            '/usr/bin/python','-I','-B','/usr/lib/enzimos-lab/update_api_client.py',mode],capture_output=True,text=True,timeout=2400)
        text=log.read_text();print('ENZIMOS_UPDATE_API_TRANSCRIPT\n'+text+result.stderr,flush=True)
        if result.returncode:print(native.output(['journalctl','-b','--no-pager','-n','90','-u',UNIT]),flush=True)
        check(result.returncode==0,'authorized live update API failed');lines=[line for line in text.splitlines() if line.startswith('ENZIMOS_UPDATE_API_CLIENT=')]
        check(len(lines)==1,'update API client result missing');return json.loads(lines[0].split('=',1)[1])
    cancelled=authenticated('plan-cancel');check(native.output(['pacman','-Q'])==before,'cancelled plan changed packages')
    if cut:native.atomic_json(CONTROL/'update-api-cut.json',{'before_inventory':before,'authority':authority,'boot_id':boot_id,'running_kernel':running,'generation':GENERATION})
    stop=threading.Event();errors=[];samples=[]
    def observe():
        while not stop.wait(.5):
            if not Path('/usr/lib/modules',running,'kernel/fs/overlayfs/overlay.ko.zst').is_file():errors.append('running module path lost')
            log=Path('/var/log/pacman-enzimos-api.log')
            if log.exists() and '[ALPM] upgraded linux (' in log.read_text() and not samples:
                try:
                    if cut:
                        # Freeze only the explicitly named guest service cgroup,
                        # not PID1/fixture/host. The external controller exits QEMU
                        # after a synced mid-transaction boundary, not power loss.
                        native.run(['systemctl','freeze',UNIT])
                        text=log.read_text();check('[ALPM] transaction completed' not in text.rsplit('[ALPM] transaction started',1)[-1],'transaction finished before freeze')
                    module_trial();samples.append(True)
                    if cut:
                        native.atomic_json(CONTROL/'update-api-cut-observed.json',{'partial_inventory':native.output(['pacman','-Q']),'module_trial':True,'phase':'linux-upgraded-service-frozen'})
                        os.sync();print('ENZIMOS_UPDATE_API_CUT_READY linux-upgraded-service-frozen',flush=True)
                        while True:time.sleep(1)
                except Exception as exc:errors.append(type(exc).__name__)
    observer=threading.Thread(target=observe);observer.start()
    try:updated=authenticated('update')
    finally:stop.set();observer.join(10)
    check(not errors and samples,'running module path/autoload not observed during API update')
    after=native.output(['pacman','-Q']);check(after!=before,'API update did not change package cohort')
    check(native.boot_id()==boot_id and os.uname().release==running,'API forced reboot')
    module_trial();check(native.authority_identity()==authority and home.read_text()=='NEWER-HOME-LIVE-API\n','update lost current authority/home')
    native.run(['systemctl','restart',UNIT]);repeated=authenticated('completed');check(native.output(['pacman','-Q'])==after,'completed update retried packages')
    native.atomic_json(CONTROL/'update-api-boots.json',{'generation':GENERATION,'inventory':after,'authority':authority,'kernels':native.installed_kernels(),'step':0})
    native.run(['systemctl','stop',UNIT])
    return {'real_active_admin_authorization':True,'ordinary_inactive_denied':True,'cancel_before_update_no_mutation':True,'full_live_pacman_transaction':True,
            'ordinary_running_modules_preserved':True,'no_forced_reboot':True,'completed_restart_no_package_replay':True,'home_authority_preserved':True,
            'internet_cohort_admission':False,'password_prompts':sum(row['password_prompts'] for row in (cancelled,updated,repeated))}


def cut_review(check,module_trial):
    before=json.loads((CONTROL/'update-api-cut.json').read_text());observed=json.loads((CONTROL/'update-api-cut-observed.json').read_text())
    check(native.boot_id()!=before['boot_id'] and observed['module_trial'] is True,'later interrupted-update boot required')
    check(native.output(['pacman','-Q'])==before['before_inventory'],'retained boot package inventory differs')
    check(native.authority_identity()==before['authority'] and Path('/home/enzimos-admin/update-api-marker').read_text()=='NEWER-HOME-LIVE-API\n','cut rollback lost authority/home')
    root=native.output(['findmnt','-n','-o','FSROOT','/']);check(root=='/enzimos-old-'+GENERATION,'cut did not boot retained root')
    import sys
    sys.path.insert(0,'/usr/lib/enzimos-backend');import operation_jobs,update_operation,generation_registry
    store=operation_jobs.OperationStore(CONTROL/'backend-operations',generation_registry.storage_guard)
    initial=store.status('5'*32,1000);check(initial['state']=='running','interrupted update receipt not running')
    manager=operation_jobs.Manager(store,{'update-apply':update_operation.UpdateOperation()});status=manager.status('5'*32,1000)
    check(status['state']=='uncertain','interrupted updater not uncertain')
    try:manager.submit('5'*32,1000,status['plan_sha256'])
    except operation_jobs.storage.JobFailure as exc:check(str(exc)=='job-transition-refused','wrong updater replay refusal')
    else:raise AssertionError('interrupted update replayed')
    check(manager.worker is None and native.output(['pacman','-Q'])==before['before_inventory'],'review changed retained packages')
    module_trial()
    return {'retained_root_booted':True,'exact_old_package_inventory':True,'current_authority_newer_home_preserved':True,
            'running_receipt_becomes_uncertain':True,'no_update_replay':True,'normal_retained_modules':True,'physical_power_loss':False}


def boot(check,module_trial):
    value=json.loads((CONTROL/'update-api-boots.json').read_text());step=value['step'];sequence=[(True,'linux'),(True,'linux-lts'),(False,'linux'),(False,'linux-lts')]
    check(0<=step<4,'update API boot matrix complete');mode,flavor=sequence[step]
    check(Path('/sys/firmware/efi').exists()==mode and os.uname().release==value['kernels'][flavor],'wrong API updated kernel/loader')
    check(native.output(['pacman','-Q'])==value['inventory'] and native.authority_identity()==value['authority'],'updated boot changed package/authority')
    check(Path('/home/enzimos-admin/update-api-marker').read_text()=='NEWER-HOME-LIVE-API\n','API updated boot lost home')
    module_trial();native.select_generation(value['generation'],'linux-lts' if step in (0,2) else 'linux');value['step']+=1;native.atomic_json(CONTROL/'update-api-boots.json',value)
    return {'step':step,'kernel':os.uname().release,'uefi':mode,'updated_inventory_home_authority':True}
