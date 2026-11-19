#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""NAS backup over SMB entirely within this disposable guest: a Samba server in a
guest-private network namespace, only fresh LAB credentials (D-124)."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import native
import backup
import backup_remote as remote

BASE=Path('/run/remote-backup-lab');NS='enzimos-backup-server';ADDRESS='10.204.7.1'
SHARE_PASSWORD=Path('/etc/enzimos/backup-remote.share-password')
LAB_SHARE_PASSWORD='ENZIMOS-PUBLIC-LAB-SHARE-PASSWORD'
# The guest image already carries smbclient and its libraries; if pacman reports a
# missing dependency when the inputs are regenerated, extend this closed set.
SAMBA_PACKAGES={'samba'}


def samba_config(path):
    return f'''[global]
server role = standalone server
workgroup = WORKGROUP
server min protocol = SMB3
server signing = mandatory
interfaces = {ADDRESS}/24
bind interfaces only = yes
smb ports = 445
disable netbios = yes
map to guest = never
restrict anonymous = 2
load printers = no
printing = bsd
printcap name = /dev/null
disable spoolss = yes
pid directory = {BASE}/samba/run
lock directory = {BASE}/samba/lock
state directory = {BASE}/samba/state
cache directory = {BASE}/samba/cache
private dir = {BASE}/samba/private
ncalrpc dir = {BASE}/samba/ncalrpc
passdb backend = tdbsam:{BASE}/samba/private/passdb.tdb
log level = 1

[backups]
path = {path}
valid users = enzimos-backup-lab
force user = enzimos-backup-lab
read only = no
create mask = 0600
directory mask = 0700
'''


def qualify(check,payload,candidate=46,retrieval=False,extra=None):
    payload=Path(payload);check(native.output(['pacman','-Q','enzimos-native-policy'])==(candidate if isinstance(candidate,str) else 'enzimos-native-policy 0.1.0-'+str(candidate)),'wrong remote candidate')
    BASE.mkdir(mode=0o700);authority=native.authority_identity()
    plan=json.loads((payload/'smb-plan.json').read_text());check({r['name'] for r in plan['packages']}==SAMBA_PACKAGES,'closed Samba additions required')
    keys=BASE/'admission';keys.mkdir(mode=0o700)
    for name in ('pubring.gpg','trustdb.gpg','gpg.conf'):shutil.copyfile(payload/'smb-public-keys'/name,keys/name)
    config=BASE/'pacman.conf';config.write_text('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n')
    packages=[]
    for row in plan['packages']:
        p=payload/'smb-packages'/row['url'].rsplit('/',1)[-1];check(native.sha(p)==row['sha256_from_metadata'],'Samba package drift');packages.append(p)
    native.run(['pacman','--config',config,'--gpgdir',keys,'--noconfirm','-U',*packages])
    check(native.authority_identity()==authority,'Samba install changed runtime authority')
    check(subprocess.run(['systemctl','is-active','--quiet','smb']).returncode!=0,'Samba installation enabled a server')
    inventory=native.output(['pacman','-Q']);native.run(['mount','/backup-repository'])
    before={row['id'] for row in backup.snapshots(backup.read_config())};check(before,'existing local recovery point required')
    point=sorted(before)[-1]
    # The share lives on the guest's backup disk; the repository is its folder `restic`.
    repository=Path('/backup-repository/remote-lab');repository.mkdir(mode=0o700)
    other=Path('/backup-repository/remote-lab-other');other.mkdir(mode=0o700)
    native.run(['useradd','-M','-d','/nonexistent','-s','/usr/bin/nologin','enzimos-backup-lab'])
    native.run(['usermod','-p','*','enzimos-backup-lab'])
    uid=int(native.output(['id','-u','enzimos-backup-lab']));gid=int(native.output(['id','-g','enzimos-backup-lab']))
    for folder in (repository,other):os.chown(folder,uid,gid)
    for name in ('run','lock','state','cache','private','ncalrpc'):(BASE/'samba'/name).mkdir(parents=True,mode=0o700)
    daemon=BASE/'smb.conf';daemon.write_text(samba_config(repository))
    subprocess.run(['smbpasswd','-c',str(daemon),'-s','-a','enzimos-backup-lab'],input=(LAB_SHARE_PASSWORD+'\n')*2,text=True,check=True)
    Path('/backup-remote').mkdir(mode=0o700,exist_ok=True)
    remote.PASSWORD.write_text('ENZIMOS-PUBLIC-LAB-REMOTE-RESTIC-PASSWORD\n');remote.PASSWORD.chmod(0o600)
    SHARE_PASSWORD.write_text(LAB_SHARE_PASSWORD+'\n');SHARE_PASSWORD.chmod(0o600)
    remote.CONFIG.write_text(json.dumps({'schema':2,'server':ADDRESS,'share':'backups','folder':'restic','user':'enzimos-backup-lab'}));remote.CONFIG.chmod(0o600)
    native.run(['ip','netns','add',NS]);native.run(['ip','link','add','enz-bk-client','type','veth','peer','name','eth0','netns',NS])
    native.run(['nmcli','device','set','enz-bk-client','managed','no'])
    native.run(['ip','addr','add','10.204.7.2/24','dev','enz-bk-client']);native.run(['ip','link','set','enz-bk-client','up'])
    native.run(['ip','netns','exec',NS,'ip','addr','add',ADDRESS+'/24','dev','eth0']);native.run(['ip','netns','exec',NS,'ip','link','set','eth0','up']);native.run(['ip','netns','exec',NS,'ip','link','set','lo','up'])
    native.run(['apparmor_parser','-r','/etc/apparmor.d/enzimos-restic'])
    log=(BASE/'smbd.log').open('wb')
    def start():
        return subprocess.Popen(['ip','netns','exec',NS,'/usr/bin/smbd','--foreground','--no-process-group','--debug-stdout','-s',str(daemon)],stdout=log,stderr=log)
    server=start()
    def refuse(function):
        try:function()
        except (native.Failure,subprocess.SubprocessError):return
        raise AssertionError('remote negative control succeeded')
    original_run=remote.subprocess.run
    def diagnostic_run(*args,**kwargs):
        result=original_run(*args,**kwargs)
        if result.returncode and args and isinstance(args[0],list) and args[0][:1]==['/usr/bin/aa-exec']:
            stream=kwargs.get('stderr')
            if hasattr(stream,'seek'):
                stream.seek(0);print('ENZIMOS_LAB_REMOTE_ERROR '+stream.read(16000).decode(errors='replace'),flush=True)
        return result
    remote.subprocess.run=diagnostic_run
    try:
        time.sleep(2);check(server.poll() is None,'private Samba server exited')
        result=remote.initialize();check(result['scheduler_enabled'] is False,'remote init enabled work')
        copied=remote.replicate(point);remote.check()
        check(copied['source_snapshot']==point,'wrong point replicated')
        check(not any(line.split()[1:2]==['/backup-remote'] for line in Path('/proc/self/mounts').read_text().splitlines()),'share mount leaked into the host namespace')
        # Decrypt the server-side repository locally to independently compare its
        # captured tree with the source point. The server is guest-only storage.
        env=dict(PATH='/usr/bin',HOME='/nonexistent',LANG='C.UTF-8',RESTIC_REPOSITORY=str(repository/'restic'),RESTIC_PASSWORD_FILE=str(remote.PASSWORD),GOMAXPROCS='1')
        listing=subprocess.check_output(['restic','--no-cache','ls','--json',copied['remote_snapshot']],env=env,text=True)
        check('/backup-source/system' in listing and '/backup-source/home' in listing and '/backup-source/inventory/packages.txt' in listing,'remote contents incomplete')
        added=extra(repository,uid,gid,point) if extra else {}
        # An extra flow that deliberately adds local points (explicit retrieval) re-baselines.
        if added.pop('local_points_added',False):before={row['id'] for row in backup.snapshots(backup.read_config())}
        if retrieval:
            # A fresh remote-only fixture point avoids deleting/adopting any local
            # backup. Closed full-source labels contain deliberately tiny lab data;
            # this is transport/content retrieval, NOT a full-system restore proof.
            sources=[Path('/backup-source')/name for name in ('system','home','boot','inventory')]
            for folder in sources:folder.mkdir(parents=True,exist_ok=True)
            sample=sources[1]/'enzimos-user/remote-file';sample.parent.mkdir();sample.write_bytes(b'REMOTE-ONLY-LAB-CONTENT\n')
            subprocess.run(['restic','--no-cache','backup','--host','enzimos','--tag','enzimos-whole-linux',*map(str,sources)],env=env,check=True)
            remote_rows=json.loads(subprocess.check_output(['restic','--no-cache','snapshots','--json'],env=env,text=True))
            remote_point=max(remote_rows,key=lambda row:row['time'])['id']
            # The local lab-only writer ran as root; Samba serves the share as its account.
            native.run(['chown','-R',f'{uid}:{gid}',repository/'restic'])
            fetched=remote.retrieve('lab-retrieval',remote_point)
            check(fetched['remote_snapshot']==remote_point and not fetched['automatic_retry'],'retrieval result mismatch')
            data=backup.restic(backup.read_config(),['dump',fetched['local_snapshot'],'/backup-source/home/enzimos-user/remote-file'],capture=True).stdout
            check(data=='REMOTE-ONLY-LAB-CONTENT\n','retrieved file bytes mismatch')
            refuse(lambda:remote.retrieve('lab-retrieval',remote_point))
            check(before<={row['id'] for row in backup.snapshots(backup.read_config())},'retrieval removed old local points')
            before={row['id'] for row in backup.snapshots(backup.read_config())}
        pin=remote.control_path('backup-remote-pin.json').read_bytes()
        # A wrong share password fails at the SMB session, before Restic runs.
        SHARE_PASSWORD.write_text('WRONG-'+LAB_SHARE_PASSWORD+'\n');SHARE_PASSWORD.chmod(0o600);refuse(remote.check)
        SHARE_PASSWORD.write_text(LAB_SHARE_PASSWORD+'\n');SHARE_PASSWORD.chmod(0o600);remote.check()
        # A substituted share: another repository that the same Restic password opens
        # sits at the configured folder. The pinned repository ID refuses it.
        subprocess.run(['restic','--no-cache','init'],env=dict(env,RESTIC_REPOSITORY=str(other/'restic')),check=True,stdout=subprocess.DEVNULL)
        native.run(['chown','-R',f'{uid}:{gid}',other])
        server.terminate();server.wait(10);daemon.write_text(samba_config(other));server=start();time.sleep(2)
        refuse(remote.check);refuse(lambda:remote.replicate(point))
        check(remote.control_path('backup-remote-pin.json').read_bytes()==pin,'repository pin changed after a substituted share')
        server.terminate();server.wait(10);daemon.write_text(samba_config(repository));server=start();time.sleep(2);remote.check()
        # A NAS that is off: the copy is refused within the bounded connect, not hung.
        server.terminate();server.wait(10);started=time.monotonic();refuse(remote.check)
        check(time.monotonic()-started<120,'a silent NAS held the check');server=start();time.sleep(2)
        check({row['id'] for row in backup.snapshots(backup.read_config())}==before,'replication changed local recovery points')
        check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'transport changed inventory/authority')
        check(not (Path('/var/lib/enzimos-control')/'backup.enabled').exists(),'transport enabled scheduled backup')
        return {**added,'remote_point_retrieved_to_local':retrieval,'retrieval_fixture_not_full_system_restore':retrieval,'authenticated_smb_copy':True,'local_point_preserved':True,'remote_contents_observed':True,
                'wrong_share_password_refused':True,'substituted_share_refused_by_repository_pin':True,'silent_nas_bounded':True,'share_mount_private':True,
                'runtime_authority_preserved':True,'scheduler_enabled':False,'append_only_server':False,'network_scope':'guest-private-veth-only'}
    finally:
        remote.subprocess.run=original_run
        print(native.output(['journalctl','-k','-b','--no-pager','-n','80']),flush=True)
        server.terminate()
        try:server.wait(10)
        except subprocess.TimeoutExpired:server.kill();server.wait(5)
        log.close();print('ENZIMOS_SMB_LAB_LOG\n'+(BASE/'smbd.log').read_text()[-12000:],flush=True)
        native.run(['ip','link','delete','enz-bk-client']);native.run(['ip','netns','delete',NS])
