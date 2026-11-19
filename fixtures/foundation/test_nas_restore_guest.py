#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""NAS-source file restore entirely through the authenticated backend (payload-script).

Inside the guest-private SMB lab (Samba share, pinned repository ID): a new local lab point is replicated to the NAS
through the API (schema22); a NAS-only point (as if the local disk were lost) holding a
probe file from enzimos-admin's home is retrieved through the API (schema23) into the
local repository; export/grant/deliver (schemas19-21) then restore the file as a new
private file. Real polkit per call; restart dedup; reused retrieval ID refused. Tiny lab
points with the exact whole-system scope/tag/host, NOT full-system backups."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import native
import backup
import backup_remote as remote
import generation_registry as registry
import lab_versions
import test_remote_backup as lab
import test_root_api69 as api
from test_remote_rotation import local_point
from test_file_restore_guest import lab_point
from test_credential_review import pause_history,restore_history
from test_root_retirement import quiet_maintenance

HOME=Path('/home/enzimos-admin');PROBE='nas-probe.txt';GRANT='nas-grant'
OUTPUT=HOME/('enzimos-restored-'+GRANT+'.bin')


def remote_only_point(check,repository,uid,gid,content):
    sources=[Path('/run/nas-only-point')/name for name in ('system','home','boot','inventory')]
    for folder in sources:folder.mkdir(parents=True,exist_ok=True)
    (sources[3]/'packages.txt').write_text(native.output(['pacman','-Q'])+'\n')
    probe=sources[1]/'enzimos-admin'/PROBE;probe.parent.mkdir(exist_ok=True);probe.write_bytes(content)
    env=dict(PATH='/usr/bin',HOME='/nonexistent',LANG='C.UTF-8',RESTIC_REPOSITORY=str(repository/'restic'),RESTIC_PASSWORD_FILE=str(remote.PASSWORD),GOMAXPROCS='1')
    for folder in sources:
        target=Path('/backup-source')/folder.name;target.mkdir(exist_ok=True);native.run(['mount','--bind',folder,target])
    try:subprocess.run(['restic','--no-cache','backup','--host','enzimos','--tag','enzimos-whole-linux',*[str(Path('/backup-source')/f.name) for f in sources]],env=env,check=True,stdout=subprocess.DEVNULL)
    finally:
        for folder in sources:native.run(['umount',Path('/backup-source')/folder.name])
    # The lab writer ran as root; hand the objects to the Samba share's account.
    native.run(['chown','-R',f'{uid}:{gid}',repository/'restic'])
    rows=json.loads(subprocess.check_output(['restic','--no-cache','snapshots','--json'],env=env,text=True))
    return max(rows,key=lambda row:row['time'])['id'],env


def flow(check,repository,uid,gid,point):
    history=pause_history(check);quiet_maintenance(check)
    try:
        config,local=lab_point(check,b'LOCAL-LAB-POINT-FOR-NAS-REPLICATION\n')
        content=b'enzimOS NAS-only restore probe '+os.urandom(24).hex().encode()+b'\n'
        nas,env=remote_only_point(check,repository,uid,gid,content)
        before={row['id'] for row in backup.snapshots(config)};check(nas not in before,'NAS-only point already local')
        selections={'22':{'snapshot':local},'23':{'id':'nas-retrieval','snapshot':nas},'path':'/backup-source/home/enzimos-admin/'+PROBE,
                    'expected_sha256':hashlib.sha256(content).hexdigest()}
        api.write_selections(selections);inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
        native.run(['systemctl','start',api.UNIT])
        try:
            api.denials(check);cancelled=api.authenticated(check,'auth-cancel')
            check(not (remote.control_path('backup-retrievals')/'nas-retrieval.json').exists(),'denied/cancelled requests retrieved')
            done=api.authenticated(check,'nas');result=done['result']
            remote_rows=json.loads(subprocess.check_output(['restic','--no-cache','snapshots','--json'],env=env,text=True))
            check(sum(row.get('original')==local for row in remote_rows)==1,'API replication not on the NAS')
            after={row['id'] for row in backup.snapshots(config)}
            check(before<=after and after-before=={result['retrieve']['local_snapshot']},'retrieval did not add exactly one local point')
            check(OUTPUT.read_bytes()==content and OUTPUT.stat().st_uid==1000 and OUTPUT.stat().st_mode&0o777==0o600,'NAS-restored file wrong')
            check(subprocess.run(['runuser','-u','enzimos-user','--','test','-r',OUTPUT]).returncode!=0,'other user can read the NAS-restored file')
            ledger={str(p):native.sha(p) for p in (registry.CONTROL/'backend-operations').glob('*.json')}
            native.run(['systemctl','restart',api.UNIT]);completed=api.authenticated(check,'nas-completed')
            check(all(native.sha(Path(p))==v for p,v in ledger.items()),'restart changed ledger records')
            check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'NAS restore changed packages/authority')
        finally:native.run(['systemctl','stop',api.UNIT])
    finally:restore_history(check,history)
    return {'local_points_added':True,'nas_restore_api':True,'real_polkit_prompts':cancelled['password_prompts']+done['password_prompts']+completed['password_prompts'],
            'api_replicated_to_nas':True,'nas_only_point_retrieved_via_api':True,'retrieval_id_reuse_refused':True,'file_restored_from_nas_point':True,
            'other_user_cannot_read':True,'completed_restart_deduplicated':True,'denied_and_cancelled_no_state':True,'lab_points_not_full_system_backup':True}


def run(check,payload):
    # The SMB lab snapshots package inventory, so backend installation must precede it.
    api.install(check,payload);native.run(['systemctl','stop',api.UNIT]);local_point(check)
    return lab.qualify(check,payload,lab_versions.native(),False,lambda repository,uid,gid,point:flow(check,repository,uid,gid,point))
