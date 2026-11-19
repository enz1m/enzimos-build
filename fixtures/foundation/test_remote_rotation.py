#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Remote replica compromise rotation inside the guest-private SMB lab: new remote
encryption context, verified copy, a REAL process death at a switch boundary, reviewed
resume, discard, and the old remote repository left on the server (disclosed)."""
import json
import os
from pathlib import Path
import subprocess
import native
import backup_remote as remote
import backup_remote_rotation as rotation
import lab_versions
import test_remote_backup as lab
import generation_registry as registry
import test_root_api69 as api
PAYLOAD=None


def refused(check,expected,callable_):
    try:callable_()
    except native.Failure as exc:check(expected in str(exc),'wrong refusal: '+str(exc));return
    raise AssertionError('not refused: '+expected)


def rotate(check,repository,uid,gid,point):
    # Scheduled history/maintenance share the operation lock; pause them for the rotation.
    from test_credential_review import pause_history,restore_history
    from test_root_retirement import quiet_maintenance
    history=pause_history(check);quiet_maintenance(check)
    try:return steps(check,repository,uid,gid,point)
    finally:restore_history(check,history)


def steps(check,repository,uid,gid,point):
    config=json.loads(remote.CONFIG.read_text());new=dict(config,folder='restic-rotated')
    refused(check,'no remote rotation recorded',rotation.review)
    rotation.ROTATION_CONFIG.write_text(json.dumps(new));rotation.ROTATION_CONFIG.chmod(0o600)
    rotation.ROTATION_PASSWORD.write_text('ENZIMOS-PUBLIC-LAB-REMOTE-ROTATED-PASSWORD\n');rotation.ROTATION_PASSWORD.chmod(0o600)
    prepared=rotation.prepare()
    check(prepared['status']=='remote-rotation-copied-verified' and prepared['points']>=1 and prepared['old_password_refused'] and not prepared['old_remote_repository_deleted'],'remote rotation copy')
    refused(check,'already recorded',rotation.prepare)
    refused(check,'unfinished remote compromise rotation',lambda:remote.replicate(point))
    review=rotation.review();check((review['phase'],review['boundary'],review['next_action'])==('copied',0,'switch'),'copied review')
    # A real process death right after the third switch step (config switched, old password retired).
    child=os.fork()
    if child==0:
        try:rotation.advance(review['review_sha256'],'switch',lambda index:os._exit(9) if index==3 else None)
        finally:os._exit(3)
    _,status=os.waitpid(child,0);check(os.WIFEXITED(status) and os.WEXITSTATUS(status)==9,'switch child did not die at boundary 3')
    again=rotation.review();check((again['phase'],again['boundary'],again['next_action'])==('switching',3,'switch'),'interrupted boundary review')
    refused(check,'review changed',lambda:rotation.advance(review['review_sha256'],'switch'))
    refused(check,'unfinished remote compromise rotation',lambda:remote.replicate(point))
    # Resume and discard through the authenticated backend (fresh polkit per call).
    api.install(check,PAYLOAD);ledger=registry.CONTROL/'backend-operations'
    try:
        api.write_selections({'15':{'rotation':'remote'},'16':{'rotation':'remote','review_sha256':'0'*64,'action':'switch'}})
        api.denials(check);cancelled=api.authenticated(check,'auth-cancel');executed=api.authenticated(check,'remote')
        check(json.loads(remote.CONFIG.read_text())==new,'API switch did not install the new configuration')
        check(rotation.read_journal()['phase']=='complete' and not rotation.RETIRED_PASSWORD.exists() and not rotation.RETIRED_CONFIG.exists(),'API discard')
        saved={str(p):native.sha(p) for p in ledger.glob('*.json')}
        native.run(['systemctl','restart',api.UNIT]);completed=api.authenticated(check,'remote-completed')
        check(all(native.sha(Path(p))==v for p,v in saved.items()),'restart changed ledger records')
    finally:
        native.run(['systemctl','stop',api.UNIT])
    remote.check()
    replicated=remote.replicate(point);check(replicated['repository_id']==json.loads(remote.control_path('backup-remote-pin.json').read_text())['repository_id'],'replication after rotation uses the new remote')
    check((repository/'restic'/'config').is_file(),'old remote repository unexpectedly gone from the server')
    return {'remote_rotation_api':True,'password_prompts':cancelled['password_prompts']+executed['password_prompts']+completed['password_prompts'],
            'completed_restart_deduplicated':True,'remote_rotation_copied_verified':True,'old_remote_password_refused_on_new':True,'real_process_death_at_switch_boundary':True,
            'reviewed_resume_only':True,'replication_blocked_while_unfinished':True,'retired_local_material_discarded':True,
            'replication_after_rotation':True,'old_remote_repository_left_on_server':True,'old_remote_repository_deleted':False}


def local_point(check):
    """The SMB lab replicates an existing local point; make one if this lineage has none."""
    import backup
    from test_credential_review import pause_history,restore_history
    native.run(['mount','/backup-repository']);history=pause_history(check)
    try:
        config=backup.read_config()
        if not Path(config['repository'],'config').exists():backup.initialize()
        if not backup.snapshots(config):
            # A tiny lab-only point with the exact whole-system scope/tag/host (as the remote
            # retrieval fixture does remotely): the SMB lab share lives on the same
            # 2 GiB backup disk, so a full system point would exhaust it twice over.
            # NOT a full-system backup; transport/rotation of real encrypted points only.
            import subprocess
            sources=[Path('/run/lab-point')/name for name in ('system','home','boot','inventory')]
            for folder in sources:folder.mkdir(parents=True,exist_ok=True)
            (sources[3]/'packages.txt').write_text(native.output(['pacman','-Q'])+'\n');(sources[1]/'lab-marker').write_text('REMOTE-ROTATION-LAB-POINT\n')
            env=dict(PATH='/usr/bin',HOME='/nonexistent',LANG='C.UTF-8',RESTIC_REPOSITORY=config['repository'],RESTIC_PASSWORD_FILE=config['password_file'],GOMAXPROCS='1')
            Path('/backup-source').mkdir(exist_ok=True)
            for folder in sources:
                target=Path('/backup-source')/folder.name;target.mkdir(exist_ok=True);native.run(['mount','--bind',folder,target])
            try:subprocess.run(['restic','--no-cache','backup','--host','enzimos','--tag','enzimos-whole-linux',*[str(Path('/backup-source')/f.name) for f in sources]],env=env,check=True)
            finally:
                for folder in sources:native.run(['umount',Path('/backup-source')/folder.name])
        check(backup.snapshots(config),'local recovery point missing')
    finally:
        restore_history(check,history);native.run(['umount','/backup-repository'])


class ReadTee:
    """Lab-only diagnostic: observe the bytes the unchanged production runner reads so a
    failed restic command's error tail can be printed. Production behaviour is unchanged."""
    def __init__(self,real):self.real=real;self.tail=bytearray()
    def read(self,fd,size):
        data=self.real.read(fd,size);self.tail.extend(data);del self.tail[:-8192];return data
    def __getattr__(self,name):return getattr(self.real,name)


def qualify(check,payload):
    global PAYLOAD
    # Install the backend BEFORE the SMB lab snapshots the package inventory it preserves.
    PAYLOAD=payload;api.install(check,payload);native.run(['systemctl','stop',api.UNIT]);local_point(check)
    tee=ReadTee(remote.os);remote.os=tee
    try:return run(check,payload)
    except native.Failure:
        print('ENZIMOS_LAB_REMOTE_ERROR '+tee.tail.decode(errors='replace'),flush=True);raise
    finally:remote.os=tee.real


def run(check,payload):
    return lab.qualify(check,payload,lab_versions.native(),False,lambda repository,uid,gid,point:rotate(check,repository,uid,gid,point))
