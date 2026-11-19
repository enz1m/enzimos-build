#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Administrator file restore through the backend with real polkit (payload-script; two runs).

Run 1: a tiny lab recovery point (exact whole-system scope/tag/host, NOT a full-system
backup: the 2 GiB lab backup disk) holds a probe file from enzimos-admin's home; the live
file is then damaged. Through the API: export (schema19) -> grant to the current account
(schema20) -> deliver (schema21) as a NEW private file; stale/missing-plan refusals, replay
refusal after delivery, and a collision delivery that must end uncertain without
overwriting. Restart dedup. Run 2 (later boot): completed jobs dedup, the uncertain job
never replays, the grant expires with the boot, outputs unchanged."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import native
import backup
import generation_registry as registry
import backup_delivery as delivery
from test_credential_review import pause_history,restore_history
from test_root_retirement import quiet_maintenance
import test_root_api69 as api

STATE=Path('/var/lib/enzimos-control/file-restore-api-fixture.json')
HOME=Path('/home/enzimos-admin');PROBE=HOME/'restore-probe.txt'
EXPORT='restore-probe';GRANT='restore-grant';COLLISION='restore-collision'
OUTPUT=HOME/('enzimos-restored-'+GRANT+'.bin');BLOCKED=HOME/('enzimos-restored-'+COLLISION+'.bin')


def lab_point(check,content):
    config=backup.read_config()
    if not Path(config['repository'],'config').exists():backup.initialize()
    before={row['id'] for row in backup.snapshots(config)}
    sources=[Path('/run/lab-restore-point')/name for name in ('system','home','boot','inventory')]
    for folder in sources:folder.mkdir(parents=True,exist_ok=True)
    (sources[3]/'packages.txt').write_text(native.output(['pacman','-Q'])+'\n')
    probe=sources[1]/'enzimos-admin'/PROBE.name;probe.parent.mkdir(exist_ok=True);probe.write_bytes(content)
    env=dict(PATH='/usr/bin',HOME='/nonexistent',LANG='C.UTF-8',RESTIC_REPOSITORY=config['repository'],RESTIC_PASSWORD_FILE=config['password_file'],GOMAXPROCS='1')
    Path('/backup-source').mkdir(exist_ok=True)
    for folder in sources:
        target=Path('/backup-source')/folder.name;target.mkdir(exist_ok=True);native.run(['mount','--bind',folder,target])
    try:subprocess.run(['restic','--no-cache','backup','--host','enzimos','--tag','enzimos-whole-linux',*[str(Path('/backup-source')/f.name) for f in sources]],env=env,check=True,stdout=subprocess.DEVNULL)
    finally:
        for folder in sources:native.run(['umount',Path('/backup-source')/folder.name])
    added=[row['id'] for row in backup.snapshots(config) if row['id'] not in before];check(len(added)==1,'lab point not created')
    return config,added[0]


def material(config):
    def file(path):
        if not path.exists():return None
        info=path.stat();return {'sha256':native.sha(path),'uid':info.st_uid,'mode':info.st_mode&0o777}
    return {'output':file(OUTPUT),'blocked':file(BLOCKED),'live':file(PROBE),'points':sorted(row['id'] for row in backup.snapshots(config)),
            'inventory':native.output(['pacman','-Q']),'authority':native.authority_identity()}


def first(check,payload):
    api.install(check,payload);history=pause_history(check);quiet_maintenance(check)
    native.run(['mount','/backup-repository'])
    content=b'enzimOS lab file-restore probe '+os.urandom(24).hex().encode()+b'\n'
    config,snapshot=lab_point(check,content)
    PROBE.write_bytes(b'DAMAGED-AFTER-BACKUP\n');os.chown(PROBE,1000,1000);PROBE.chmod(0o600)
    BLOCKED.write_bytes(b'KEEP-EXISTING\n');os.chown(BLOCKED,1000,1000);BLOCKED.chmod(0o600)
    before=material(config)
    selections={'19':{'id':EXPORT,'snapshot':snapshot,'path':'/backup-source/home/enzimos-admin/'+PROBE.name},
                          '20':{'id':GRANT,'export':EXPORT,'uid':1000},'21':{'id':GRANT,'grant_sha256':'0'*64},'expected_sha256':hashlib.sha256(content).hexdigest(),
                          'collision':COLLISION}
    api.write_selections(selections)
    try:
        api.denials(check);cancelled=api.authenticated(check,'auth-cancel')
        check(not (registry.CONTROL/'restore-exports'/EXPORT).exists(),'denied/cancelled requests exported')
        restored=api.authenticated(check,'restore')
        check(OUTPUT.read_bytes()==content and OUTPUT.stat().st_uid==1000 and OUTPUT.stat().st_mode&0o777==0o600,'restored file wrong')
        check(subprocess.run(['runuser','-u','enzimos-user','--','test','-r',OUTPUT]).returncode!=0,'other user can read the restored file')
        check(PROBE.read_bytes()==b'DAMAGED-AFTER-BACKUP\n' and BLOCKED.read_bytes()==b'KEEP-EXISTING\n','live/colliding file overwritten')
        check(delivery.status(GRANT)['status']=='complete' and delivery.status(COLLISION)['status']=='uncertain','native delivery states')
        after=material(config)
        check(all(after[key]==before[key] for key in ('live','blocked','points','inventory','authority')),'restore changed points/packages/authority/live files')
        native.run(['systemctl','restart',api.UNIT]);completed=api.authenticated(check,'restore-completed')
        check(material(config)==after,'restart changed restore material')
        native.atomic_json(STATE,{'boot_id':native.boot_id(),'material':after,'history':history,'selections':selections,
                                  'prompts':cancelled['password_prompts']+restored['password_prompts']+completed['password_prompts']});os.sync()
    finally:
        native.run(['systemctl','stop',api.UNIT]);native.run(['umount','/backup-repository'])
    return {'step':'restored','api_export_grant_deliver':True,'real_polkit_prompts':cancelled['password_prompts']+restored['password_prompts']+completed['password_prompts'],
            'denied_and_cancelled_no_state':True,'stale_plans_refused':True,'new_private_file_delivered':True,'other_user_cannot_read':True,
            'live_file_not_overwritten':True,'collision_uncertain_not_overwritten':True,'delivery_replay_refused':True,'completed_restart_deduplicated':True,
            'points_packages_authority_preserved':True,'lab_point_not_full_system_backup':True,'metadata_restored':False}


def second(check,payload,saved):
    check(saved['boot_id']!=native.boot_id(),'later boot required')
    # /run is per boot: the client reads its selections there.
    api.install(check,payload);api.write_selections(saved['selections']);native.run(['mount','/backup-repository'])
    try:
        config=backup.read_config();check(material(config)==saved['material'],'later boot restore material changed')
        check(delivery.status(GRANT)['status']=='complete' and delivery.status(COLLISION)['status']=='uncertain','later delivery states')
        for identifier in (GRANT,COLLISION):
            _,value=delivery.read_grant(identifier)
            try:delivery.deliver(identifier,value['grant_sha256'])
            except native.Failure as exc:check('no replay' in str(exc),'unexpected later delivery refusal: '+str(exc))
            else:check(False,'later delivery replayed')
        later=api.authenticated(check,'restore-completed')
        check(material(config)==saved['material'],'later review changed restore material')
    finally:
        native.run(['systemctl','stop',api.UNIT]);native.run(['umount','/backup-repository'])
    STATE.unlink();restore_history(check,saved['history'])
    return {'step':'reviewed','later_boot':True,'completed_deduplicated':True,'uncertain_never_replayed':True,'native_replay_refused':True,
            'outputs_unchanged':True,'real_polkit_prompts':later['password_prompts']}


def run(check,payload):
    if not STATE.exists():return first(check,payload)
    return second(check,payload,json.loads(STATE.read_text()))
