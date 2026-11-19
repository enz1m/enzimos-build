#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real compromise rotation into a new restic encryption context with process kills,
a synced QMP cut at a switch boundary and later-boot digest-bound continuation."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import native
import backup
import backup_rotation as rotation
import backup_schedule as schedule
from test_credential_review import pause_history,restore_history

import lab_versions
VERSION=lab_versions.native()
STATE=Path('/var/lib/enzimos-control/rotation-cut-fixture.json')
OLD_COPY=Path('/run/enzimos/lab-old-password')
PASSWORDS={'rot-a':'ENZIMOS-PUBLIC-LAB-ROTATION-A\n','rot-b':'ENZIMOS-PUBLIC-LAB-ROTATION-B\n'}
HELPER='''
import os,signal,sys,threading
sys.path.insert(0,'/usr/lib/enzimos');import backup_rotation as rotation
mode,identifier,value=sys.argv[1],sys.argv[2],sys.argv[3]
def die(*_):os.killpg(os.getpgid(0),signal.SIGKILL)
if mode=='prepare':
    original=rotation.rotation_restic
    def wrapped(args,*rest,**named):
        if args[0]=='copy':threading.Timer(float(value),die).start()
        return original(args,*rest,**named)
    rotation.rotation_restic=wrapped;rotation.prepare(identifier)
else:
    review=rotation.review(identifier)
    def hook(step):
        if str(step)==value:
            if value=='2' and len(sys.argv)>4:
                os.sync();print('ENZIMOS_ROTATION_CUT_READY switch-2',flush=True)
                import time
                while True:time.sleep(1)
            die()
    rotation.advance(identifier,review['review_sha256'],mode,step_hook=hook)
'''


def helper(check,mode,identifier,value,cut=False,expect_kill=True):
    args=['python','-I','-B','-c',HELPER,mode,identifier,str(value)]+(['cut'] if cut else [])
    if cut:
        # The host observes the cut marker through inherited stdout.
        subprocess.run(args,start_new_session=True);raise AssertionError('rotation cut did not stop the guest')
    result=subprocess.run(args,capture_output=True,text=True,start_new_session=True,timeout=3000)
    if expect_kill:check(result.returncode==-signal.SIGKILL,'rotation helper was not killed: '+result.stderr[-400:])
    else:check(result.returncode==0,'rotation helper failed: '+result.stderr[-400:])


def write_secret(path,text):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'w') as stream:stream.write(text);stream.flush();os.fsync(stream.fileno())


def refused(expected,callable_):
    try:callable_()
    except (native.Failure,OSError) as exc:
        if expected not in str(exc):raise AssertionError('wrong refusal: '+str(exc))
        return True
    raise AssertionError('operation was not refused: '+expected)


def material():
    return {'inventory':native.output(['pacman','-Q']),'authority':native.authority_identity(),
            'home':native.output(['btrfs','subvolume','show','/home']).splitlines()[:3]}


def normal_refuses():
    try:backup.snapshots(backup.read_config())
    except (native.Failure,OSError,subprocess.CalledProcessError):return True
    return False


def points_of(repository,password):return rotation.points(repository,password)


def switch_all(check,identifier,old_password,kills=True):
    """Kill after every intermediate boundary, review each exact state, then finish."""
    review=rotation.review(identifier);check(review['next_action']=='switch' and review['boundary']==0,'copied rotation boundary')
    refused('review changed',lambda:rotation.advance(identifier,'0'*64,'switch'))
    refused('requires switch',lambda:rotation.advance(identifier,review['review_sha256'],'discard'))
    seen=[]
    if kills:
        for index in (1,2,3,4):
            helper(check,'switch',identifier,index)
            review=rotation.review(identifier);check(review['phase']=='switching' and review['boundary']==index,'wrong boundary after kill')
            check(normal_refuses(),'normal backup access accepted mid-switch');seen.append(index)
            if index==3:
                # A foreign object at a fixed name is never guessed around.
                write_secret(rotation.guard.PASSWORD,'ENZIMOS-FOREIGN-PASSWORD\n')
                refused('exact recorded boundary',lambda:rotation.review(identifier))
                os.unlink(rotation.guard.PASSWORD)
                check(rotation.review(identifier)['boundary']==3,'foreign removal did not restore boundary')
    review=rotation.review(identifier)
    result=rotation.advance(identifier,review['review_sha256'],'switch')
    check(result['status']=='rotation-switched' and result['old_access_revoked'] is False,'switch result')
    return seen


def verify_switched(check,identifier,old_points,old_password_file):
    record=rotation.records(rotation.folder())[identifier]
    config=backup.read_config();current=backup.snapshots(config)
    check(sorted(row.get('original') for row in current)==old_points,'current repository lacks exact copied lineage')
    check(rotation.refuses(rotation.guard.REPOSITORY,old_password_file),'old password opens the switched repository')
    found=rotation.keys(rotation.guard.REPOSITORY,rotation.guard.PASSWORD);check(len(found)==1,'switched repository key count')
    return record


def discard(check,identifier,old_password_file,kill=True):
    review=rotation.review(identifier);check(review['next_action']=='discard','switched rotation next action')
    check(sorted(rotation.points(rotation.RETIRED,rotation.RETIRED_PASSWORD))==rotation.records(rotation.folder())[identifier]['old_points'],'retired repository unreadable before discard')
    if kill:
        helper(check,'discard',identifier,'discarding')
        check(rotation.review(identifier)['phase']=='discarding','discard kill boundary')
    review=rotation.review(identifier);result=rotation.advance(identifier,review['review_sha256'],'discard')
    check(result['status']=='rotation-complete' and result['external_copies_revoked'] is False,'discard result')
    check(not os.path.lexists(rotation.RETIRED) and not os.path.lexists(rotation.RETIRED_PASSWORD),'retired material remains')
    check(rotation.records(rotation.folder())[identifier]['phase']=='complete','rotation receipt incomplete')
    refused('already finished',lambda:rotation.review(identifier))
    check(rotation.refuses(rotation.guard.REPOSITORY,old_password_file),'old password opens repository after discard')
    backup.restic(backup.read_config(),['check','--read-data'],capture=True)


def controls(check):
    native.run(['mount','/backup-repository']);config=backup.read_config()
    if not Path(config['repository'],'config').exists():backup.initialize()
    check(not schedule.marker().exists(),'unexpected automatic backup opt-in')
    if not backup.snapshots(config):backup.backup(False)
    rows=backup.snapshots(config);old=sorted(row['id'] for row in rows);check(old,'fixture needs an existing point')
    lineage=sorted(rotation.lineage(row) for row in rows)
    before=material();pin=rotation.pin_sha();binding=schedule.binding(config)
    write_secret(OLD_COPY,Path(config['password_file']).read_text())
    # Preconditions are checked before any journal or staging object exists.
    refused('',lambda:rotation.prepare('no-input'))
    write_secret(rotation.ROTATION_PASSWORD,OLD_COPY.read_text())
    refused('already opens the current repository',lambda:rotation.prepare('same-password'))
    os.unlink(rotation.ROTATION_PASSWORD);write_secret(rotation.ROTATION_PASSWORD,PASSWORDS['rot-a'])
    schedule.enable();refused('disable automatic backup',lambda:rotation.prepare('scheduled'));schedule.disable()
    for user in ('enzimos-user','enzimos-admin'):
        result=subprocess.run(['runuser','-u',user,'--','python','/usr/lib/enzimos/backup_rotation.py','--id','x','--action','prepare'],capture_output=True,text=True)
        check(result.returncode!=0 and 'root authorization required' in result.stderr,'ordinary user may rotate')
    check(not rotation.folder().exists() or not any(rotation.folder().iterdir()),'refused rotation left a journal')
    check(not os.path.lexists(rotation.STAGE),'refused rotation left staging')
    # Real process death during copying leaves only an abandonable stage.
    helper(check,'prepare','killed-copy',6)
    review=rotation.review('killed-copy');check(review['phase']=='prepared' and review['next_action']=='abandon','killed copy review')
    refused('other unfinished rotation',lambda:rotation.prepare('blocked'))
    refused('review changed',lambda:rotation.advance('killed-copy','0'*64,'abandon'))
    rotation.advance('killed-copy',review['review_sha256'],'abandon')
    check(not os.path.lexists(rotation.STAGE) and rotation.pin_sha()==pin and sorted(row['id'] for row in backup.snapshots(config))==old,'abandon changed current repository')
    # Full rotation with kills after every switch boundary and during discard.
    prepared=rotation.prepare('rot-a');check(prepared['points']==len(old) and prepared['old_password_refused_by_new'],'rotation copy')
    seen=switch_all(check,'rot-a',OLD_COPY)
    verify_switched(check,'rot-a',lineage,OLD_COPY)
    discard(check,'rot-a',OLD_COPY)
    check(material()==before,'rotation changed packages/authority/home')
    check(schedule.binding(backup.read_config())!=binding,'automatic opt-in binding survived rotation')
    return {'preconditions_refused_without_journal':True,'ordinary_users_denied':True,'killed_copy_abandoned':True,
            'points_reencrypted':len(old),'switch_boundaries_killed':seen,'foreign_object_refused':True,
            'normal_access_refused_mid_switch':True,'old_password_refused_by_new_repository':True,'discard_kill_resumed':True,
            'retired_repository_removed':True,'repository_data_checked':True,'packages_authority_home_preserved':True,
            'external_copies_revoked':False,'media_remanence_addressed':False,'physical_power_loss':False}


def cut(check,history):
    native.run(['mount','/backup-repository']);config=backup.read_config()
    old=sorted(rotation.lineage(row) for row in backup.snapshots(config))
    os.unlink(OLD_COPY) if OLD_COPY.exists() else None
    write_secret(OLD_COPY,Path(config['password_file']).read_text());write_secret(rotation.ROTATION_PASSWORD,PASSWORDS['rot-b'])
    check(rotation.prepare('rot-b')['points']==len(old),'second rotation copy')
    native.atomic_json(STATE,{'boot_id':native.boot_id(),'old_points':old,'old_password':OLD_COPY.read_text(),'material':material(),'history':history})
    os.sync();helper(check,'switch','rot-b',2,cut=True)


def review_after_cut(check):
    saved=json.loads(STATE.read_text());check(saved['boot_id']!=native.boot_id(),'later boot required')
    native.run(['mount','/backup-repository'])
    write_secret(OLD_COPY,saved['old_password'])
    review=rotation.review('rot-b');check(review['phase']=='switching' and review['boundary']==2,'cut boundary not preserved')
    check(normal_refuses(),'normal access accepted at cut boundary')
    refused('review changed',lambda:rotation.advance('rot-b','0'*64,'switch'))
    result=rotation.advance('rot-b',review['review_sha256'],'switch');check(result['status']=='rotation-switched','later switch')
    verify_switched(check,'rot-b',saved['old_points'],OLD_COPY)
    discard(check,'rot-b',OLD_COPY,kill=False)
    check(material()==saved['material'],'later rotation changed packages/authority/home')
    return saved['history'],{'later_boot':True,'cut_boundary':2,'normal_access_refused_at_cut':True,'digest_bound_continuation':True,
                             'old_password_refused_by_new_repository':True,'retired_repository_removed':True,'repository_data_checked':True,
                             'packages_authority_home_preserved':True,'automatic_replay':False,'physical_power_loss':False}


def qualify(check,selection):
    check(native.output(['pacman','-Q','enzimos-native-policy'])==VERSION,'wrong rotation candidate')
    if selection=='backup-rotation-review':
        history,result=review_after_cut(check);restore_history(check,history);return result
    history=pause_history(check)
    if selection=='backup-rotation-cut':cut(check,history)
    try:return controls(check)
    finally:
        for path in (rotation.ROTATION_PASSWORD,OLD_COPY):
            if path.exists():path.unlink()
        restore_history(check,history)
