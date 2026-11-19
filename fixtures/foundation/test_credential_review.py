#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real enrollment effect interruption and later explicit receipt-only completion."""
import json
import os
from pathlib import Path
import subprocess
import time
import native
import backup
import backup_credentials as c

STATE=Path('/var/lib/enzimos-control/credential-review-fixture.json')
ID='receipt-interrupted'
PAUSE=Path('/var/lib/enzimos-control/home-history.disabled')
UNITS=('enzimos-home-history.timer','enzimos-home-history.service')


def pause_history(check):
    check(not PAUSE.exists(),'fixture requires history initially unpaused')
    states={unit:native.output(['systemctl','is-enabled',unit]) for unit in UNITS}
    active=subprocess.run(['systemctl','is-active','--quiet',UNITS[0]]).returncode==0
    native.run(['systemctl','stop',UNITS[0]]);native.atomic_text(PAUSE,'LAB credential interruption fixture\n')
    # Let an existing snapshot finish; never kill its worker to steal the lock.
    deadline=time.monotonic()+120
    while native.output(['systemctl','show','--value','--property=ActiveState',UNITS[1]]) in ('active','activating','deactivating'):
        check(time.monotonic()<deadline,'history worker did not finish within fixture budget');time.sleep(1)
    native.run(['systemctl','mask',*UNITS])
    return {'states':states,'timer_was_active':active}


def restore_history(check,schedule):
    native.run(['systemctl','unmask',*UNITS])
    check({unit:native.output(['systemctl','is-enabled',unit]) for unit in UNITS}==schedule['states'],'history unit settings not restored')
    PAUSE.unlink()
    if schedule['timer_was_active']:native.run(['systemctl','start',UNITS[0]])


def material(config):
    return {'keys':c.key_list(config),'key_files':{p.name:native.sha(p) for p in (c.guard.REPOSITORY/'keys').iterdir()},
            'points':sorted(row['id'] for row in backup.snapshots(config)),
            'inventory':native.output(['pacman','-Q']),'authority':native.authority_identity(),
            'password':native.sha(c.guard.PASSWORD)}


def qualify(check,selection):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-55','wrong credential review candidate')
    native.run(['mount','/backup-repository']);config=backup.read_config()
    if selection=='credential-review-resume':
        saved=json.loads(STATE.read_text());check(saved['boot_id']!=native.boot_id(),'later boot required')
        check(PAUSE.is_file() and not PAUSE.is_symlink(),'fixture history pause lost')
        for unit in UNITS:
            status=subprocess.run(['systemctl','is-enabled',unit],capture_output=True,text=True)
            check(status.stdout.strip()=='masked','fixture history mask lost')
        check(material(config)==saved['material'],'interrupted key/point/package/authority material changed')
        check(native.sha(c.folder()/(ID+'.json'))==saved['journal_sha256'],'interrupted credential journal changed')
    else:
        schedule=pause_history(check) if selection=='credential-review-cut' else None
        before=material(config)
        c.NEXT.write_text('ENZIMOS-PUBLIC-LAB-RECEIPT-RECOVERY-PASSWORD\n');c.NEXT.chmod(0o600)
        original=c.registry.save_document
        def save(path,value):
            if value.get('id')==ID and value.get('phase')=='complete':
                after=material(config)
                check(len(after['keys'])==len(before['keys'])+1 and set(before['keys'])<set(after['keys']),'exactly one actual key addition required')
                check(all(after[k]==before[k] for k in ('points','inventory','authority','password')),'enrollment changed protected material')
                native.atomic_json(STATE,{'boot_id':native.boot_id(),'material':after,'journal_sha256':native.sha(c.folder()/(ID+'.json')),'schedule':schedule})
                if selection=='credential-review-cut':
                    os.sync();print('ENZIMOS_CREDENTIAL_CUT_READY key-added',flush=True)
                    while True:time.sleep(1)
                raise OSError('LAB final receipt write interrupted')
            return original(path,value)
        c.registry.save_document=save
        try:
            try:c.enroll(ID)
            except OSError as exc:check(str(exc)=='LAB final receipt write interrupted','unexpected enrollment failure')
            else:raise AssertionError('receipt interruption not reached')
        finally:c.registry.save_document=original
        saved=json.loads(STATE.read_text())
    journal=c.folder()/(ID+'.json');pending=journal.read_bytes();unchanged=material(config)
    try:c.enroll('blocked-new-enrollment')
    except native.Failure as exc:check('uncertain credential enrollment' in str(exc),'wrong uncertain refusal')
    else:raise AssertionError('uncertain enrollment replayed')
    for user in ('enzimos-user','enzimos-admin'):
        for action in ('review','complete'):
            args=['runuser','-u',user,'--','python','/usr/lib/enzimos/backup_credentials.py','--id',ID,'--action',action]
            if action=='complete':args+=['--review-sha256','a'*64]
            result=subprocess.run(args,capture_output=True,text=True)
            check(result.returncode!=0 and 'root authorization required' in result.stderr,'ordinary credential review/completion permitted')
    review=c.review(ID)
    check(journal.read_bytes()==pending and material(config)==unchanged,'review mutated enrollment material')
    try:c.complete(ID,'0'*64)
    except native.Failure as exc:check('review changed' in str(exc),'wrong stale review refusal')
    else:raise AssertionError('stale credential digest accepted')
    check(journal.read_bytes()==pending and material(config)==unchanged,'stale completion changed material')
    completed=c.complete(ID,review['review_sha256'])
    record=c.records(c.folder())[ID]
    check(record['phase']=='complete' and record['new_key']==review['new_key'],'completion receipt missing')
    check(material(config)==unchanged,'completion changed keys/points/packages/password/authority')
    receipt=journal.read_bytes()
    try:c.complete(ID,review['review_sha256'])
    except native.Failure as exc:check('already complete' in str(exc),'wrong completed refusal')
    else:raise AssertionError('completion replayed')
    check(journal.read_bytes()==receipt and material(config)==unchanged,'completed retry changed material')
    if selection=='credential-review-resume':restore_history(check,saved['schedule'])
    return {'fixture_schedule_restored':True,'later_boot':selection=='credential-review-resume','actual_key_add_before_interruption':True,
            'uncertain_enrollment_blocks_new_key':True,'ordinary_users_denied':True,'review_preserves_material':True,
            'stale_digest_refused':True,'receipt_only_completion':True,'completed_retry_refused':True,
            'keys_points_packages_password_authority_preserved':True,'old_access_revoked':False,
            'physical_power_loss':False,'key_creation_replayed':completed['key_creation_replayed']}
