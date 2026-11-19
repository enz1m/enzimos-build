#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real restic recovery password addition, preservation and uncertain no-replay."""
import json
from pathlib import Path
import subprocess
import native
import backup
import backup_credentials as credentials


def qualify(check):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-52','wrong credential candidate')
    native.run(['mount','/backup-repository']);config=backup.read_config();before=credentials.key_list(config)
    points={row['id'] for row in backup.snapshots(config)};inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
    current_password=native.sha('/etc/enzimos/backup.password')
    credentials.NEXT.write_text('ENZIMOS-PUBLIC-LAB-RECOVERY-PASSWORD-ONLY\n');credentials.NEXT.chmod(0o600)
    for user in ('enzimos-user','enzimos-admin'):
        denied=subprocess.run(['runuser','-u',user,'--','python','/usr/lib/enzimos/backup_credentials.py','--id','unauthorized'],capture_output=True,text=True)
        check(denied.returncode!=0 and 'root authorization required' in denied.stderr,'ordinary enrollment permitted')
    result=credentials.enroll('recovery-one');after=credentials.key_list(config)
    check(set(before)<set(after) and len(after)==len(before)+1,'recovery key not added exactly once')
    check(credentials.key_list(config,True)[result['new_key']] is True,'new recovery password unusable')
    check(native.sha('/etc/enzimos/backup.password')==current_password,'existing backup password changed')
    try:credentials.enroll('recovery-one')
    except native.Failure:pass
    else:raise AssertionError('duplicate enrollment replayed')
    try:credentials.enroll('duplicate-password')
    except native.Failure as exc:check('already authenticates' in str(exc),'wrong duplicate password refusal')
    else:raise AssertionError('same recovery password added another key')
    # Test a persisted uncertain creation outcome via a new public candidate:
    # inject only the guest's trusted in-process final journal write, not restic.
    credentials.NEXT.write_text('ENZIMOS-PUBLIC-LAB-SECOND-RECOVERY-PASSWORD\n')
    save=credentials.registry.save_document
    def fail(path,value):
        if value.get('id')=='uncertain-two' and value.get('phase')=='complete':raise OSError('LAB completed receipt interruption')
        return save(path,value)
    credentials.registry.save_document=fail
    try:
        try:credentials.enroll('uncertain-two')
        except OSError:pass
        else:raise AssertionError('receipt fault not injected')
    finally:credentials.registry.save_document=save
    uncertain_keys=credentials.key_list(config);check(len(uncertain_keys)==len(after)+1,'uncertain key mutation absent')
    try:credentials.enroll('third-attempt')
    except native.Failure as exc:check('uncertain credential enrollment' in str(exc),'wrong pending enrollment refusal')
    else:raise AssertionError('uncertain credential operation replayed')
    check(credentials.key_list(config)==uncertain_keys and {row['id'] for row in backup.snapshots(config)}==points,'credential review changed keys/points')
    check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'credential operation changed packages/authority')
    check(result['old_access_revoked'] is False and result['credential_exported'] is False,'credential security overclaim')
    return {'new_recovery_password_authenticated_and_checked':True,'old_password_preserved':True,'ordinary_users_denied':True,
            'duplicate_id_and_password_refused':True,'post_add_receipt_failure_preserved':True,'uncertain_enrollment_never_replayed':True,
            'points_packages_authority_preserved':True,'old_access_revoked':False,'physical_power_loss':False}
