#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real systemd opt-in controls in the guest; no clock changes or timer bypass."""
import json
from pathlib import Path
import subprocess
import native
import backup
import backup_schedule as schedule


def qualify(check):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-52','wrong schedule candidate')
    native.run(['mount','/backup-repository']);config=backup.read_config();before={r['id'] for r in backup.snapshots(config)}
    inventory=native.output(['pacman','-Q']);authority=native.authority_identity();marker=schedule.marker()
    check(not marker.exists(),'fixture already opted in')
    for user in ('enzimos-user','enzimos-admin'):
        denied=subprocess.run(['runuser','-u',user,'--','python','/usr/lib/enzimos/backup_schedule.py','enable'],capture_output=True,text=True)
        check(denied.returncode!=0 and 'root authorization required' in denied.stderr,'ordinary user changed backup schedule')
    enabled=schedule.enable();check(enabled['immediate_backup_started'] is False,'enable started backup')
    check(native.output(['systemctl','is-enabled',schedule.TIMER])=='enabled','timer not enabled')
    check(subprocess.run(['systemctl','is-active','--quiet',schedule.TIMER]).returncode!=0,'enable implicitly started timer')
    schedule.automatic_guard();check({r['id'] for r in backup.snapshots(config)}==before,'schedule enable changed repository')
    body=Path('/etc/enzimos/backup.json').read_bytes();changed=dict(config,keep_last=7);Path('/etc/enzimos/backup.json').write_text(json.dumps(changed))
    try:
        try:backup.backup(True)
        except native.Failure as exc:check('binding changed' in str(exc),'wrong automatic drift refusal')
        else:raise AssertionError('changed configuration retained automatic authority')
    finally:Path('/etc/enzimos/backup.json').write_bytes(body)
    # Real timer unit can start while no service payload is forced; do not change
    # system time or shorten shipping intervals to manufacture a timer pass.
    native.run(['systemctl','start',schedule.TIMER]);check(native.output(['systemctl','is-active',schedule.TIMER])=='active','timer start failed')
    with native.operation_lock():disabled=schedule.disable()
    check(disabled['inflight_backup_cancelled'] is False and not marker.exists(),'disable did not revoke future work')
    check(subprocess.run(['systemctl','is-active','--quiet',schedule.TIMER]).returncode!=0,'timer remained active')
    original=backup.read_config
    def forbidden():raise AssertionError('disabled automatic backup scanned source/config')
    backup.read_config=forbidden
    try:check(backup.backup(True)=={'status':'disabled-no-source-scan'},'disabled automatic backup entered')
    finally:backup.read_config=original
    check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'schedule changed packages/authority')
    return {'root_only_controls':True,'enable_no_immediate_backup':True,'configuration_drift_revokes_automatic_entry':True,
            'real_systemd_timer_started_and_stopped':True,'disable_while_operation_locked':True,'disabled_no_source_scan':True,
            'packages_authority_preserved':True,'calendar_firing_qualified':False}
