#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only restic destination identity/reconnect and fail-closed controls."""
import json
import os
from pathlib import Path

import backup
import backup_destination as guard
import native

CONTROL = Path('/var/lib/enzimos-control')


def qualify(check):
    check(native.output(['pacman', '-Q', 'enzimos-native-policy']) == 'enzimos-native-policy 0.1.0-33', 'wrong backup hardening package')
    native.run(['mount', '/backup-repository'])
    config = backup.read_config();original_config = guard.CONFIG.read_bytes()
    original_inventory = native.output(['pacman', '-Q']);original_authority = native.authority_identity()
    repository = guard.REPOSITORY
    check(not (repository/'config').exists(), 'fresh uninitialized repository required')
    backup.initialize();pinned = (CONTROL/'backup-destination.json').read_bytes()
    c = backup.read_config();before = guard.before(c)
    check(backup.snapshots(c) == [], 'new restic repository has snapshots')
    marker = CONTROL/'backup.enabled';check(not marker.exists(), 'automatic backup unexpectedly enabled')
    check(backup.backup(True)['status'] == 'disabled-no-source-scan', 'automatic opt-in ignored')
    def refuse(action, expected):
        try:action()
        except native.Failure as exc:check(expected in str(exc), 'wrong destination refusal: '+str(exc))
        else:raise AssertionError('unsafe backup destination accepted')
        check((CONTROL/'backup-destination.json').read_bytes() == pinned, 'refusal changed destination pin')
    changed = dict(c, destination_uuid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');guard.CONFIG.write_text(json.dumps(changed))
    try:refuse(backup.read_config, 'identity mismatch')
    finally:guard.CONFIG.write_bytes(original_config)
    # A same-filesystem path is not enough: a bind-mounted subdirectory must fail.
    probe = Path('/var/lib/enzimos-bind-destination-probe');probe.mkdir(mode=0o755)
    native.run(['umount', '/backup-repository']);native.run(['mount', '--bind', probe, '/backup-repository'])
    try:refuse(backup.read_config, 'whole Btrfs')
    finally:native.run(['umount', '/backup-repository'])
    refuse(backup.read_config, 'explicit unique backup mount')
    native.run(['mount', '/backup-repository']);after = guard.before(c)
    check(before['filesystem_uuid'] == after['filesystem_uuid'] and before['repository_sha256'] == after['repository_sha256'], 'reconnect changed persistent binding')
    check(before['mount']['unique_mount_id'] != after['mount']['unique_mount_id'], 'reconnect did not exercise unique mount change')
    check(backup.snapshots(c) == [], 'reconnected repository not usable')
    # A nested mount can hide repository contents while the outer mount is unchanged.
    native.run(['mount', '-t', 'tmpfs', '-o', 'mode=0700,size=1m', 'tmpfs', repository])
    try:refuse(lambda:backup.snapshots(c), 'nested backup destination mount')
    finally:native.run(['umount', repository])
    config_path = repository/'config';body = config_path.read_bytes();config_path.write_bytes(body+b' ')
    try:refuse(lambda:backup.snapshots(c), 'binding changed')
    finally:config_path.write_bytes(body)
    # Configuration unknown fields and inherited command/password environment refuse
    # or are ignored before execution, never used as a root shell capability.
    guard.CONFIG.write_text(json.dumps(dict(c, password_command='touch /run/forbidden-backup-command')))
    try:refuse(backup.read_config, 'configuration fields')
    finally:guard.CONFIG.write_bytes(original_config)
    os.environ['RESTIC_PASSWORD_COMMAND'] = 'touch /run/forbidden-backup-command'
    os.environ['RESTIC_PASSWORD'] = 'WRONG-ENVIRONMENT-PASSWORD'
    try:check(backup.snapshots(c) == [], 'ambient environment changed repository access')
    finally:os.environ.pop('RESTIC_PASSWORD_COMMAND');os.environ.pop('RESTIC_PASSWORD')
    check(not Path('/run/forbidden-backup-command').exists(), 'ambient password command executed')
    # Replacement after the coordinator's earlier observation is detected rather
    # than persisting a success receipt for another mount instance.
    refuse(lambda:guard.after(c, before), 'changed during operation')
    backup.restic(c, ['check', '--read-data'])
    check(native.output(['pacman', '-Q']) == original_inventory and native.authority_identity() == original_authority, 'destination checks changed packages/authority')
    check((CONTROL/'backup-destination.json').read_bytes() == pinned and not marker.exists(), 'destination controls changed pin or activated jobs')
    return {'real_restic_initialized_pinned_checked': True, 'wrong_filesystem_refused': True,
            'bind_subdirectory_refused': True, 'unmounted_refused': True, 'same_repository_reconnect_passed': True,
            'repository_config_drift_refused': True, 'unknown_config_refused': True, 'ambient_credentials_ignored': True,
            'changed_mount_during_job_refused': True, 'nested_mount_refused': True,
            'legacy_mount_id_reused': before['mount']['mount_id'] == after['mount']['mount_id'],
            'unique_mount_ids': [before['mount']['unique_mount_id'], after['mount']['unique_mount_id']],
            'automatic_disabled': True, 'packages_authority_pin_preserved': True,
            'repository_binding_sha256': native.sha(CONTROL/'backup-destination.json'), 'retirement_enabled': False}
