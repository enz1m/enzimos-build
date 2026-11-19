#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Disposable guest install and real system-bus/polkit snapshot tests."""
import json
import os
from pathlib import Path
import subprocess
import native

CONTROL = Path('/var/lib/enzimos-control')
UNIT = 'enzimos-system-backend.service'


def qualify(check, payload):
    payload = Path(payload);package = payload/'system-backend.pkg.tar.zst'
    check(native.output(['pacman', '-Q', 'enzimos-native-policy']) == 'enzimos-native-policy 0.1.0-38', 'wrong native dependency')
    check(native.sha(package) == json.loads((payload/'backend-build.json').read_text())['sha256'], 'backend input changed')
    # A fresh LAB-only signing identity exists in this guest RAM only. No disabled
    # signature checking, host trust, production/private user credential access.
    key = Path('/run/backend-lab-signing');key.mkdir(mode=0o700)
    native.run(['gpg', '--homedir', key, '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
                'enzimOS DISPOSABLE backend package', 'ed25519', 'sign', '1d'])
    signature = Path('/run/system-backend.pkg.tar.zst.sig')
    native.run(['gpg', '--homedir', key, '--batch', '--detach-sign', '--output', signature, package])
    exported = subprocess.check_output(['gpg', '--homedir', str(key), '--batch', '--export'])
    subprocess.run(['gpg', '--homedir', '/etc/pacman.d/gnupg', '--batch', '--no-autostart', '--import'], input=exported, check=True)
    fingerprint = next(line.split(':')[9] for line in native.output(['gpg', '--homedir', key, '--with-colons', '--list-keys']).splitlines() if line.startswith('fpr:'))
    native.run(['gpg', '--homedir', '/etc/pacman.d/gnupg', '--batch', '--no-autostart', '--import-ownertrust'], input=fingerprint+':5:\n')
    native.run(['cp', package, '/run/system-backend.pkg.tar.zst'])
    native.run(['pacman', '--noconfirm', '-U', '/run/system-backend.pkg.tar.zst'])
    check(subprocess.run(['systemctl', 'is-active', '--quiet', UNIT]).returncode != 0, 'install activated service')
    native.run(['systemctl', 'daemon-reload'])
    native.run(['busctl', 'call', 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', 'ReloadConfig'])
    native.run(['systemctl', 'start', UNIT])
    check(native.output(['systemctl', 'is-active', UNIT]) == 'active', 'backend not active')
    before_packages = native.output(['pacman', '-Q']);before_authority = native.authority_identity()
    marker = Path('/home/enzimos-admin/backend-api-home-marker')
    check(not marker.exists(), 'fresh API home marker required')
    marker.write_text('NEWER-HOME-PRESERVED-BY-API\n');os.chown(marker, 1000, 1000)
    before_home = marker.read_bytes()
    native.run(['install', '-m', '0644', payload/'backend_api_client.py', '/usr/lib/enzimos-lab/backend_api_client.py'])
    def snapshots():return native.output(['snapper', '--no-dbus', '-c', 'home', '--csvout', 'list', '--columns', 'number'])
    # Ordinary scheduled history may create unrelated snapshots during this long
    # authentication matrix. Observe its real pause control in the isolated guest.
    pause=CONTROL/'home-history.disabled';check(not pause.exists(),'history already paused')
    pause.touch(mode=0o600)
    native.run(['systemctl','stop','enzimos-home-history.service'])
    # Retention is independent of creation pause. Isolate only the guest test's
    # cleanup timer so receipt/history comparisons cannot cross a scheduled prune.
    native.run(['systemctl','stop','snapper-cleanup.timer','snapper-cleanup.service'])
    before = snapshots()
    for user, mode in (('enzimos-user', 'deny-user'), ('enzimos-admin', 'deny-admin')):
        result = subprocess.run(['runuser', '-u', user, '--', 'python', '-I', '-B', '/usr/lib/enzimos-lab/backend_api_client.py', mode], capture_output=True, text=True, timeout=150)
        print(result.stdout+result.stderr, flush=True);check(result.returncode == 0, 'ordinary/inactive API refusal failed')
    check(snapshots() == before, 'denied calls created history')
    def authenticated(mode):
        unit = 'enzimos-api-client-'+mode
        native.run(['systemctl', 'mask', '--runtime', '--now', 'getty@tty2.service', 'autovt@tty2.service'])
        native.run(['chvt', '2'])
        log = Path('/run')/(unit+'.log');check(not log.exists(), 'fresh VT log required')
        args = ['systemd-run', '--quiet', '--wait', '--collect', '--unit='+unit, '--uid=enzimos-admin',
                '--property=PAMName=login', '--property=TTYPath=/dev/tty2', '--property=StandardInput=tty-force',
                '--property=StandardOutput=append:'+str(log), '--property=StandardError=append:'+str(log),
                '--setenv=XDG_SESSION_TYPE=tty', '--setenv=XDG_SESSION_CLASS=user',
                '/usr/bin/python', '-I', '-B', '/usr/lib/enzimos-lab/backend_api_client.py', mode]
        result = subprocess.run(args, capture_output=True, text=True, timeout=200)
        native.run(['journalctl', '--sync'])
        transcript = log.read_bytes()
        journal = subprocess.check_output(['journalctl', '-b', '--no-pager', '-o', 'cat', '-u', unit+'.service'])
        print('ENZIMOS_API_CLIENT_UNIT '+journal.decode(errors='replace'), flush=True)
        print('ENZIMOS_API_AUTH_TRANSCRIPT\n'+transcript.decode(errors='replace')+result.stderr, flush=True)
        (CONTROL/('api-'+mode+'.log')).write_bytes(transcript)
        check(result.returncode == 0, 'authenticated VT API failed')
        lines = [line for line in transcript.decode(errors='replace').splitlines() if line.startswith('ENZIMOS_API_CLIENT=')]
        check(len(lines) == 1, 'API client result absent')
        return json.loads(lines[0].split('=', 1)[1])

    try:allowed = authenticated('allow')
    except Exception:
        for args in (['journalctl', '-b', '--no-pager', '-n', '90', '-u', UNIT, '-u', 'polkit.service'],
                     ['pkaction', '--action-id', 'org.enzimos.system.home-history-create', '--verbose']):
            result = subprocess.run(args, capture_output=True, text=True, timeout=10)
            print('ENZIMOS_API_DIAGNOSTIC '+repr(args)+'\n'+result.stdout[-20000:]+result.stderr[-2000:], flush=True)
        raise
    check(snapshots() != before, 'authenticated history not created')
    before_lock = snapshots()
    with native.operation_lock():locked = authenticated('locked')
    check(snapshots() == before_lock, 'locked call created history')
    cancelled = authenticated('cancel')
    check(cancelled['authentication_cancelled'] and snapshots() == before_lock, 'cancelled auth created history')
    native.run(['systemctl', 'restart', UNIT])
    check(native.output(['systemctl', 'is-active', UNIT]) == 'active', 'service restart failed')
    result = subprocess.run(['runuser', '-u', 'enzimos-user', '--', 'python', '-I', '-B', '/usr/lib/enzimos-lab/backend_api_client.py', 'deny-user'], capture_output=True, text=True, timeout=150)
    print(result.stdout+result.stderr, flush=True);check(result.returncode == 0 and snapshots() == before_lock, 'restart leaked authority')
    submitted = authenticated('jobs-submit');after_job = snapshots()
    check(after_job != before_lock and submitted['job_result']['state']=='completed', 'durable job did not create history')
    native.run(['systemctl', 'restart', UNIT])
    repeated = authenticated('jobs-repeat')
    check(repeated['job_result']==submitted['job_result'] and snapshots()==after_job, 'completed job repeated mutation after restart')
    with native.operation_lock():authenticated('jobs-locked')
    check(snapshots()==after_job, 'locked durable job created history')
    native.run(['systemctl', 'restart', UNIT])
    uncertain = authenticated('jobs-status');authenticated('jobs-retry')
    print('ENZIMOS_DURABLE_HISTORY_BEFORE\n'+after_job+'\nENZIMOS_DURABLE_HISTORY_AFTER\n'+snapshots(),flush=True)
    check(uncertain['job_result']['state']=='uncertain' and snapshots()==after_job, 'uncertain job replayed after restart')
    check(native.output(['pacman', '-Q']) == before_packages and native.authority_identity() == before_authority, 'API changed package/authority')
    check(marker.read_bytes() == before_home, 'API changed home content')
    check(not (CONTROL/'backup.enabled').exists(), 'API enabled backup worker')
    native.run(['systemctl', 'stop', UNIT])
    pause.unlink()
    native.run(['systemctl','start','snapper-cleanup.timer'])
    return {'real_system_bus_polkit': True, 'admin_challenges': 3, 'new_home_snapshots': allowed['snapshots'],
            'inactive_and_ordinary_denied': True, 'no_retained_authorization': True, 'operation_lock_refused': locked['lock_refused'],
            'packages_home_authority_preserved': True, 'backup_jobs_disabled': True, 'service_stopped': True,
            'authentication_cancelled_without_snapshot': True, 'restart_preserves_denial': True,
            'durable_completed_deduplicated_after_restart': True, 'durable_uncertain_refuses_replay': True,
            'durable_job':submitted['job_result'],
            'ui_qualified': False, 'general_mutating_api_qualified': False}
