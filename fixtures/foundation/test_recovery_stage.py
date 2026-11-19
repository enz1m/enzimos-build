#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only setup for packaged staging. Boot activation is explicitly fixture code."""
import json
import os
from pathlib import Path
import re
import subprocess

import native
import generation_registry as registry

CONTROL = Path('/var/lib/enzimos-control')
ID = 'fdn-stage'


def prepare(check, review_only=False):
    import recovery_stage
    package = native.output(['pacman', '-Q', 'enzimos-native-policy'])
    check(package == 'enzimos-native-policy 0.1.0-29', 'wrong packaged recovery candidate')
    unprivileged = subprocess.run(['runuser', '-u', 'enzimos-user', '--', 'python', '/usr/lib/enzimos/recovery_stage.py',
                                  'prepare', '--id', ID, '--birth', 'fdn-success', '--generation', 'old-fdn-success'], capture_output=True, text=True)
    check(unprivileged.returncode != 0 and 'root authorization required' in unprivileged.stderr, 'ordinary user prepared recovery')
    result = recovery_stage.prepare(ID, 'fdn-success', 'old-fdn-success')
    path = CONTROL/'recovery-jobs'/f'{ID}.json';before = native.sha(path)
    try:recovery_stage.stage(ID, result['plan_sha256'])
    except native.Failure as exc:check('independent initramfs' in str(exc) or 'RAM-root' in str(exc), 'wrong online stage refusal')
    else:raise AssertionError('installed system executed recovery staging')
    for action in (registry.confirm_current, lambda:native.select_generation('fdn-success', 'linux'),
                   lambda:native.run_update('/etc/pacman-foundation.conf', 'blocked-recovery', {}, Path('/proc/cmdline').read_text().strip())):
        try:action()
        except native.Failure as exc:check('recovery staging requires explicit review' in str(exc), 'wrong planned recovery blocker')
        else:raise AssertionError('planned recovery allowed online transition')
    check(native.sha(path) == before, 'refused calls changed recovery plan')
    home = Path('/home/enzimos-admin/foundation-home-marker');home.write_text('NEWER-HOME-MUST-SURVIVE-ROOT-RESTORE\n')
    native.atomic_json(CONTROL/'packaged-recovery-source.json', dict(result, current_inventory=native.output(['pacman', '-Q']),
                      authority=native.authority_identity(), candidate_package=package))
    # Break only the named disposable root after the plan exists. Packaged recovery
    # must not execute or depend on its systemd; the read-only source remains intact.
    if not review_only:
        init = Path('/usr/lib/systemd/systemd');init.rename(init.with_name('systemd.lab-broken'))
    native.atomic_text('/boot/loader/loader.conf','default recovery.conf\ntimeout 0\neditor no\n')
    limine=Path('/boot/limine/limine.conf');text=limine.read_text()
    number=native.limine_number(text,'Independent enzimOS lab recovery')
    native.atomic_text(limine,re.sub(r'^default_entry: .*$',f'default_entry: {number}',text,flags=re.M))
    return {'plan': result, 'online_stage_refused': True, 'planned_transitions_blocked': True,
            'unprivileged_refused': True, 'main_init_broken': not review_only, 'plan_unchanged_by_refusals': True}


def boot(check, module_trial):
    record = json.loads((CONTROL/'restored-boot.json').read_text())
    source = json.loads((CONTROL/'packaged-recovery-source.json').read_text())
    job = json.loads((CONTROL/'recovery-jobs'/f'{ID}.json').read_text())
    step_path = CONTROL/'packaged-restored-step';step = int(step_path.read_text()) if step_path.exists() else 0
    flavor = 'linux' if step == 0 else 'linux-lts';check(step < 2, 'packaged recovery two-boot branch complete')
    check(native.output(['findmnt', '-n', '-o', 'FSROOT', '/']) == '/'+job['plan']['target_name'], 'wrong staged root booted')
    check(os.uname().release == record['kernels'][flavor], 'wrong restored kernel')
    check(native.output(['pacman', '-Q']) == (CONTROL/'packaged-recovery-inventory.txt').read_text(), 'staged package inventory changed')
    check(Path('/home/enzimos-admin/foundation-home-marker').read_text() == 'NEWER-HOME-MUST-SURVIVE-ROOT-RESTORE\n', 'newer home lost')
    check(native.authority_identity() == source['authority'], 'current authority lost across staged boot')
    check(job['phase'] == 'staged' and native.config()['root_subvol'] == job['root']['path'], 'staging journal/config mismatch')
    module_trial()
    native.atomic_text('/boot/loader/loader.conf', f'default {record["root"]}-linux-lts.conf\ntimeout 0\neditor no\n')
    path = Path('/boot/limine/limine.conf');native.atomic_text(path, re.sub(r'^default_entry: .*$', f'default_entry: {record["bios_first"]+1}', path.read_text(), flags=re.M))
    step_path.write_text(str(step+1))
    return {'root_uuid': job['root']['uuid'], 'kernel': os.uname().release, 'uefi': Path('/sys/firmware/efi').is_dir(),
            'flavor': flavor, 'stage': job['phase'], 'home_authority_preserved': True, 'boot_activation': 'lab-fixture-only',
            'packaged_policy_version': native.output(['pacman', '-Q', 'enzimos-native-policy']), 'retirement_enabled': False}
