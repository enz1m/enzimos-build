#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Disposable guest-only activation fixture. Never alters host storage or firmware."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

import native
import generation_registry as registry
import recovery_stage as staging
import recovery_activation as activation
import root_ownership as birth

CONTROL = Path('/var/lib/enzimos-control')
ID = 'fdn-activation'
GENERATION = 'old-'+ID


def prepare(check, fixture_path, candidate=31):
    check(native.output(['pacman', '-Q', 'enzimos-native-policy']) == 'enzimos-native-policy 0.1.0-'+str(candidate), 'wrong activation package')
    check(not registry.status()['catalog']['generations'], 'fresh activation catalog required')
    # Verifier is lab-only, outside packaged policy, and enters the source before
    # snapshot creation; no newer policy is injected into a restored package cohort.
    shutil.copyfile(Path(fixture_path)/'test_recovery_activation.py', '/usr/lib/enzimos-lab/test_recovery_activation.py')
    with native.operation_lock():
        created = birth.create_fallback(ID)
        native.publish_boot('/boot', GENERATION, native.installed_kernels(), native.root_options(Path('/proc/cmdline').read_text().strip(), created['subvolume']))
    result = staging.prepare(ID, ID, GENERATION)
    inventory = native.output(['pacman', '-Q']);authority = native.authority_identity()
    home = Path('/home/enzimos-admin/foundation-home-marker');home.write_text('ACTIVATION-NEWER-HOME-PRESERVED\n')
    native.atomic_json(CONTROL/'activation-source.json', {'plan': result, 'inventory': inventory, 'authority': authority,
                      'kernels': native.installed_kernels(), 'policy_files': activation.policy_hashes(Path('/usr/lib/enzimos'))})
    ordinary = subprocess.run(['runuser', '-u', 'enzimos-user', '--', 'python', '/usr/lib/enzimos/recovery_activation.py', 'prepare', '--id', ID, '--job-sha256', 'f'*64], capture_output=True, text=True)
    check(ordinary.returncode != 0 and 'root authorization required' in ordinary.stderr, 'ordinary user reached activation')
    native.atomic_text('/boot/loader/loader.conf', 'default recovery.conf\ntimeout 0\neditor no\n')
    path = Path('/boot/limine/limine.conf');text = path.read_text();number = native.limine_number(text, 'Independent enzimOS lab recovery')
    native.atomic_text(path, re.sub(r'^default_entry: .*$', 'default_entry: '+str(number), text, flags=re.M))
    return {'prepared': result, 'compatible_policy_snapshotted': True, 'ordinary_user_refused': True, 'staged_root_selected': False}


def recover(check, selection):
    staging.TOP.mkdir(mode=0o700, parents=True, exist_ok=True);native.run(['mount', '--bind', '/mnt', staging.TOP])
    source = json.loads((CONTROL/'activation-source.json').read_text());plan = source['plan'];path = CONTROL/'recovery-jobs'/(ID+'.json')
    job = json.loads(path.read_text())
    before_artifacts = {str(p): native.sha(p) for folder in ('/boot/enzimos/generations', '/boot/enzimos-recovery') for p in Path(folder).rglob('*') if p.is_file()}
    def refuse(action, expected):
        before = {str(p): native.sha(p) for folder in ('recovery-jobs', 'recovery-activations') if (CONTROL/folder).exists() for p in (CONTROL/folder).iterdir() if p.is_file()}
        try:action()
        except native.Failure as exc:check(expected in str(exc), 'wrong activation refusal: '+str(exc))
        else:raise AssertionError('unsafe activation accepted')
        check(all(native.sha(p) == h for p, h in before.items()), 'refusal changed private journals')
    if job['phase'] == 'planned':staging.stage(ID, plan['plan_sha256'])
    reviewed = staging.review(ID, plan['plan_sha256'])
    if ID not in activation.records():
        target = staging.TOP/job['plan']['target_name']/'usr/lib/enzimos/native.py';body = target.read_bytes();target.write_bytes(body+b'\n# deliberate LAB drift\n')
        try:refuse(lambda:activation.prepare(ID, reviewed['job_sha256']), 'restored policy incompatible')
        finally:target.write_bytes(body)
        prepared = activation.prepare(ID, reviewed['job_sha256'])
    else:prepared = {'intent_sha256': activation.records()[ID]['intent']['intent_sha256']}
    digest = prepared['intent_sha256'];initial = activation.records()[ID]['phase']
    refuse(lambda:activation.publish(ID, 'f'*64), 'stale')
    value = activation.records()[ID]
    if value['phase'] in ('prepared', 'published'):
        path_bios = Path('/boot/limine/limine.conf');before = path_bios.read_bytes();path_bios.write_bytes(before+b'# unexpected LAB drift\n')
        try:refuse(lambda:activation.publish(ID, digest), 'metadata drift')
        finally:path_bios.write_bytes(before)
        def cut(name):
            if selection == 'recovery-activation-cut' and name == 'loader/entries/enzimos-staged-'+ID+'-linux.conf':
                os.sync();print('ENZIMOS_ACTIVATION_CUT_READY first-entry', flush=True)
                while True:time.sleep(1)
        activation.publish(ID, digest, cut)
    flavor = 'linux-lts' if selection == 'recovery-activation-lts' else 'linux'
    activation.select(ID, digest, flavor)
    value = activation.records()[ID]
    check(value['phase'] == 'selected' and value['selection']['flavor'] == flavor, 'activation selection incomplete')
    check(all(native.sha(p) == h for p, h in before_artifacts.items()), 'activation copied/changed kernel artifacts')
    check(native.output(['pacman', '--root', '/mnt/fdn-root', '--config', '/etc/enzimos/pacman-query.conf', '-Q']) == source['inventory'], 'activation changed main package inventory')
    check(native.authority_identity() == source['authority'], 'activation changed current authority')
    return {'intent_sha256': digest, 'initial_phase': initial, 'flavor': flavor, 'selected': value['selection'],
            'root': value['intent']['job']['root'], 'compatibility_drift_refused': True,
            'metadata_drift_refused': True, 'stale_digest_refused': True, 'artifacts_packages_authority_preserved': True,
            'selection': 'packaged-disk-defaults', 'retirement_enabled': False}


def boot(check, module_trial):
    source = json.loads((CONTROL/'activation-source.json').read_text())
    result = activation.confirm_current();value = activation.records()[ID];job = value['intent']['job']
    check(native.output(['findmnt', '-n', '-o', 'FSROOT', '--mountpoint', '/']) == '/'+job['root']['path'], 'wrong staged root booted')
    check(native.output(['pacman', '-Q']) == source['inventory'], 'restored inventory differs')
    check(native.authority_identity() == source['authority'], 'restored authority differs')
    check(Path('/home/enzimos-admin/foundation-home-marker').read_text() == 'ACTIVATION-NEWER-HOME-PRESERVED\n', 'newer home lost')
    before = native.sha(CONTROL/'recovery-activations'/f'{ID}.json')
    for action in (lambda:native.select_generation(GENERATION, 'linux'),
                   lambda:native.run_update('/etc/pacman-foundation.conf', 'blocked-staged', {}, Path('/proc/cmdline').read_text().strip())):
        try:action()
        except native.Failure as exc:check('activated restored-root update/ordinary selection not yet qualified' in str(exc), 'wrong activated-root refusal')
        else:raise AssertionError('unqualified transition ran on restored root')
    check(native.sha(CONTROL/'recovery-activations'/f'{ID}.json') == before, 'blocked operations changed activation')
    module_trial()
    return {'confirmation': result, 'root': job['root'], 'kernel': os.uname().release,
            'policy_version': native.output(['pacman', '-Q', 'enzimos-native-policy']), 'uefi': Path('/sys/firmware/efi').is_dir(),
            'packages_home_authority_preserved': True, 'unqualified_update_selection_blocked': True, 'normal_module_load': True,
            'retirement_enabled': False}
