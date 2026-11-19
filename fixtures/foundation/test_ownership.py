#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only birth-record controls; deliberately no retirement executor."""
import json
import os
from pathlib import Path
import subprocess
import time

import native
import generation_registry as registry
import root_ownership as birth
from native import Failure, output, sha

CONTROL = Path('/var/lib/enzimos-control')
CUT_ID = 'fdn-birth-cut'
CUT = 'ENZIMOS_BIRTH_CUT_READY root-recorded-before-publication'
HOME = Path('/home/enzimos-admin/birth-home-marker')


def normalization_controls(check):
    c = native.config();base = native.RUN/'birth-normalization-probes';base.mkdir(mode=0o700)
    for kind in ('parent-link', 'temporary-link', 'history-mount'):
        case = base/kind;target = case/'target';outside = case/'outside'
        (target/'etc/enzimos').mkdir(parents=True);(target/'.snapshots').mkdir();outside.mkdir()
        storage = target/'etc/enzimos/storage.json';storage.write_text(json.dumps(c))
        fstab = target/'etc/fstab';fstab.write_text(f'UUID={c["filesystem_uuid"]} / btrfs subvol={c["root_subvol"]} 0 0\n')
        marker = outside/'storage.json';marker.write_text(json.dumps(c))
        before = (sha(marker), sha(fstab), sha(storage));mounted = None
        if kind == 'parent-link':
            storage.unlink();storage.parent.rmdir();storage.parent.symlink_to(outside, target_is_directory=True)
            expected = 'unsafe fallback configuration directory'
        elif kind == 'temporary-link':
            storage.with_name(storage.name+'.new').symlink_to(marker)
            expected = 'stale fallback write destination'
        else:
            empty = case/'empty-mount';empty.mkdir();mounted = target/'.snapshots'
            native.run(['mount', '--bind', empty, mounted]);expected = 'snapshot placeholder is mounted'
        try:
            try:birth.normalize_root(target, 'must-not-be-written', c)
            except Failure as exc:check(expected in str(exc), 'normalization did not refuse at its preflight boundary')
            else:raise AssertionError('unsafe fallback normalization was accepted')
            check((sha(marker), sha(fstab), sha(storage)) == before, 'normalization preflight changed either destination')
        finally:
            if mounted is not None:native.run(['umount', mounted])
    return 3


def prepare(check):
    import test_registry
    check(birth.status()['resources'] == {}, 'fresh birth registry required')
    normalization = normalization_controls(check)
    unprivileged = subprocess.run(['runuser', '-u', 'enzimos-user', '--', 'python', '/usr/lib/enzimos/root_ownership.py', 'status'], capture_output=True, text=True)
    check(unprivileged.returncode != 0 and 'root authorization required' in unprivileged.stderr, 'unprivileged birth registry access')
    supplied = subprocess.run(['python', '/usr/lib/enzimos/root_ownership.py', 'adopt', '--owned'], capture_output=True, text=True)
    check(supplied.returncode == 2, 'caller adoption interface unexpectedly exists')
    c = native.config();boundaries = []
    with native.operation_lock():
        birth.create_fallback('fdn-owned-probe', lambda phase, _: boundaries.append(phase))
        with birth.top_mount(c) as top:
            collision = top/'enzimos-old-fdn-collision'
            registry.bounded_query(['/usr/bin/btrfs', 'subvolume', 'create', str(collision)])
    before = {p.name: sha(p) for p in (CONTROL/'root-births').iterdir()}
    try:
        with native.operation_lock():birth.create_fallback('fdn-collision')
    except Failure as exc:check('cannot be adopted' in str(exc), 'wrong existing-root refusal')
    else:raise AssertionError('existing root was adopted')
    check({p.name: sha(p) for p in (CONTROL/'root-births').iterdir()} == before, 'existing-root refusal changed birth records')
    value = birth.status()
    check(len(value['resources']) == 3 and not value['pending'] and not value['drift'], 'new-resource birth identity verification failed')
    check(all(item['publisher_origin_observed'] and not item['deletion_authorized'] for item in value['resources'].values()), 'birth evidence missing or promoted to deletion')
    record = json.loads((CONTROL/'root-births/fdn-owned-probe.json').read_text())
    check((CONTROL/'root-births/fdn-owned-probe.json').stat().st_mode & 0o777 == 0o600, 'birth record is not private')
    # Move only this unpublished probe; a replacement with the same name is not it.
    with native.operation_lock(), birth.top_mount(c) as top:
        original = top/record['target_name'];moved = top/(record['target_name']+'-moved')
        original.rename(moved)
        try:
            registry.bounded_query(['/usr/bin/btrfs', 'subvolume', 'create', str(original)])
            observed = birth.status_locked()
            check('fdn-owned-probe:root-subvolume' in observed['drift'], 'same-name different root UUID was accepted')
            original.rename(top/(record['target_name']+'-unowned-replacement'))
        finally:moved.rename(original)
        snapshot = top/record['snapshot']['object']['path']
        registry.bounded_query(['/usr/bin/btrfs', 'property', 'set', '-ts', str(snapshot), 'ro', 'false'])
        try:
            check('fdn-owned-probe:source-snapshot' in birth.status_locked()['drift'], 'writable source snapshot was accepted')
        finally:registry.bounded_query(['/usr/bin/btrfs', 'property', 'set', '-ts', str(snapshot), 'ro', 'true'])
    check(not birth.status()['drift'], 'probe identity was not restored')
    prepared = test_registry.prepare(check)
    return {'registry': prepared, 'birth_boundaries': boundaries, 'new_resources': 3,
            'normalization_preflight_controls': normalization, 'normalization_destinations_unchanged': True,
            'unprivileged_refused': True, 'adoption_api_absent': True, 'existing_root_refused_without_record_changes': True,
            'same_name_replacement_detected': True, 'writable_snapshot_detected': True, 'retirement_enabled': False}


def updated(update, check, kernels):
    import test_rebind
    result = test_rebind.finished_update(update, check, kernels)
    value = birth.status();record = json.loads((CONTROL/'root-births/fdn-success.json').read_text())
    check(record['phase'] == 'ready' and record['root']['uuid'] == result['retained_uuid'], 'update fallback not birth-registered')
    check(len(value['resources']) == 6 and not value['pending'] and not value['drift'], 'update birth resources incomplete or changed')
    check(all(item['publisher_origin_observed'] and not item['deletion_authorized'] for item in value['resources'].values()), 'update ownership scope invalid')
    return {'rebind': result, 'birth_resources': len(value['resources']), 'fallback_birth_uuid': record['root']['uuid'], 'retirement_enabled': False}


def boot(check, module_trial):
    import test_rebind
    result = test_rebind.boot(check, module_trial)
    value = birth.status()
    check(len(value['resources']) == 6 and not value['pending'] and not value['drift'], 'birth registry did not survive root/boot transition')
    return {'boot': result, 'birth_resources': len(value['resources']), 'retirement_enabled': False}


def interrupted(check):
    before = output(['pacman', '-Q']);HOME.write_text('NEWER-HOME-SURVIVES-BIRTH-CUT\n')
    def checkpoint(phase, record):
        if phase != 'root-recorded':return
        check(record['history'] is None and not Path('/var/lib/pacman/db.lck').exists(), 'birth cut crossed package/history boundary')
        native.atomic_json(CONTROL/'birth-cut.json', {'id': CUT_ID, 'inventory': before, 'authority': native.authority_identity(),
                                                   'root_uuid': record['root']['uuid'], 'source': record['source']})
        os.sync();print(CUT, flush=True)
        while True:time.sleep(1)
    with native.operation_lock():birth.create_fallback(CUT_ID, checkpoint)
    raise AssertionError('birth cut boundary was not reached')


def pending(check, module_trial):
    info = json.loads((CONTROL/'birth-cut.json').read_text());value = birth.status()
    check(value['pending'] == [CUT_ID] and not value['drift'], 'incomplete birth was adopted or lost')
    check(all(item['transaction'] != CUT_ID for item in value['resources'].values()), 'pending birth acquired ownership')
    records = CONTROL/'root-births';before = {p.name: sha(p) for p in records.iterdir()}
    def retry():
        with native.operation_lock():birth.create_fallback(CUT_ID)
    for action in (retry, registry.confirm_current,
                   lambda: native.select_generation('fdn-reg-b', 'linux'),
                   lambda: native.run_update('/etc/pacman-foundation.conf', 'blocked-birth', {}, Path('/proc/cmdline').read_text().strip())):
        try:action()
        except Failure as exc:check('fallback creation is incomplete' in str(exc), 'wrong pending-birth refusal')
        else:raise AssertionError('pending birth permitted adoption or mutation')
    check({p.name: sha(p) for p in records.iterdir()} == before, 'pending birth refusal altered journal')
    check(output(['pacman', '-Q']) == info['inventory'] and native.authority_identity() == info['authority'], 'pending birth changed packages/current authority')
    check(HOME.read_text() == 'NEWER-HOME-SURVIVES-BIRTH-CUT\n', 'pending birth lost newer home')
    check(registry.root_identity(native.config()['root_subvol']) == info['source'], 'pending birth changed live root')
    check(registry.status()['pending_births'] == [CUT_ID], 'publisher registry ignored pending birth')
    module_trial()
    return {'pending_birth': CUT_ID, 'automatic_adoption_refused': True, 'mutations_blocked': True,
            'journal_unchanged': True, 'packages_home_authority_preserved': True, 'retirement_enabled': False}
