#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only reference observation; no adoption, retirement or package replay."""
import json
import os
from pathlib import Path
import subprocess

import boot_inventory
import generation_registry as registry
import native
import root_ownership as birth
import root_references as refs

CONTROL = Path('/var/lib/enzimos-control')


def qualify(check):
    catalog = registry.status()['catalog']
    c, directory = birth.private_directory();records = birth.read_records(c, directory)
    check('fdn-success' in records, 'changing-update birth fixture required')
    record = records['fdn-success'];key = record['root']['uuid']
    names = sorted(name for name, value in catalog['generations'].items() if value['material']['root_identity']['uuid'] == key)
    check(len(names) >= 2, 'shared retained-root aliases required')
    protected = [CONTROL/'generation-registry/catalog.json', *(directory.iterdir())]
    before = {str(path): native.sha(path) for path in protected}
    inventory = native.output(['pacman', '-Q']);authority = native.authority_identity()
    home = Path('/home/enzimos-admin/reference-home-marker');home.write_text('NEWER-HOME-REFERENCE-OBSERVATION\n')
    with native.operation_lock():
        baseline = refs.observe_locked(catalog, boot_inventory.namespace_observation())
        check(baseline['resources'][key]['generation_roots'] == names, 'retained aliases not joined')
        check(baseline['resources'][key]['publisher_origin_observed'], 'retained root origin missing')
        for name in names:
            check({record['root']['uuid'], record['history']['uuid'], record['snapshot']['object']['uuid']} <=
                  set(baseline['generations'][name]['resources']), 'birth dependencies missing')
        with birth.top_mount(c) as top:
            path = top/record['history']['path']/'reference-unowned-child'
            native.run(['btrfs', 'subvolume', 'create', path])
            child = birth.observe(path, record['history']['path']+'/reference-unowned-child', c['filesystem_uuid'])
            target = native.RUN/'reference-bind';target.mkdir(mode=0o700)
            native.run(['mount', '--bind', top/record['root']['path']/'usr', target])
            try:
                observed = refs.observe_locked(catalog, boot_inventory.namespace_observation())
                check(not observed['resources'][child['uuid']]['publisher_origin_observed'], 'untracked child was adopted')
                check(observed['resources'][child['uuid']]['container'] == record['history']['uuid'], 'nested store reference missing')
                check(set(names) <= set(observed['resources'][child['uuid']]['required_by_generations']), 'shared roots lost nested child')
                check('unowned-nested-subvolume:'+child['path'] in observed['blockers'], 'nested ownership uncertainty was hidden')
                check(any(row['target'] == str(target) and row['root'].endswith('/usr') for row in observed['resources'][key]['mount_references']),
                      'subdirectory bind mount was not attached to its containing root')
            finally:native.run(['umount', target])
            original = top/record['root']['path'];moved = top/(record['root']['path']+'-reference-moved')
            original.rename(moved)
            try:
                native.run(['btrfs', 'subvolume', 'create', original])
                drift = refs.observe_locked(catalog, boot_inventory.namespace_observation())
                check(all(not drift['generations'][name]['identity_matches'] for name in names), 'same-name replacement resolved old aliases')
                check(all('generation-root-identity-drift:'+name in drift['blockers'] for name in names), 'generation drift blocker missing')
                original.rename(top/(record['root']['path']+'-reference-unowned-replacement'))
            finally:moved.rename(original)
    observation = boot_inventory.collect()
    check(observation['root_references'] is not None, 'packaged boot collector did not include root references')
    check(not observation['complete'] and not observation['execution_available'], 'collector claimed retirement readiness')
    if not Path('/sys/firmware/efi').is_dir():
        check('EFI-loader-state-not-observable-on-this-boot' in observation['blockers'], 'BIOS EFI uncertainty was hidden')
    check({str(path): native.sha(path) for path in protected} == before, 'observation rewrote private catalog/births')
    check(native.output(['pacman', '-Q']) == inventory and native.authority_identity() == authority, 'observation changed packages/authority')
    check(home.read_text() == 'NEWER-HOME-REFERENCE-OBSERVATION\n', 'observation changed newer home')
    unauthorized = subprocess.run(['runuser', '-u', 'enzimos-user', '--', 'python', '/usr/lib/enzimos/boot_inventory.py', 'collect'], capture_output=True, text=True)
    check(unauthorized.returncode != 0 and 'root authorization required' in unauthorized.stderr, 'unprivileged collection accepted')
    native.atomic_json(CONTROL/'root-reference-observation.json', observation)
    return {'uefi': Path('/sys/firmware/efi').is_dir(), 'kernel': os.uname().release,
            'shared_aliases': names, 'retained_root_uuid': key, 'unowned_child_uuid': child['uuid'],
            'nested_child_not_adopted': True, 'bind_subdirectory_observed': True, 'same_name_replacement_refused': True,
            'private_records_unchanged': True, 'packages_home_authority_preserved': True, 'unprivileged_refused': True,
            'observation_sha256': observation['observation_sha256'], 'blockers': observation['blockers'],
            'complete': False, 'retirement_enabled': False}
