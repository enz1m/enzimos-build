#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only completed staging review. Never publish or select the staged root."""
import copy
import json
import os
from pathlib import Path

import native
import recovery_stage as stage
import recovery_image
import recovery_publication
import generation_registry as registry

CONTROL = Path('/var/lib/enzimos-control')


def qualify(check):
    source = json.loads((CONTROL/'packaged-recovery-source.json').read_text());identifier = source['id']
    stage.TOP.mkdir(mode=0o700, parents=True, exist_ok=True)
    native.run(['mount', '--bind', '/mnt', stage.TOP])
    path = CONTROL/'recovery-jobs'/(identifier+'.json');plan = json.loads(path.read_text())['plan']
    before_boot = {str(p): native.sha(p) for p in Path('/boot').rglob('*') if p.is_file()}
    journal_before = path.read_bytes()
    def refuse(action, text):
        before = path.read_bytes()
        try:action()
        except native.Failure as exc:check(text in str(exc), 'wrong review refusal: '+str(exc))
        else:raise AssertionError('unsafe staging/review accepted')
        check(path.read_bytes() == before, 'refusal rewrote staging job')
    refuse(lambda:stage.review(identifier, source['plan_sha256']), 'incomplete staging')
    refuse(lambda:stage.stage(identifier, 'f'*64), 'stale recovery preview')
    # An orphan publication must block a second writer, even from independent recovery.
    descriptor = json.loads(recovery_image.EMBEDDED.read_text());image_id = recovery_image.image_id(descriptor)
    files = {name: {'bytes': (Path('/boot/enzimos-recovery')/filename).stat().st_size,
                    'sha256': native.sha(Path('/boot/enzimos-recovery')/filename)}
             for name, filename in (('kernel', 'kernel'), ('initrd.img', 'initrd.img'))}
    record = {'schema': 1, 'id': image_id, 'phase': 'intent', 'created_boot': native.boot_id(),
              'filesystem_uuid': plan['filesystem_uuid'], 'boot_uuid': plan['boot_uuid'],
              'control': plan['protected']['control'], 'inputs': {'schema': 1, 'identity': descriptor, 'files': files},
              'options': 'console=ttyS0 enzimos.recovery='+image_id, 'observations': {}}
    recovery_image.validate(record, image_id)
    publication = recovery_publication.create(record, Path('/boot/limine/limine.conf').read_text(), Path('/boot/loader/loader.conf').read_text())
    orphan = recovery_publication.directory()/(image_id+'.json')
    try:
        refuse(lambda:stage.stage(identifier, source['plan_sha256']), 'orphan publication')
        check(path.read_bytes() == journal_before and not (stage.TOP/plan['target_name']).exists(), 'orphan guard created root')
    finally:orphan.unlink()  # Only this explicitly synthetic guest test journal.
    result = stage.stage(identifier, source['plan_sha256'])
    completed = path.read_bytes();job = json.loads(completed);target = stage.TOP/plan['target_name']
    review = stage.review(identifier, source['plan_sha256'])
    check(review['material']['root'] == job['root'] and not review['boot_activation_available'], 'staged review binding changed')
    for relative, replacement, message in (('etc/fstab', b'# altered\n', 'fstab'),
                                           ('etc/enzimos/storage.json', b'{}\n', 'storage configuration'),
                                           ('etc/fstab.partial', b'stale\n', 'temporary')):
        probe = target/relative;original = probe.read_bytes() if probe.exists() else None;probe.write_bytes(replacement)
        try:refuse(lambda:stage.review(identifier, source['plan_sha256']), message)
        finally:
            if original is None:probe.unlink()
            else:probe.write_bytes(original)
    wrong = copy.deepcopy(job);wrong['root']['id'] += 100000
    registry.save_document(path, wrong)
    try:refuse(lambda:stage.review(identifier, source['plan_sha256']), 'identity changed')
    finally:path.write_bytes(completed)
    mount = Path('/run/staged-review-bind');mount.mkdir()
    native.run(['mount', '--bind', target, mount])
    try:refuse(lambda:stage.review(identifier, source['plan_sha256']), 'mounted in a namespace')
    finally:native.run(['umount', mount])
    check(stage.review(identifier, source['plan_sha256']) == review, 'read-only repeated review differs')
    check(path.read_bytes() == completed, 'review changed completed job')
    check({str(p): native.sha(p) for p in Path('/boot').rglob('*') if p.is_file()} == before_boot, 'staging/review changed boot selection/artifacts')
    check(native.output(['pacman', '--root', '/mnt/fdn-root', '--config', '/etc/enzimos/pacman-query.conf', '-Q']) == source['current_inventory'], 'review changed original packages')
    check(native.authority_identity() == source['authority'], 'review changed current authority')
    # Test fixture selects the ORIGINAL live root only after preservation checks.
    native.atomic_text('/boot/loader/loader.conf', 'default enzimos-fdn-success-linux.conf\ntimeout 0\neditor no\n')
    limine = Path('/boot/limine/limine.conf');text = limine.read_text()
    import re
    number = native.limine_number(text, 'enzimOS fdn-success linux')
    native.atomic_text(limine, re.sub(r'^default_entry: .*$', 'default_entry: '+str(number), text, flags=re.M))
    return {'stage': result, 'review': review, 'orphan_publication_blocked_before_creation': True,
            'partial_review_refused': True, 'stale_preview_refused': True, 'configuration_drift_refused': True,
            'identity_drift_refused': True, 'mounted_target_refused': True, 'repeat_review_readonly': True,
            'packages_authority_boot_preserved_before_fixture_selection': True,
            'fixture_selection': 'original-live-root-only-after-checks', 'staged_root_selected': False,
            'kernel': os.uname().release, 'uefi': Path('/sys/firmware/efi').is_dir(), 'retirement_enabled': False}


def graph(check):
    import boot_inventory
    path = CONTROL/'recovery-jobs/fdn-stage.json';before = path.read_bytes();job = json.loads(before)
    check(job['phase'] == 'staged', 'completed staging missing')
    check(native.output(['findmnt', '-n', '-o', 'FSROOT', '--mountpoint', '/']) == '/fdn-root', 'staged graph must observe from original root')
    observation = boot_inventory.collect();result = observation['recovery_references']
    check(result is not None and not result['complete'], 'staged graph unavailable or falsely complete')
    edges = {(row['source'], row['target'], row['reason']) for row in result['edges']}
    for role in ('root', 'history'):
        key = 'root:'+job[role]['uuid']
        check(result['nodes'][key]['identity_matches'], 'staged graph identity mismatch')
        check(('stage:fdn-stage', key, 'staging-root-dependency') in edges, 'staged dependency missing')
        check(not result['nodes'][key]['deletion_authorized'], 'staged graph authorized deletion')
    check(path.read_bytes() == before, 'collector changed staged job')
    return {'root': job['root'], 'history': job['history'], 'completed_staged_resources_linked': True,
            'journal_unchanged': True, 'complete': False, 'retirement_enabled': False,
            'kernel': os.uname().release, 'uefi': Path('/sys/firmware/efi').is_dir()}
