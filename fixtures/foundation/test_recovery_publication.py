#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Disposable-guest interruption controls, not production auto-replay policy."""
import json
import os
from pathlib import Path
import re
import shutil
import time

import native
import recovery_image as image
import recovery_publication as publication
import generation_registry as registry

CONTROL = Path('/var/lib/enzimos-control')


def cut(payload, checkpoint, check):
    payload = Path(payload)
    check(native.output(['pacman', '-Q', 'enzimos-native-policy']) == 'enzimos-native-policy 0.1.0-28', 'wrong publication replay candidate')
    supplied = json.loads((payload/'recovery-image-manifest.json').read_text());identifier = image.image_id(supplied['identity'])
    image.INPUT.mkdir(mode=0o700, parents=True)
    shutil.copyfile(payload/'recovery-image-manifest.json', image.INPUT/'manifest.json')
    shutil.copyfile('/boot/enzimos-recovery/kernel', image.INPUT/'kernel')
    shutil.copyfile('/boot/enzimos-recovery/initrd.img', image.INPUT/'initrd.img')
    line = native.entry_fields(Path('/boot/loader/entries/recovery.conf').read_text(), None)['options']
    Path('/home/enzimos-admin/foundation-home-marker').write_text('NEWER-HOME-PUBLICATION-INTERRUPTION\n')
    old_boot = {str(path): native.sha(path) for path in Path('/boot').rglob('*') if path.is_file()}
    native.atomic_json(CONTROL/'publication-cut.json', {'id': identifier, 'checkpoint': checkpoint, 'options': line,
        'inventory': native.output(['pacman', '-Q']), 'authority': native.authority_identity(), 'boot_before': old_boot})
    def interrupt(name, record):
        if name != checkpoint:return
        check(record['phase'] == ('intent' if name == 'artifact:kernel' else 'artifacts'), 'wrong publication cut phase')
        os.sync();print('ENZIMOS_PUBLICATION_CUT_READY '+checkpoint, flush=True)
        while True:time.sleep(1)
    image.publish(line, interrupt)
    raise AssertionError('publication cut not reached')


def recover(check):
    source = json.loads((CONTROL/'publication-cut.json').read_text());identifier = source['id']
    path = image.directory()/(identifier+'.json');before_record = native.sha(path)
    journal_path = publication.directory()/(identifier+'.json');before_journal = native.sha(journal_path)
    journal = publication.journals()[identifier]
    check(not image.INPUT.exists(), 'replay must not depend on previous RAM inputs')
    original_record = image.records()[identifier]
    check(not original_record['observations'], 'unfinished publication confirmed')
    for action in (lambda:image.publish(source['options']), registry.confirm_current,
                   lambda:native.select_generation('unavailable', 'linux'),
                   lambda:native.run_update('/etc/pacman-foundation.conf', 'blocked-publication', {}, Path('/proc/cmdline').read_text())):
        try:action()
        except native.Failure as exc:check('recovery image publication incomplete' in str(exc), 'pending publication not blocked before mutation')
        else:raise AssertionError('unfinished publication allowed transition')
    check(native.sha(path) == before_record and native.sha(journal_path) == before_journal, 'pending refusal altered journal')
    # Prior boot metadata/resources stay byte-identical except the newly appended
    # BIOS entry at the BIOS-write boundary; its before/after bytes are journal-bound.
    for name, digest in source['boot_before'].items():
        # systemd-boot refreshes this entropy seed on ordinary boot. It is not a
        # recovery artifact or selection/configuration authority to roll back.
        if name == '/boot/loader/random-seed':continue
        if name == '/boot/limine/limine.conf' and source['checkpoint'] == 'bios':continue
        check(native.sha(name) == digest, 'interruption damaged existing boot resources')
    resumed = False;boundaries = []
    if original_record['phase'] == 'intent':
        try:publication.resume(identifier, journal['journal_sha256'])
        except native.Failure as exc:check('artifact creation incomplete' in str(exc), 'partial artifacts were replayed or adopted')
        else:raise AssertionError('partial artifact replay accepted')
        check(native.sha(path) == before_record and native.sha(journal_path) == before_journal, 'artifact refusal changed records')
    else:
        reviewed = publication.review(identifier);check(reviewed['resume_available'], 'verified artifact resume unavailable')
        try:publication.resume(identifier, 'f'*64)
        except native.Failure as exc:check('stale' in str(exc), 'wrong stale review refusal')
        else:raise AssertionError('stale publication review accepted')
        bios = Path('/boot/limine/limine.conf');text = bios.read_text()
        native.atomic_text(bios, text+'# LAB metadata drift\n')
        try:
            try:publication.resume(identifier, reviewed['journal_sha256'])
            except native.Failure as exc:check('metadata drift' in str(exc), 'wrong drift refusal')
            else:raise AssertionError('changed BIOS metadata overwritten')
            check(bios.read_text() == text+'# LAB metadata drift\n', 'drift refusal overwrote user data')
            check(native.sha(path) == before_record and native.sha(journal_path) == before_journal, 'drift refusal changed journal')
        finally:native.atomic_text(bios, text)
        # Inject exceptions after each completed metadata step; replay must accept
        # exactly before/after bytes, then preserve a completed record on retry.
        for phase in ('uefi', 'bios', 'ready'):
            def stop(name, _):
                if name == phase:boundaries.append(name);raise OSError('LAB replay boundary')
            try:publication.resume(identifier, reviewed['journal_sha256'], stop)
            except OSError as exc:check('LAB replay boundary' in str(exc), 'wrong replay failure')
            else:raise AssertionError('replay boundary did not interrupt')
        completed_hash = native.sha(path)
        check(publication.resume(identifier, reviewed['journal_sha256'])['status'] == 'already-ready', 'completed replay not idempotent')
        check(native.sha(path) == completed_hash and native.sha(journal_path) == before_journal, 'idempotent replay rewrote records')
        image.verify_published(image.records()[identifier]);resumed = True
    check(native.output(['pacman', '-Q']) == source['inventory'] and native.authority_identity() == source['authority'], 'replay changed packages/current authority')
    check(Path('/home/enzimos-admin/foundation-home-marker').read_text() == 'NEWER-HOME-PUBLICATION-INTERRUPTION\n', 'newer home changed')
    check(native.sha('/boot/loader/loader.conf') == source['boot_before']['/boot/loader/loader.conf'], 'replay changed UEFI default')
    check(native.limine_menu(Path('/boot/limine/limine.conf').read_text())[2] == native.limine_menu(journal['bios_before'])[2], 'replay changed BIOS default')
    if resumed:
        native.atomic_json(CONTROL/'image-test.json', {'id': identifier, 'record_sha256': native.sha(path), 'inventory': source['inventory'],
            'authority': source['authority'], 'old_recovery_sha256': native.sha('/boot/enzimos-recovery/initrd.img')})
        # Test-only selection happens after preservation assertions, not in resume.
        native.atomic_text('/boot/loader/loader.conf', f'default {identifier}.conf\ntimeout 0\neditor no\n')
        bios = Path('/boot/limine/limine.conf');text = bios.read_text()
        number = native.limine_number(text, 'enzimOS recovery '+identifier)
        native.atomic_text(bios, re.sub(r'^default_entry: .*$', f'default_entry: {number}', text, flags=re.M))
    return {'checkpoint': source['checkpoint'], 'phase_before': original_record['phase'], 'resumed': resumed,
            'artifact_replay_refused': not resumed, 'pending_transitions_blocked': True, 'journal_preserved': True,
            'interrupted_replay_boundaries': boundaries, 'packages_home_authority_preserved': True,
            'defaults_preserved_by_replay': True, 'artifact_inputs_absent': True,
            'boot_managed_mutable_exclusion': '/boot/loader/random-seed', 'selection': 'lab-only-after-replay' if resumed else 'unchanged',
            'retirement_enabled': False}
