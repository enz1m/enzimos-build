#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only graph observation on real publication or prepared staging records."""
import json
import os
from pathlib import Path
import subprocess

import boot_inventory
import native
import generation_registry as registry
import recovery_stage
import recovery_image
import recovery_publication

CONTROL = Path('/var/lib/enzimos-control')


def qualify(check):
    check(native.output(['pacman', '-Q', 'enzimos-native-policy']) == 'enzimos-native-policy 0.1.0-28', 'wrong reference candidate')
    catalog = registry.status()['catalog'];mode = 'publication' if recovery_image.records() else 'stage-plan'
    if mode == 'stage-plan':
        recovery_stage.prepare('fdn-reference-plan', 'fdn-success', 'old-fdn-success')
    protected = []
    for folder in ('generation-registry', 'recovery-jobs', 'recovery-publications', 'recovery-images', 'root-births'):
        path = CONTROL/folder
        if path.exists():protected.extend(p for p in path.iterdir() if p.suffix == '.json')
    before = {str(path): native.sha(path) for path in protected};inventory = native.output(['pacman', '-Q']);authority = native.authority_identity()
    home = Path('/home/enzimos-admin/recovery-reference-marker');home.write_text('PRESERVE-REFERENCE-OBSERVATION\n')
    boot_before = {str(path): native.sha(path) for path in Path('/boot').rglob('*') if path.is_file()}
    observation = boot_inventory.collect();graph = observation['recovery_references']
    check(graph is not None and not graph['complete'] and not graph['execution_available'], 'graph missing or falsely complete')
    check(all(not row['deletion_authorized'] for row in graph['nodes'].values()), 'graph granted deletion')
    if mode == 'stage-plan':
        stage = graph['nodes']['stage:fdn-reference-plan']
        check(stage['phase'] == 'planned' and 'pending-recovery-stage:fdn-reference-plan' in graph['blockers'], 'pending real recovery plan missing')
        check(any(row['source'] == 'stage:fdn-reference-plan' and row['target'] == 'system:old-fdn-success' for row in graph['edges']), 'staging generation reference lost')
        artifact = '/enzimos/generations/old-fdn-success/vmlinuz-linux'
        source_entry = Path('/boot/loader/entries/enzimos-old-fdn-success-linux.conf')
    else:
        records = recovery_image.records();check(len(records) == 1, 'one real pending image fixture required')
        identifier = next(iter(records));check(records[identifier]['phase'] == 'artifacts', 'expected interrupted complete-artifact publication')
        check('publication:'+identifier in graph['nodes'] and 'pending-publication-journal:'+identifier in graph['blockers'], 'orphan/pending publication graph lost')
        artifact = '/enzimos/recovery-images/'+identifier+'/kernel'
        source_entry = None
    check(graph['nodes']['boot:'+artifact]['bytes_match'], 'recorded artifact bytes not observed')
    alias = Path('/boot/loader/entries/reference-alias.conf')
    if source_entry:alias.write_text(source_entry.read_text())
    else:
        identifier = next(iter(recovery_image.records()))
        record = recovery_image.records()[identifier]
        alias.write_text(recovery_image.entry_texts(identifier, record['options'])[0])
    try:
        observed = boot_inventory.collect()['recovery_references']
        check(any(row['source'] == 'entry:uefi:reference-alias.conf' and row['target'] == 'boot:'+artifact for row in observed['edges']), 'unregistered shared alias ignored')
        # Same-node aliases protect resources but do not adopt the alias as owned.
        check(not observed['nodes']['entry:uefi:reference-alias.conf']['deletion_authorized'], 'alias claimed ownership')
        alias.write_text(alias.read_text()+'unknown-key /unrecognized\n')
        unknown = boot_inventory.collect()['recovery_references']
        check('unparsed-loader-fields:uefi:reference-alias.conf' in unknown['blockers'], 'unknown alias field silently accepted')
    finally:alias.unlink()
    check({str(path): native.sha(path) for path in protected} == before, 'collector rewrote private records')
    check({str(path): native.sha(path) for path in Path('/boot').rglob('*') if path.is_file()} == boot_before, 'collector changed boot resources')
    check(native.output(['pacman', '-Q']) == inventory and native.authority_identity() == authority and home.read_text() == 'PRESERVE-REFERENCE-OBSERVATION\n', 'collector changed packages/home/authority')
    if not Path('/sys/firmware/efi').is_dir():
        check('EFI-loader-state-not-observable-on-this-boot' in graph['blockers'], 'BIOS EFI uncertainty lost')
    ordinary = subprocess.run(['runuser', '-u', 'enzimos-user', '--', 'python', '/usr/lib/enzimos/boot_inventory.py', 'collect'], capture_output=True, text=True)
    check(ordinary.returncode != 0 and 'root authorization required' in ordinary.stderr, 'ordinary user accessed privileged graph')
    native.atomic_json(CONTROL/'recovery-reference-observation.json', observation)
    return {'mode': mode, 'uefi': Path('/sys/firmware/efi').is_dir(), 'kernel': os.uname().release,
            'nodes': len(graph['nodes']), 'edges': len(graph['edges']), 'real_pending_records_linked': True,
            'artifact_bytes_verified': True, 'shared_alias_linked': True, 'unknown_fields_blocked': True,
            'private_records_boot_packages_home_authority_preserved': True, 'unprivileged_refused': True,
            'observation_sha256': observation['observation_sha256'], 'complete': False, 'retirement_enabled': False}
