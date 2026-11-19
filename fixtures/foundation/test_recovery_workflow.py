#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Independent guest recovery workflow cuts; no production fault hooks."""
import json
import os
from pathlib import Path
import time

import native
import generation_registry as registry
import recovery_activation as activation
import recovery_stage as stage
import recovery_workflow as workflow

CONTROL = Path('/var/lib/enzimos-control')
ID = 'fdn-activation'


def material():
    folders = ('recovery-workflows', 'recovery-jobs', 'recovery-activations')
    journals = {str(p):native.sha(p) for name in folders for p in (CONTROL/name).glob('*.json')}
    boots = {str(p):native.sha(p) for name in ('loader/entries', 'limine', 'enzimos/generations', 'enzimos-recovery')
             for p in (Path('/boot')/name).rglob('*') if p.is_file()}
    boots['/boot/loader/loader.conf'] = native.sha('/boot/loader/loader.conf')
    return {'journals':journals, 'boots':boots, 'roots':stage.subvolumes('/mnt'),
            'authority':native.authority_identity(),
            'home':native.sha('/mnt/lab-home/enzimos-admin/foundation-home-marker')}


def qualify(check, selection):
    stage.TOP.mkdir(mode=0o700, parents=True, exist_ok=True)
    native.run(['mount', '--bind', '/mnt', stage.TOP])
    source = json.loads((CONTROL/'activation-source.json').read_text()); plan = source['plan']
    if selection == 'recovery-workflow-review':
        saved = json.loads((CONTROL/'workflow-cut.json').read_text())
        check(native.boot_id() != saved['boot_id'], 'review reused cut boot')
        check(material() == saved['material'], 'workflow cut material drift')
        value = workflow.status(ID)
        check(value['state'] == 'uncertain' and not value['automatic_replay'], 'workflow cut replayed or completed')
        check(value['last_action'] == saved['boundary'], 'wrong interrupted action')
        for action, fragment in (
            (lambda:workflow.execute(ID, plan['plan_sha256'], 'linux'), 'no replay'),
            (lambda:workflow.execute('other-workflow', plan['plan_sha256'], 'linux'), 'uncertain recovery workflow'),
        ):
            try:action()
            except native.Failure as exc:check(fragment in str(exc), 'wrong workflow refusal: '+str(exc))
            else:raise AssertionError('uncertain workflow operation succeeded')
        check(material() == saved['material'], 'workflow review/refusal changed material')
        check(native.output(['pacman', '--root', '/mnt/fdn-root', '--config', '/etc/enzimos/pacman-query.conf', '-Q']) == source['inventory'], 'workflow cut changed original packages')
        return {'boundary':saved['boundary'], 'later_boot':True, 'uncertain_never_replayed':True,
                'new_workflow_blocked':True, 'journals_roots_boot_home_authority_preserved':True,
                'original_packages_preserved':True, 'physical_power_loss':False, 'retirement_enabled':False}
    if selection in ('recovery-workflow-cut-stage', 'recovery-workflow-cut-publish'):
        boundary = selection.rsplit('-', 1)[-1]
        owner = stage if boundary == 'stage' else activation
        original = getattr(owner, boundary)
        def cut(*args, **kwargs):
            result = original(*args, **kwargs)
            check(workflow.records()[ID]['state'] == 'running' and workflow.records()[ID]['action'] == boundary, 'cut missed durable running intent')
            registry.save_document(CONTROL/'workflow-cut.json', {'boundary':boundary, 'boot_id':native.boot_id(), 'material':material()})
            os.sync()
            print('ENZIMOS_WORKFLOW_CUT_READY '+boundary, flush=True)
            while True:time.sleep(1)
            return result
        setattr(owner, boundary, cut)
    flavor = 'linux-lts' if selection == 'recovery-workflow-lts' else 'linux'
    result = workflow.execute(ID, plan['plan_sha256'], flavor)
    check(workflow.status(ID)['state'] == 'complete', 'workflow did not complete')
    check(activation.records()[ID]['selection']['flavor'] == flavor, 'workflow selected wrong kernel')
    try:workflow.execute(ID, plan['plan_sha256'], flavor)
    except native.Failure as exc:check('no replay' in str(exc), 'wrong completed retry refusal')
    else:raise AssertionError('completed workflow replayed')
    return dict(result, completed_retry_refused=True)
