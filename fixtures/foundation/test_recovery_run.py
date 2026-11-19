#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Loader-started packaged independent recovery: build the recovery image, plan a
snapshot recovery, stage a one-shot recovery run (recovery-run-stage); the firmware/
loader starts the image's packaged PID1 which unlocks and runs the packaged workflow
(recovery-run-boot, harness); the next normal boot lands on the restored root and
finishes the run (recovery-run-finish). No lab recovery script runs in the image."""
import json
import os
from pathlib import Path
import native
import generation_registry as registry
import root_ownership as birth
import recovery_stage as staging
import recovery_activation as activation
import recovery_run
from test_credential_review import pause_history,restore_history
from test_root_retirement import quiet_maintenance,refused
import test_coordinator_boot as coordinator
import test_root_api69 as api
import lab_versions

VERSION=lab_versions.native()
ID='fdn-recovery-run'
GENERATION='old-'+ID
STATE=Path('/var/lib/enzimos-control/recovery-run-fixture.json')
HOME=Path('/home/enzimos-admin/recovery-run-home-marker')


def write_selections(image,identifier='x'):
    api.write_selections({'4':{'birth':ID,'generation':GENERATION},'17':{'id':identifier,'plan_sha256':'0'*64,'image':image,'flavor':'linux','exit':'poweroff'},
                          '18':{'id':identifier},'image':image})


def stage(check,payload):
    api.install(check,payload);history=pause_history(check);quiet_maintenance(check)
    try:
        image,extra=coordinator.build_image(check)
        with native.operation_lock():
            created=birth.create_fallback(ID)
            native.publish_boot('/boot',GENERATION,native.installed_kernels(),native.root_options(Path('/proc/cmdline').read_text().strip(),created['subvolume']))
        # Newer home data after the snapshot: the recovery must never overwrite it.
        HOME.write_text('RECOVERY-RUN-NEWER-HOME-PRESERVED\n')
        before=Path('/boot/loader/loader.conf').read_text()
        write_selections(image);api.denials(check);cancelled=api.authenticated(check,'auth-cancel')
        check(not recovery_run.records() and not staging.read_jobs(staging.jobs_directory()).get('api-'+'a'*32),'cancelled/denied requests changed state')
        staged=api.authenticated(check,'run-stage');identifier=staged['result']['prepare']['recovery_id']
        value=recovery_run.records()[identifier];check(value['phase']=='staged' and value['image']==image,'API did not stage the run over the built image')
        # A second staging refuses at the pending-run guard, before any record/entry work.
        refused(check,'unfinished recovery run',lambda:recovery_run.stage_run(identifier,value['plan_sha256'],'linux',image,'poweroff'))
        # Every online transition refuses; the planned staging job's guard runs before the run's own.
        try:native.assert_transition_idle()
        except native.Failure as exc:check(any(text in str(exc) for text in ('planned or incomplete recovery staging','unfinished recovery run')),'wrong refusal: '+str(exc))
        else:raise AssertionError('online transitions not blocked by the staged recovery run')
        uefi=coordinator.uefi_staged(check,value['entry'],before)
        _,entries,selected=native.limine_menu(Path('/boot/limine/limine.conf').read_text());check(entries[selected-1]['title']==value['entry']['bios_title'],'BIOS default not staged')
        native.atomic_json(STATE,{'boot_id':native.boot_id(),'id':identifier,'image':image,'inventory':native.output(['pacman','-Q']),
                                  'authority':native.authority_identity(),'history':history,'home':HOME.read_text()})
        os.sync()
        return {**extra,**uefi,'real_active_admin_authorization':True,'ordinary_inactive_denied':True,'auth_cancel_no_job':True,
                'recovery_plan_prepared_via_api':True,'stale_digest_refused':True,'run_staged_via_api':True,'duplicate_staging_refused':True,
                'online_transitions_blocked':True,'bios_default_staged':True,'password_prompts':cancelled['password_prompts']+staged['password_prompts'],
                'restored_online':False}
    finally:native.run(['systemctl','stop',api.UNIT])


def finish(check,payload):
    saved=json.loads(STATE.read_text());check(saved['boot_id']!=native.boot_id(),'later boot required');identifier=saved['id']
    value=activation.records()[identifier];check(value['phase']=='selected','recovery workflow did not select the restored root')
    root=value['intent']['job']['root']['path']
    check(registry.bounded_query(['findmnt','-n','-o','FSROOT','--mountpoint','/'])=='/'+root,'next boot is not the restored root')
    confirmed=activation.confirm_current();check(confirmed['id']==identifier,'restored root confirmation')
    check(recovery_run.records()[identifier]['phase']=='executed','offline run not recorded as executed')
    api.install(check,payload)
    try:
        write_selections(saved['image'],identifier);api.denials(check);finished=api.authenticated(check,'run-finish')
        check(recovery_run.records()[identifier]['phase']=='complete','API finish did not complete the run')
        refused(check,'executed recovery run required',lambda:recovery_run.finish(identifier))
        ledger={str(p):native.sha(p) for p in (registry.CONTROL/'backend-operations').glob('*.json')}
        native.run(['systemctl','restart',api.UNIT]);completed=api.authenticated(check,'run-completed')
        check(all(native.sha(Path(p))==v for p,v in ledger.items()),'restart changed ledger records')
    finally:native.run(['systemctl','stop',api.UNIT])
    # Adoption: before it, the restored root refuses its own updates/selection by design;
    # after an explicit digest-bound adoption of this confirmed boot the guards pass.
    refused(check,'activated restored-root update',native.assert_transition_idle)
    intent=activation.records()[identifier]['intent']['intent_sha256']
    refused(check,'exact intent required',lambda:activation.adopt(identifier,'0'*64))
    adopted=activation.adopt(identifier,intent);check(adopted['status']=='restored-root-adopted' and adopted['old_roots_retired'] is False,'restored root adoption')
    refused(check,'exact intent required',lambda:activation.adopt(identifier,intent))
    native.assert_transition_idle();registry.assert_update_safe()
    check(activation.confirm_current()['id']==identifier and activation.records()[identifier]['phase']=='adopted','adopted root confirmation')
    check(HOME.read_text()==saved['home'],'newer home overwritten by recovery')
    check(native.output(['pacman','-Q'])==saved['inventory'] and native.authority_identity()==saved['authority'],'recovery changed packages/authority')
    STATE.unlink();restore_history(check,saved['history'])
    return {'later_boot':True,'restored_root_booted':True,'restored_root_confirmed':True,'run_finished_via_api':True,'no_replay':True,
            'completed_restart_deduplicated':True,'newer_home_preserved':True,'packages_authority_preserved':True,
            'updates_refused_before_adoption':True,'restored_root_adopted':True,'update_guards_pass_after_adoption':True,'package_transaction_run':False,
            'password_prompts':finished['password_prompts']+completed['password_prompts'],'old_roots_retired':False}


def qualify(check,selection,payload):
    check(native.output(['pacman','-Q','enzimos-native-policy'])==VERSION,'wrong recovery run candidate')
    return stage(check,payload) if selection=='recovery-run-stage' else finish(check,payload)
