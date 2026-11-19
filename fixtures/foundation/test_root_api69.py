#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real polkit authorization for offline root retirement through the backend: prepare and
stage the coordinator (root-api-stage), the loader-started coordinator deletes offline
(coordinator-boot), then finish through the API (root-api-finish)."""
import json
import os
from pathlib import Path
import subprocess
import native
import generation_registry as registry
import recovery_image as image
import root_ownership as birth
import root_retirement as retirement
from test_credential_review import pause_history,restore_history
from test_root_retirement import quiet_maintenance,births,inventory
import test_lifecycle63_api as base
import test_coordinator_boot as coordinator

UNIT=base.UNIT;CONTROL=registry.CONTROL
PROBE='fdn-api-coordinator-probe'
STATE=Path('/var/lib/enzimos-control/root-api-fixture.json')
SELECTIONS=Path('/run/lifecycle69-selections.json')
CLIENT='/usr/lib/enzimos-lab/lifecycle69_api_client.py'


def install(check,payload):
    """Backend package once per lineage; later boots only start the service."""
    if subprocess.run(['pacman','-Q','enzimos-system-backend'],capture_output=True).returncode:base.install_backend(check,payload)
    else:
        check(native.output(['pacman','-Q','enzimos-system-backend'])==base.BACKEND,'wrong root API backend')
        native.run(['systemctl','start',UNIT])
    native.run(['install','-m','0644',Path(payload)/'lifecycle69_api_client.py',CLIENT])


def authenticated(check,mode):
    unit='enzimos-lifecycle69-api-'+mode;native.run(['systemctl','mask','--runtime','--now','getty@tty2.service','autovt@tty2.service']);native.run(['chvt','2'])
    log=Path('/run')/(unit+'.log')
    result=subprocess.run(['systemd-run','--quiet','--wait','--collect','--unit='+unit,'--uid=enzimos-admin','--property=PAMName=login','--property=TTYPath=/dev/tty2',
        '--property=StandardInput=tty-force','--property=StandardOutput=append:'+str(log),'--property=StandardError=append:'+str(log),'--setenv=XDG_SESSION_TYPE=tty','--setenv=XDG_SESSION_CLASS=user',
        '/usr/bin/python','-I','-B',CLIENT,mode],capture_output=True,text=True,timeout=1800)
    text=log.read_text();print('ENZIMOS_LIFECYCLE69_API_TRANSCRIPT\n'+text+result.stderr,flush=True)
    if result.returncode:print(native.output(['journalctl','-b','--no-pager','-n','80','-u',UNIT]),flush=True)
    check(result.returncode==0,'authenticated root API failed: '+mode)
    lines=[line for line in text.splitlines() if line.startswith('ENZIMOS_LIFECYCLE69_API_CLIENT=')]
    check(len(lines)==1,'root API client result missing');return json.loads(lines[0].split('=',1)[1])


def denials(check):
    for user,mode in (('enzimos-user','deny-user'),('enzimos-admin','deny-admin')):
        result=subprocess.run(['runuser','-u',user,'--','python','-I','-B',CLIENT,mode],capture_output=True,text=True,timeout=150)
        print(result.stdout+result.stderr,flush=True);check(result.returncode==0,'root API authorization denial failed')


def write_selections(value):
    SELECTIONS.write_text(json.dumps(value));SELECTIONS.chmod(0o644)


def stage(check,payload):
    install(check,payload);history=pause_history(check);quiet_maintenance(check)
    try:
        # The packaged builder makes the coordinator image; the API only stages a ready one.
        identifier,_=coordinator.build_image(check)
        before={'loader':Path('/boot/loader/loader.conf').read_text(),'limine':Path('/boot/limine/limine.conf').read_text()}
        with native.operation_lock():birth.create_fallback(PROBE)
        root=births()[PROBE]['root']['uuid'];plan=retirement.plan(root);check(plan['retirable'],'fresh orphan root protected: '+json.dumps(plan['protection']))
        expected='root-'+root.replace('-','')[:32]
        write_selections({'12':{'root_uuid':root,'plan_sha256':plan['plan_sha256']},'13':{'id':expected,'image':identifier,'exit':'poweroff'},'14':{'id':expected},'image':identifier})
        inventory_before=native.output(['pacman','-Q']);authority=native.authority_identity()
        denials(check);cancelled=authenticated(check,'auth-cancel')
        check(not list((CONTROL/'backend-operations').glob('*.json')) or all(json.loads(p.read_text())['operation'] not in ('root-retire-prepare','root-retire-stage','root-retire-finish') for p in (CONTROL/'backend-operations').glob('*.json')),'cancelled auth created a root job')
        check(expected not in retirement.records(),'denied requests prepared a retirement')
        staged=authenticated(check,'stage')
        value=retirement.records()[expected];check(value['phase']=='prepared' and value['coordinator']['image']==identifier,'API did not stage the coordinator over the built image')
        entry=value['coordinator'];uefi=coordinator.uefi_staged(check,entry,before['loader'])
        _,entries,selected=native.limine_menu(Path('/boot/limine/limine.conf').read_text());check(entries[selected-1]['title']==entry['bios_title'],'BIOS default not staged')
        check(native.output(['pacman','-Q'])==inventory_before and native.authority_identity()==authority,'API staging changed packages/authority')
        markers=[w.split('=',1)[1] for w in Path('/proc/cmdline').read_text().split() if w.startswith('enzimos.generation=')]
        native.atomic_json(STATE,{'boot_id':native.boot_id(),'id':expected,'targets':plan['targets'],'before':before,'running':markers,'image':identifier,
                                  'inventory':inventory_before,'authority':authority,'history':history,'prompts':cancelled['password_prompts']+staged['password_prompts']})
        os.sync()
        return {**uefi,'real_active_admin_authorization':True,'ordinary_inactive_denied':True,'auth_cancel_no_job':True,'draft_cancellations':True,
                'stale_digest_refused':True,'unready_image_refused':True,'pending_retirement_blocks_prepare':True,'prepared_via_api':True,
                'coordinator_staged_via_api':True,'packaged_image_built':True,'packages_authority_preserved':True,
                'password_prompts':cancelled['password_prompts']+staged['password_prompts'],'deleted_online':False}
    finally:native.run(['systemctl','stop',UNIT])


def finish(check,payload):
    saved=json.loads(STATE.read_text());check(saved['boot_id']!=native.boot_id(),'later boot required')
    markers=[w.split('=',1)[1] for w in Path('/proc/cmdline').read_text().split() if w.startswith('enzimos.generation=')]
    check(markers==saved['running'],'restored default did not boot the previous entry')
    quiet_maintenance(check);present=inventory()
    for row in saved['targets']:check(row['path'] not in present and all(v['uuid']!=row['uuid'] for v in present.values()),'coordinator deletion not observed: '+row['path'])
    check(retirement.records()[saved['id']]['phase']=='deleted','offline deletion not recorded')
    install(check,payload)
    try:
        write_selections({'12':{'root_uuid':'0'*8+'-0000-0000-0000-'+'0'*12,'plan_sha256':'0'*64},'13':{'id':saved['id'],'image':saved['image'],'exit':'poweroff'},'14':{'id':saved['id']},'image':saved['image']})
        denials(check);finished=authenticated(check,'finish')
        check(retirement.records()[saved['id']]['phase']=='complete' and births()[PROBE]['phase']=='retired','API finish did not complete/tombstone')
        check(Path('/boot/loader/loader.conf').read_text()==saved['before']['loader'] and Path('/boot/limine/limine.conf').read_text()==saved['before']['limine'],'loader metadata not restored exactly')
        ledger={str(p):native.sha(p) for p in (CONTROL/'backend-operations').glob('*.json')}
        native.run(['systemctl','restart',UNIT]);completed=authenticated(check,'completed')
        check(all(native.sha(Path(p))==v for p,v in ledger.items()),'restart changed ledger records')
        check(native.output(['pacman','-Q'])==saved['inventory'] and native.authority_identity()==saved['authority'],'API retirement changed packages/authority')
        STATE.unlink();restore_history(check,saved['history'])
        return {'later_boot':True,'previous_default_booted':True,'offline_deletion_observed':True,'finished_via_api':True,'birth_tombstoned':True,
                'loader_metadata_restored_exactly':True,'completed_restart_deduplicated':True,'packages_authority_preserved':True,
                'password_prompts':finished['password_prompts']+completed['password_prompts'],'deleted_by_backend':False}
    finally:native.run(['systemctl','stop',UNIT])


def qualify(check,selection,payload):
    check(native.output(['pacman','-Q','enzimos-native-policy'])==base.NATIVE,'wrong root API native candidate')
    return stage(check,payload) if selection=='root-api-stage' else finish(check,payload)
