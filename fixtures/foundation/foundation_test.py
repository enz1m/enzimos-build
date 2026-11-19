#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Closed disposable-guest qualification scenarios, not shipped user workflows."""
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import traceback

sys.path.insert(0,'/usr/lib/enzimos')
import native
import backup
from native import run,output,sha,Failure
CONTROL=Path('/var/lib/enzimos-control')
RESULTS=[]


def check(condition, message):
    if not condition: raise AssertionError(message)

def case(identifier, function):
    print('ENZIMOS_FOUNDATION_CASE_START '+identifier,flush=True)
    started=time.monotonic()
    detail=function() or {}
    row={'case':identifier,'status':'PASS','seconds':round(time.monotonic()-started,3),'detail':detail}
    RESULTS.append(row)
    print('ENZIMOS_FOUNDATION_CASE_PASS '+identifier,flush=True)
    return detail

def mounted_payload():
    if not os.path.ismount('/payload'):
        Path('/payload').mkdir(exist_ok=True)
        run(['mount','-t','iso9660','-o','ro,nodev,nosuid,noexec','/dev/disk/by-id/virtio-enzimos-lab-payload','/payload'])
    if Path('/dev/disk/by-id/virtio-enzimos-lab-patch').exists():
        if not os.path.ismount('/patches'):
            Path('/patches').mkdir(exist_ok=True)
            run(['mount','-t','iso9660','-o','ro,nodev,nosuid,noexec','/dev/disk/by-id/virtio-enzimos-lab-patch','/patches'])
        return '/patches'
    return '/payload'

def authority():
    check(output(['findmnt','-n','-o','FSROOT','/etc/pacman.d/gnupg'])=='/fdn-authority','authority mount missing')
    return sha('/etc/pacman.d/gnupg/pubring.gpg')

def kernels():
    d={}
    for line in (CONTROL/'kernels.env').read_text().splitlines():
        k,v=line.split('=',1);d[k]=v
    return d

def package_rows(label):
    wanted=(CONTROL/(label+'-packages.txt')).read_text().splitlines()
    actual=output(['pacman','-Q']).splitlines()
    actual=[line for line in actual if not line.startswith('enzimos-native-policy ')]
    check(sorted(actual)==sorted(wanted),'package inventory mismatch: '+label)

def snap_list(name):
    text=output(['snapper','--no-dbus','-c',name,'--csvout','list','--columns','number,type,pre-number'])
    return list(csv.DictReader(io.StringIO(text)))

def new_snapshot_pairs(before,after):
    old={row['number'] for row in before}
    pre={row['number'] for row in after if row['type']=='pre' and row['number'] not in old}
    return [(row['pre-number'],row['number']) for row in after if row['type']=='post' and row['number'] not in old and row['pre-number'] in pre]


def module_trial():
    run(['modprobe','overlay']);check(Path('/sys/module/overlay').exists(),'normal overlay load')
    run(['modprobe','-r','overlay'])
    run(['ip','link','add','enz-autoload','type','veth','peer','name','enz-autopeer'])
    check(Path('/sys/module/veth').exists(),'kernel-requested veth autoload')
    run(['ip','link','del','enz-autoload']);run(['modprobe','-r','veth'])

def probe_module_view():
    mounted_payload();before=output(['readlink','/proc/self/ns/mnt'])
    original=output(['stat','-Lc','%d:%i','/usr/lib/modules'])
    with native.operation_lock():
        view=native.ModuleView('probe-'+str(time.time_ns()));view.enter()
        try:
            module_trial()
            data=output(['unshare','--mount','--propagation','private','bash','-ec','mount --bind "$1" /usr/lib/modules; stat -Lc "%d:%i" /usr/lib/modules; touch /usr/lib/modules/.enzimos-transaction-witness','probe',str(view.original)])
            check(data==original,'private transaction view is not the original package-owned directory')
            check((view.original/'.enzimos-transaction-witness').exists(),'transaction write did not reach original tree')
            check(not Path('/usr/lib/modules/.enzimos-transaction-witness').exists(),'transaction write leaked into retained live view')
            (view.original/'.enzimos-transaction-witness').unlink()
        finally:view.leave()
    module_trial()
    boot={p.name:p.stat().st_size for p in Path('/boot').iterdir() if p.name.startswith(('vmlinuz-','initramfs-'))}
    return {'initial_namespace':before,'transaction_inode':data,'original_inode':original,'boot_files':boot,'esp_free':shutil.disk_usage('/boot').free}

def update(fault=None):
    mounted_payload();k=kernels();package_rows('old')
    check(os.uname().release==k['OLD_REGULAR'],'old regular kernel required')
    a=authority();before=snap_list('root');home_before=snap_list('home')
    old_inventory=output(['pacman','-Q'])
    generation='fdn-'+(fault or 'success')
    options=Path('/proc/cmdline').read_text().strip()
    # Strip fixture selectors; retain real encrypted-root and security parameters.
    options=' '.join(x for x in options.split() if not x.startswith('enzimos.'))
    observed={'during':False,'samples':0}
    transaction_log=Path('/var/log/pacman-foundation.log')
    initial_log_bytes=transaction_log.stat().st_size if transaction_log.exists() else 0
    def observer(child):
        text=transaction_log.read_bytes()[initial_log_bytes:].decode(errors='replace') if transaction_log.exists() else ''
        if not observed['during'] and '[ALPM] upgraded linux (' in text and '[ALPM] transaction completed' not in text:
            os.killpg(child.pid,signal.SIGSTOP)
            try:
                check(not (native.RUN/'transaction-modules'/k['OLD_REGULAR']/'kernel/fs/overlayfs/overlay.ko.zst').exists(),'transaction view unexpectedly retained package file; inspect timing')
                module_trial();observed['during']=True
                print('ENZIMOS_FOUNDATION_DURING_LOAD_PASS normal-path kernel-autoload',flush=True)
            finally:os.killpg(child.pid,signal.SIGCONT)
        if time.monotonic()-observed.get('last',0)>1:
            check(Path('/usr/lib/modules',k['OLD_REGULAR'],'kernel/fs/overlayfs/overlay.ko.zst').is_file(),'ordinary running module path disappeared')
            observed['samples']+=1;observed['last']=time.monotonic()
    hook=None
    try:
        if fault in ('pre-hook','post-hook'):
            hook=Path('/etc/pacman.d/hooks/00-fdn-fail.hook' if fault=='pre-hook' else '/etc/pacman.d/hooks/98-fdn-fail.hook')
            hook.parent.mkdir(parents=True,exist_ok=True)
            hook.write_text('[Trigger]\nOperation = Upgrade\nType = Package\nTarget = linux\n[Action]\nWhen = '+('PreTransaction' if fault=='pre-hook' else 'PostTransaction')+'\nExec = /usr/bin/false\n'+('AbortOnFail\n' if fault=='pre-hook' else ''))
        try:
            result=native.run_update('/etc/pacman-foundation.conf',generation,{'linux':k['NEW_REGULAR'],'linux-lts':k['NEW_LTS']},options,observer)
            check(fault is None,'injected hook failure was not rejected')
        except (native.Failure,subprocess.CalledProcessError) as exc:
            if fault not in ('pre-hook','post-hook'):raise
            check('package transaction/hook failed' in str(exc),'failure did not come from the transaction/hook result')
            log=(native.STATE/(generation+'-pacman.log')).read_text()
            check(hook.name in log and 'error: command failed to execute correctly' in log,'injected hook was not observed failing')
            package_rows('old' if fault=='pre-hook' else 'new')
            check(authority()==a,'hook failure changed authority')
            check(not Path('/boot/enzimos/generations',generation,'PUBLISHED.json').exists(),'failed hook published a boot generation')
            fallback=json.loads((native.STATE/(generation+'-fallback.json')).read_text())
            check(native.generation_selected(fallback['generation']),'coherent fallback is not selected')
            published=json.loads((Path('/boot/enzimos/generations')/fallback['generation']/'PUBLISHED.json').read_text())
            native.atomic_json(CONTROL/'usable-boot.json',{'root':fallback['subvolume'],'inventory':old_inventory,
                'kernels':fallback['kernels'],'generation':fallback['generation'],'bios_first':published['bios_first_entry'],
                'uefi_ids':['enzimos-'+fallback['generation']+'-'+f+'.conf' for f in ('linux','linux-lts')]})
            (CONTROL/'usable-boot-step').write_text('0')
            module_trial()
            return {'rejected':fault,'specific_hook_failure_observed':True,'boot_published':False,'coherent_fallback_selected':True,'fallback':fallback}
    finally:
        if hook:hook.unlink(missing_ok=True)
    package_rows('new');module_trial();check(observed['during'],'missed deterministic during-update module test')
    check(authority()==a,'authority changed')
    after=snap_list('root');home_after=snap_list('home')
    pairs=new_snapshot_pairs(before,after)
    check(pairs,'new matching snap-pac pre/post pair absent')
    check(not new_snapshot_pairs(home_before,home_after),'system update unexpectedly made a home pre/post pair')
    # Keep original legacy files for recovery; publish/select complete new generation.
    native.select_generation(generation,'linux')
    (CONTROL/'updated-generation').write_text(generation)
    (CONTROL/'boot-step').write_text('0')
    return {'during':True,'after':True,'ordinary_path_samples':observed['samples'],'snapper_before':before,'snapper_after':after,'new_pre_post_pairs':pairs,'home_before':home_before,'home_after':home_after,'generation':generation,'boot_files':result}

def boot_check():
    k=kernels();package_rows('new');step=int((CONTROL/'boot-step').read_text())
    sequence=[(True,k['NEW_REGULAR']),(True,k['NEW_LTS']),(False,k['NEW_REGULAR']),(False,k['NEW_LTS'])]
    check(0<=step<4,'four-boot sequence already complete')
    mode,version=sequence[step]
    check(os.uname().release==version and Path('/sys/firmware/efi').exists()==mode,'wrong loader/kernel in boot matrix')
    module_trial();authority()
    native.select_generation((CONTROL/'updated-generation').read_text().strip(),'linux-lts' if step in (0,2) else 'linux')
    (CONTROL/'boot-step').write_text(str(step+1))
    return {'kernel':version,'uefi':mode,'step':step}


def usable_boot():
    record=json.loads((CONTROL/'usable-boot.json').read_text())
    check(output(['findmnt','-n','-o','FSROOT','/'])=='/'+record['root'],'wrong usable root')
    check(output(['pacman','-Q'])==record['inventory'],'usable root package inventory differs')
    step=int((CONTROL/'usable-boot-step').read_text());sequence=[(True,'linux'),(True,'linux-lts'),(False,'linux'),(False,'linux-lts')]
    check(0<=step<4,'usable four-boot sequence already complete')
    mode,flavor=sequence[step]
    check(os.uname().release==record['kernels'][flavor] and Path('/sys/firmware/efi').exists()==mode,'wrong usable loader/kernel')
    module_trial();authority()
    next_index=1 if step in (0,2) else 0
    native.atomic_text('/boot/loader/loader.conf',f'default {record["uefi_ids"][next_index]}\ntimeout 0\neditor no\n')
    import re
    path=Path('/boot/limine/limine.conf');native.atomic_text(path,re.sub(r'^default_entry: .*$',f'default_entry: {record["bios_first"]+next_index}',path.read_text(),flags=re.M))
    (CONTROL/'usable-boot-step').write_text(str(step+1))
    return {'root':record['root'],'kernel':os.uname().release,'uefi':mode,'step':step}


def restored_boot():
    record=json.loads((CONTROL/'restored-boot.json').read_text())
    check(output(['findmnt','-n','-o','FSROOT','/'])=='/'+record['root'],'wrong restored root')
    expected=json.loads((CONTROL/'restore-source.json').read_text())['inventory'] if record['root']=='fdn-restored' else json.loads((CONTROL/'interrupted-update.json').read_text())['old_inventory']
    check(output(['pacman','-Q'])==expected,'restored package inventory differs')
    step=int((CONTROL/'restored-boot-step').read_text()) if (CONTROL/'restored-boot-step').exists() else 0
    sequence=[(True,'linux'),(True,'linux-lts'),(False,'linux'),(False,'linux-lts')]
    check(0<=step<4,'restored four-boot sequence complete')
    mode,flavor=sequence[step]
    check(os.uname().release==record['kernels'][flavor] and Path('/sys/firmware/efi').exists()==mode,'wrong restored loader/kernel')
    check(Path('/home/enzimos-admin/foundation-home-marker').read_text()=='NEWER-HOME-MUST-SURVIVE-ROOT-RESTORE\n','newer home lost')
    module_trial();authority()
    next_flavor='linux-lts' if step in (0,2) else 'linux'
    native.atomic_text('/boot/loader/loader.conf',f'default {record["root"]}-{next_flavor}.conf\ntimeout 0\neditor no\n')
    import re
    path=Path('/boot/limine/limine.conf');native.atomic_text(path,re.sub(r'^default_entry: .*$',f'default_entry: {record["bios_first"]+(1 if next_flavor=="linux-lts" else 0)}',path.read_text(),flags=re.M))
    (CONTROL/'restored-boot-step').write_text(str(step+1))
    return {'root':record['root'],'kernel':os.uname().release,'uefi':mode,'step':step}

def boot_identity_check():
    import boot_inventory
    info=json.loads((CONTROL/'identity-boots.json').read_text());step=info['step']
    sequence=[(True,'linux'),(True,'linux-lts'),(False,'linux'),(False,'linux-lts')]
    check(0<=step<4,'identity boot matrix already complete')
    mode,flavor=sequence[step]
    check(os.uname().release==info['kernels'][flavor] and Path('/sys/firmware/efi').exists()==mode,'wrong identity-test kernel/loader')
    check(output(['pacman','-Q'])==info['inventory'],'identity-test package inventory changed')
    observation=boot_inventory.collect()
    check(observation['running_marker']==info['generation'],'running generation marker was not observed')
    check(observation['complete'] is False and observation['execution_available'] is False,'observation was mistaken for retirement authority')
    module_trial();authority()
    native.select_generation(info['generation'],'linux-lts' if step in (0,2) else 'linux')
    info['step']=step+1;native.atomic_json(CONTROL/'identity-boots.json',info)
    native.atomic_json(CONTROL/f'boot-observation-{step}.json',observation)
    return {'kernel':os.uname().release,'uefi':mode,'step':step,'running_marker':observation['running_marker'],
            'namespace_count':len(observation['mount_namespaces']['namespaces']),
            'efi_observable':observation['efi_observable'],'retirement_enabled':False,'blockers':observation['blockers']}


def registry_boot_check():
    import generation_registry as registry
    info=json.loads((CONTROL/'registry-boots.json').read_text());step=info['step']
    sequence=[(True,info['first'],'linux'),(True,info['second'],'linux'),(True,info['second'],'linux-lts'),(False,info['second'],'linux'),(False,info['second'],'linux-lts')]
    check(0<=step<len(sequence),'registry boot sequence complete')
    mode,generation,flavor=sequence[step]
    check(os.uname().release==info['kernels'][flavor] and Path('/sys/firmware/efi').exists()==mode,'wrong registry kernel/loader')
    check(output(['pacman','-Q'])==info['inventory'],'registry package inventory changed')
    check(registry.current_marker()==generation,'registry marker mismatch')
    tamper_rejected=False
    if step==0:
        entry=Path('/boot/loader/entries')/f'enzimos-{generation}-{flavor}.conf';original=entry.read_text()
        catalog=CONTROL/'generation-registry/catalog.json';before=sha(catalog)
        native.atomic_text(entry,original.replace('title ','title altered-fixture ',1))
        try:
            try:registry.confirm_current()
            except Failure as exc:
                check('fingerprints changed' in str(exc),'unexpected tamper failure');tamper_rejected=True
            else:raise AssertionError('changed loader entry received confirmation')
            check(sha(catalog)==before,'failed confirmation modified registry')
        finally:native.atomic_text(entry,original)
    result=registry.confirm_current();state=registry.status()
    check(result['generation']==generation and result['retirement_enabled'] is False,'invalid observed confirmation')
    rows=state['catalog']['generations'];confirmed=sum(row['first_confirmation'] is not None for row in rows.values())
    check(confirmed==(1 if step==0 else 2),'publisher confirmation count mismatch')
    check(state['root_ownership_established'] is False and state['independent_recovery_confirmation_available'] is False,'registry overclaimed retirement readiness')
    module_trial();authority()
    next_flavor='linux-lts' if step in (1,3) else 'linux'
    native.select_generation(info['second'],next_flavor)
    info['step']=step+1;native.atomic_json(CONTROL/'registry-boots.json',info)
    return {'generation':generation,'step':step,'kernel':os.uname().release,'uefi':mode,'confirmed_system_generations':confirmed,
            'confirmation':result['confirmation'],'tamper_rejected':tamper_rejected,'retirement_enabled':False}


def do_backups(selection):
    sys.path.insert(0,mounted_payload())
    import test_backups
    return test_backups.run_group(selection,case,check)

def do_defaults():
    sys.path.insert(0,mounted_payload())
    import test_defaults
    return test_defaults.run_all(case,check)

def main():
    run(['modprobe','qemu_fw_cfg'])
    selection=Path('/sys/firmware/qemu_fw_cfg/by_name/opt/enzimos/case/raw').read_bytes().decode().strip('\x00\n')
    CONTROL.mkdir(exist_ok=True)
    try:
        if selection=='probe-modules':case('U1-view',probe_module_view)
        elif selection=='updates':case('U1-U2-R1',update)
        elif selection=='boot-new':case('U2-boot',boot_check)
        elif selection=='boot-usable':case('usable-boot',usable_boot)
        elif selection=='fault-pre':case('U3-pre',lambda:update('pre-hook'))
        elif selection=='fault-post':case('U3-post',lambda:update('post-hook'))
        elif selection in ('backup-create','backup-recapture','backup-legacy-fidelity','backup-fidelity','backup-retention','backup-break'):do_backups(selection)
        elif selection=='defaults':do_defaults()
        elif selection in ('coordinator-stage','coordinator-build-stage','coordinator-finish'):
            payload=mounted_payload();sys.path.insert(0,payload);import test_coordinator_boot
            case('R-'+selection,lambda:test_coordinator_boot.qualify(check,selection,payload))
        elif selection in ('fallback-retire-prepare','fallback-retire-finish'):
            sys.path.insert(0,mounted_payload());import test_fallback_retirement
            case('R-'+selection,lambda:test_fallback_retirement.qualify(check,selection))
        elif selection in ('root-api-stage','root-api-finish'):
            payload=mounted_payload();sys.path.insert(0,payload);import test_root_api69
            case('A10-'+selection,lambda:test_root_api69.qualify(check,selection,payload))
        elif selection=='lifecycle63-api':
            payload=mounted_payload();sys.path.insert(0,payload);import test_lifecycle63_api
            case('A9-lifecycle63',lambda:test_lifecycle63_api.qualify(check,payload))
        elif selection in ('root-retire-prepare','root-retire-finish'):
            sys.path.insert(0,mounted_payload());import test_root_retirement
            case('R-'+selection,lambda:test_root_retirement.qualify(check,selection))
        elif selection in ('boot-retirement','boot-retirement-review'):
            sys.path.insert(0,mounted_payload());import test_boot_retirement
            case('R-'+selection,lambda:test_boot_retirement.qualify(check,selection))
        elif selection in ('deferred-owed','deferred-resume'):
            sys.path.insert(0,mounted_payload());import test_deferred_work
            case('R-'+selection,lambda:test_deferred_work.qualify(check,selection))
        elif selection in ('backup-rotation','backup-rotation-cut'):
            sys.path.insert(0,mounted_payload());import test_backup_rotation
            case('R-backup-rotation',lambda:test_backup_rotation.qualify(check,selection))
        elif selection=='backup-rotation-review':
            sys.path.insert(0,mounted_payload());import test_backup_rotation
            case('R-backup-rotation-review',lambda:test_backup_rotation.qualify(check,selection))
        elif selection=='backup-deferral-review':
            sys.path.insert(0,mounted_payload());import test_backup_deferral
            case('R-backup-deferral-review',lambda:test_backup_deferral.review(check))
        elif selection=='backup-deferral':
            sys.path.insert(0,mounted_payload());import test_backup_deferral
            case('R-backup-deferral',lambda:test_backup_deferral.qualify(check))
        elif selection=='maintenance-retry':
            sys.path.insert(0,mounted_payload());import test_maintenance_retry
            case('S7-maintenance-retry',lambda:test_maintenance_retry.qualify(check))
        elif selection=='boot-observe':
            sys.path.insert(0,mounted_payload());import test_boot_observation
            case('L1-observe',lambda:test_boot_observation.prepare(check))
        elif selection=='boot-identity':case('L1-boot',boot_identity_check)
        elif selection=='registry-prepare':
            sys.path.insert(0,mounted_payload());import test_registry
            case('L2-publisher-registry',lambda:test_registry.prepare(check))
        elif selection=='registry-boot':case('L2-confirm-boot',registry_boot_check)
        elif selection.startswith('publication-cut-'):
            payload=mounted_payload();sys.path.insert(0,payload);import test_recovery_publication
            boundary={'kernel':'artifact:kernel','artifacts':'artifacts','uefi':'uefi','bios':'bios'}[selection.removeprefix('publication-cut-')]
            case('R8-cut',lambda:test_recovery_publication.cut(payload,boundary,check))
        elif selection=='publication-recover':
            import test_recovery_publication
            case('R8-recover',lambda:test_recovery_publication.recover(check))
        elif selection=='image-prepare':
            payload=mounted_payload();sys.path.insert(0,payload);import test_recovery_image
            case('R7-publish',lambda:test_recovery_image.prepare(payload,check))
        elif selection in ('durable-cut-running','durable-cut-completed','durable-review'):
            fixture=mounted_payload();sys.path.insert(0,fixture);import test_durable_cut
            if selection=='durable-review':case('A2-durable-review',lambda:test_durable_cut.review(check))
            else:case('A2-durable-cut',lambda:test_durable_cut.cut(check,selection.removeprefix('durable-cut-')))
        elif selection=='core-build':
            fixture=mounted_payload();sys.path.insert(0,fixture);import test_core_build
            case('B2-core-build',lambda:test_core_build.qualify(check,fixture))
        elif selection=='clean-builder':
            fixture=mounted_payload();sys.path.insert(0,fixture);import test_clean_builder
            case('B1-clean-builder',lambda:test_clean_builder.qualify(check,fixture))
        elif selection=='backend-api':
            fixture=mounted_payload();sys.path.insert(0,fixture);import test_backend_api
            case('A1-backend',lambda:test_backend_api.qualify(check,fixture))
        elif selection=='backup-destination':
            sys.path.insert(0,mounted_payload());import test_backup_destination
            case('R12-destination',lambda:test_backup_destination.qualify(check))
        elif selection=='activation-prepare':
            fixture=mounted_payload();sys.path.insert(0,fixture);import test_recovery_activation
            case('R11-prepare',lambda:test_recovery_activation.prepare(check,fixture))
        elif selection=='activation-boot':
            import test_recovery_activation
            case('R11-boot',lambda:test_recovery_activation.boot(check,module_trial))
        elif selection=='staged-review-prepare':
            sys.path.insert(0,mounted_payload());import test_recovery_stage
            case('R10-prepare',lambda:test_recovery_stage.prepare(check,review_only=True))
        elif selection=='staged-review-graph':
            sys.path.insert(0,mounted_payload());import test_staged_review
            case('R10-graph',lambda:test_staged_review.graph(check))
        elif selection in ('recovery-prepare','recovery-stage-boot'):
            if selection=='recovery-prepare':sys.path.insert(0,mounted_payload())
            import test_recovery_stage
            if selection=='recovery-prepare':case('R6-prepare',lambda:test_recovery_stage.prepare(check))
            else:case('R6-boot',lambda:test_recovery_stage.boot(check,module_trial))
        elif selection=='recovery-references':
            sys.path.insert(0,mounted_payload());import test_recovery_references
            case('R9-references',lambda:test_recovery_references.qualify(check))
        elif selection=='backup-capture':
            sys.path.insert(0,mounted_payload());import test_backup_capture
            case('R13-capture',lambda:test_backup_capture.qualify(check))
        elif selection=='backup-sources':
            sys.path.insert(0,mounted_payload());import test_backup_sources
            case('R14-sources',lambda:test_backup_sources.qualify(check))
        elif selection=='backend-kill':
            sys.path.insert(0,mounted_payload());import test_backend_kill
            case('A6-kill',lambda:test_backend_kill.qualify(check,mounted_payload()))
        elif selection=='batch-hardening':
            sys.path.insert(0,mounted_payload());import test_batch_hardening
            case('B3-batch',lambda:test_batch_hardening.qualify(check,mounted_payload()))
        elif selection=='batch-remote':
            sys.path.insert(0,mounted_payload());import test_remote_backup
            case('B3-remote',lambda:test_remote_backup.qualify(check,mounted_payload(),53,True))
        elif selection=='workflow-prepare':
            sys.path.insert(0,mounted_payload());import test_recovery_activation
            case('B3-prepare',lambda:test_recovery_activation.prepare(check,mounted_payload(),53))
        elif selection in ('recovery-api-cut-running','recovery-api-cut-completed','recovery-api-cut-review'):
            sys.path.insert(0,mounted_payload());import test_recovery_api_cut
            if selection=='recovery-api-cut-review':case('A7-review',lambda:test_recovery_api_cut.review(check))
            else:case('A7-cut',lambda:test_recovery_api_cut.cut(check,mounted_payload(),selection.rsplit('-',1)[-1]))
        elif selection in ('update-api','update-api-boot','update-api-cut','update-api-cut-review'):
            sys.path.insert(0,mounted_payload());import test_update_api
            if selection in ('update-api','update-api-cut'):case('A5-update',lambda:test_update_api.qualify(check,mounted_payload(),module_trial,selection=='update-api-cut'))
            elif selection=='update-api-cut-review':case('A5-cut-review',lambda:test_update_api.cut_review(check,module_trial))
            else:case('A5-boot',lambda:test_update_api.boot(check,module_trial))
        elif selection in ('lifecycle-worker-cut-running','lifecycle-worker-cut-completed','lifecycle-worker-review'):
            sys.path.insert(0,mounted_payload());import test_lifecycle_api_cut
            if selection=='lifecycle-worker-review':case('A8-lifecycle-review',lambda:test_lifecycle_api_cut.review(check))
            else:case('A8-lifecycle-cut',lambda:test_lifecycle_api_cut.cut(check,mounted_payload(),selection.rsplit('-',1)[-1]))
        elif selection=='lifecycle-api':
            sys.path.insert(0,mounted_payload());import test_lifecycle_api
            case('A8-lifecycle',lambda:test_lifecycle_api.qualify(check,mounted_payload()))
        elif selection=='recovery-api':
            sys.path.insert(0,mounted_payload());import test_recovery_api
            case('A4-recovery',lambda:test_recovery_api.qualify(check,mounted_payload()))
        elif selection in ('delivery-lifecycle','delivery-lifecycle-review'):
            sys.path.insert(0,mounted_payload());import test_delivery_lifecycle
            case('R22-delivery-lifecycle',lambda:test_delivery_lifecycle.qualify(check,selection))
        elif selection in ('credential-review-controls','credential-review-cut','credential-review-resume'):
            sys.path.insert(0,mounted_payload());import test_credential_review
            case('R21-credential-review',lambda:test_credential_review.qualify(check,selection))
        elif selection=='backup-credentials':
            sys.path.insert(0,mounted_payload());import test_backup_credentials
            case('R20-credentials',lambda:test_backup_credentials.qualify(check))
        elif selection=='backup-schedule':
            sys.path.insert(0,mounted_payload());import test_backup_schedule
            case('R19-schedule',lambda:test_backup_schedule.qualify(check))
        elif selection=='flatpak-capture':
            sys.path.insert(0,mounted_payload());import test_flatpak_capture
            case('R18-flatpak-lock',lambda:test_flatpak_capture.qualify(check))
        elif selection=='application-backup':
            sys.path.insert(0,mounted_payload());import test_application_backup
            case('R17-appdata',lambda:test_application_backup.qualify(check,mounted_payload()))
        elif selection=='selective-backup':
            sys.path.insert(0,mounted_payload());import test_selective_backup
            case('R16-selective',lambda:test_selective_backup.qualify(check))
        elif selection=='payload-script':
            # Generic: run(check,payload) of the module named in the (input-bound) payload.
            payload=mounted_payload();sys.path.insert(0,payload);import importlib
            spec=json.loads((Path(payload)/'payload-script.json').read_text());module=importlib.import_module(spec['module'])
            case('P-'+spec['module'],lambda:module.run(check,payload))
        elif selection in ('adopted-update','adopted-update-boot'):
            payload=mounted_payload();sys.path.insert(0,payload);import test_adopted_update
            case('U5-'+selection,lambda:test_adopted_update.qualify(check,selection,payload))
        elif selection in ('recovery-run-stage','recovery-run-finish'):
            payload=mounted_payload();sys.path.insert(0,payload);import test_recovery_run
            case('R24-'+selection,lambda:test_recovery_run.qualify(check,selection,payload))
        elif selection in ('calendar-firing','calendar-persistent'):
            sys.path.insert(0,mounted_payload());import test_calendar_firing
            case('S8-'+selection,lambda:test_calendar_firing.qualify(check,selection))
        elif selection=='remote-rotation':
            sys.path.insert(0,mounted_payload());import test_remote_rotation
            case('R23-remote-rotation',lambda:test_remote_rotation.qualify(check,mounted_payload()))
        elif selection=='remote-backup':
            sys.path.insert(0,mounted_payload());import test_remote_backup
            case('R15-smb',lambda:test_remote_backup.qualify(check,mounted_payload()))
        elif selection in ('backup-api-cut-running','backup-api-cut-completed','backup-api-review'):
            sys.path.insert(0,mounted_payload());import test_backup_api_cut
            if selection=='backup-api-review':case('A3-review',lambda:test_backup_api_cut.review(check))
            else:case('A3-cut',lambda:test_backup_api_cut.cut(check,selection.removeprefix('backup-api-cut-')))
        elif selection=='backup-api':
            sys.path.insert(0,mounted_payload());import test_backup_api
            case('A3-backup',lambda:test_backup_api.qualify(check,mounted_payload()))
        elif selection.startswith('journal-engine-'):
            sys.path.insert(0,mounted_payload());import test_retirement_journal
            if selection=='journal-engine-prepare':case('L11-prepare',lambda:test_retirement_journal.prepare(check))
            else:case('L11-engine',lambda:test_retirement_journal.replay(check,selection))
        elif selection=='rebind-references':
            sys.path.insert(0,mounted_payload());import test_rebind_references
            case('L10-rebind-refs',lambda:test_rebind_references.qualify(check))
        elif selection=='retirement-context-prepare':
            sys.path.insert(0,mounted_payload());import test_retirement_context
            case('L9-prepare',lambda:test_retirement_context.prepare(check))
        elif selection=='mapped-references':
            sys.path.insert(0,mounted_payload());import test_mapped_references
            case('L8-mappings',lambda:test_mapped_references.qualify(check))
        elif selection=='process-references':
            sys.path.insert(0,mounted_payload());import test_process_references
            case('L7-process',lambda:test_process_references.qualify(check))
        elif selection=='generation-pins':
            sys.path.insert(0,mounted_payload());import test_generation_pins
            case('L6-pins',lambda:test_generation_pins.qualify(check))
        elif selection=='root-references':
            sys.path.insert(0,mounted_payload());import test_root_references
            case('L5-references',lambda:test_root_references.qualify(check))
        elif selection in ('ownership-prepare','ownership-update','ownership-boot','ownership-cut','ownership-pending'):
            if selection in ('ownership-prepare','ownership-update'):sys.path.insert(0,mounted_payload())
            import test_ownership
            if selection=='ownership-prepare':case('L4-birth',lambda:test_ownership.prepare(check))
            elif selection=='ownership-update':case('L4-update',lambda:test_ownership.updated(update,check,kernels))
            elif selection=='ownership-boot':case('L4-boot',lambda:test_ownership.boot(check,module_trial))
            elif selection=='ownership-cut':case('L4-cut',lambda:test_ownership.interrupted(check))
            else:case('L4-pending',lambda:test_ownership.pending(check,module_trial))
        elif selection in ('rebind-update','rebind-cut','rebind-replay','rebind-select-old','rebind-boot','rebind-fallback-boot'):
            if selection in ('rebind-update','rebind-cut'):mounted_payload()
            import test_rebind
            if selection=='rebind-update':case('L3-update',lambda:test_rebind.finished_update(update,check,kernels))
            elif selection=='rebind-cut':case('L3-cut',lambda:test_rebind.interrupted(check,kernels,module_trial))
            elif selection=='rebind-replay':case('L3-replay',lambda:test_rebind.replay(check,module_trial))
            elif selection=='rebind-select-old':case('L3-select-old',lambda:test_rebind.select_old(check))
            else:case('L3-boot',lambda:test_rebind.boot(check,module_trial,selection=='rebind-fallback-boot'))
        elif selection=='resources':
            sys.path.insert(0,mounted_payload());import test_resources
            case('U2-resources',lambda:test_resources.qualify(check,module_trial))
        elif selection=='boot-restored':case('restored-boot',restored_boot)
        elif selection in ('fault-initrd','full-esp','boot-write'):
            sys.path.insert(0,mounted_payload());import test_faults
            if selection=='fault-initrd':case('U4-cut',lambda:test_faults.interrupt(kernels(),check,module_trial))
            elif selection=='full-esp':case('U5-full-esp',lambda:test_faults.full_esp(check,module_trial))
            else:case('U5-write-repair',lambda:test_faults.boot_write(kernels(),check,module_trial))
        else:raise ValueError('unknown closed fixture case: '+selection)
        result={'case':selection,'status':'PASS','results':RESULTS}
    except BaseException as exc:
        traceback.print_exc();result={'case':selection,'status':'FAIL','error':str(exc),'results':RESULTS}
        print('ENZIMOS_FOUNDATION_FAILURE '+selection,flush=True)
    (CONTROL/'foundation-result.json').write_text(json.dumps(result,indent=2)+'\n')
    print('ENZIMOS_FOUNDATION_RESULT='+json.dumps(result,separators=(',',':')),flush=True)
    os.sync();run(['systemctl','--no-block','poweroff'])

if __name__=='__main__':main()
