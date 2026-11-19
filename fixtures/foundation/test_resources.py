#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Bounded retention/no-op checks; no automatic retirement of bootable generations."""
import json
import os
from pathlib import Path
import shutil
import native
from native import output,sha,run,Failure

CONTROL=Path('/var/lib/enzimos-control')


def qualify(check,module_trial):
    generation=(CONTROL/'updated-generation').read_text().strip()
    before_inventory=output(['pacman','-Q'])
    boot={str(p):sha(p) for p in Path('/boot').rglob('*') if p.is_file()}
    before_shots=output(['snapper','--no-dbus','-c','root','--csvout','list','--columns','number,type,pre-number'])
    authority=native.authority_identity()
    stage=native.STATE/'boot-stage'/generation
    check(stage.is_dir(),'completed staging fixture absent')
    pending=native.STATE/'boot-stage/fdn-pending-retention'
    pending.mkdir();(pending/'incomplete').write_text('must remain available for review/repair\n')
    live=native.ModuleView('fdn-current-retention')
    live.enter()
    try:
        cleaned=native.collect_resources()
        check(live.base.is_dir(),'current-boot live module view deleted')
        check(pending.is_dir(),'unpublished pending staging deleted')
        check(not stage.exists(),'published previous-boot staging not collected')
        check(any('/module-views/' in p for p in cleaned['removed']),'previous-boot module view not collected')
        module_trial()
    finally:live.leave()
    check(native.collect_resources()['removed']==[],'same-boot retained resources were collected')
    check(live.base.is_dir(),'detached same-boot module view deleted')
    shutil.rmtree(pending)
    protected={str(p) for base in ('module-views','boot-stage') for p in native.owned_directories(native.STATE/base)}
    for number in range(2):
        result=native.run_update('/etc/pacman-foundation.conf','fdn-noop-'+str(number),native.installed_kernels(),Path('/proc/cmdline').read_text().strip())
        check(result=={'status':'up-to-date-no-new-generation'},'repeat update was not a true full-upgrade no-op')
    check(protected=={str(p) for base in ('module-views','boot-stage') for p in native.owned_directories(native.STATE/base)},'no-op allocated resources')
    check(output(['snapper','--no-dbus','-c','root','--csvout','list','--columns','number,type,pre-number'])==before_shots,'no-op or transient cleanup changed retained root snapshots')
    # A conservative bounded refusal protects all existing boot resources. These
    # empty capacity witnesses are NOT represented as usable boot generations.
    witnesses=[]
    try:
        for i in range(native.MAX_BOOT_GENERATIONS):
            p=Path('/boot/enzimos/generations')/('fdn-capacity-witness-'+str(i));p.mkdir();witnesses.append(p)
        try:native.admit_generation()
        except Failure as exc:check('retention bound' in str(exc),'wrong retention-bound refusal')
        else:raise AssertionError('unbounded boot generation allocation admitted')
    finally:
        for p in witnesses:p.rmdir()
    check(output(['pacman','-Q'])==before_inventory,'retention checks changed installed packages')
    check(native.authority_identity()==authority,'cleanup changed authority')
    check(all(sha(p)==digest for p,digest in boot.items()),'cleanup/admission changed boot resources')
    module_trial()
    native.select_generation(generation,'linux')
    (CONTROL/'boot-step').write_text('0')
    return {'cleanup':cleaned,'same_boot_live_and_detached_views_preserved':True,'unpublished_staging_preserved':True,
            'full_upgrade_noop_repeats':2,'no_snapshot_or_generation_growth':True,'retention_bound_rejected':True,
            'boot_resources_inventory_authority_preserved':True,'automatic_bootable_generation_retirement':False}
