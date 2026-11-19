#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Controlled update failures inside the explicitly disposable guest only."""
import errno
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import time
import native
from native import run,output,sha,Failure
CONTROL=Path('/var/lib/enzimos-control')
CUT='ENZIMOS_FOUNDATION_CUT_READY partial-initrd synced-process-group-stopped'


def select_recovery():
    native.atomic_text('/boot/loader/loader.conf','default recovery.conf\ntimeout 0\neditor no\n')
    p=Path('/boot/limine/limine.conf');native.atomic_text(p,re.sub(r'^default_entry: .*$', 'default_entry: 3',p.read_text(),flags=re.M))


def interrupt(kernels,check,module_trial):
    generation='fdn-initrd-interrupt';old=output(['pacman','-Q']);hit=False
    options=Path('/proc/cmdline').read_text().strip()
    home=Path('/home/enzimos-admin/foundation-home-marker');home.write_text('home-before-update\n')
    transaction_log=Path('/var/log/pacman-foundation.log')
    log_offset=transaction_log.stat().st_size if transaction_log.exists() else 0
    def observe(child):
        nonlocal hit
        if hit:return
        text=transaction_log.read_bytes()[log_offset:].decode(errors='replace') if transaction_log.exists() else ''
        if "running '90-mkinitcpio-install.hook'" not in text:return
        # The upstream remove hook deletes the previous image, so mkinitcpio writes
        # directly to .img rather than .tmp on an actual kernel upgrade.
        stage=native.STATE/'boot-stage'/generation
        candidates=[stage/'initramfs-linux.img.tmp',stage/'initramfs-linux.img']
        partial=next((p for p in candidates if p.is_file() and 1024**2<=p.stat().st_size<8*1024**2),None)
        if partial is None:return
        os.killpg(child.pid,signal.SIGSTOP);hit=True
        size=partial.stat().st_size
        check(0<size<64*1024**2,'unexpected partial initrd size')
        verification=subprocess.run(['lsinitcpio','-a',partial],capture_output=True,text=True)
        check(verification.returncode!=0,'checkpoint image was already complete')
        check(Path('/var/lib/pacman/db.lck').exists(),'transaction no longer owns pacman lock')
        check(output(['pacman','-Q','linux']).split()[1]!='7.2.4.arch1-2','regular kernel package not yet upgraded')
        module_trial()
        fallback=json.loads((native.STATE/(generation+'-fallback.json')).read_text())
        home.write_text('NEWER-HOME-MUST-SURVIVE-ROOT-RESTORE\n')
        (CONTROL/'authority-epoch').write_text('CURRENT-AUTHORITY-AFTER-SNAPSHOT\n')
        native.atomic_json(CONTROL/'interrupted-update.json',{'fallback':fallback,'old_inventory':old,'partial_initrd_bytes':size,'partial_initrd_name':partial.name,'partial_verification_returncode':verification.returncode,'partial_verification_error':verification.stderr[-4000:],'generation':generation,'authority':native.authority_identity()})
        select_recovery();os.sync()
        print(CUT,flush=True)
        # The bounded controller will issue QMP quit, not a guest shutdown.
        while True:time.sleep(1)
    native.run_update('/etc/pacman-foundation.conf',generation,{'linux':kernels['NEW_REGULAR'],'linux-lts':kernels['NEW_LTS']},options,observe)
    raise AssertionError('controlled initrd checkpoint was not interrupted')


def full_esp(check,module_trial):
    before=output(['pacman','-Q'])
    paths=[p for p in Path('/boot').rglob('*') if p.is_file()]
    hashes={str(p):sha(p) for p in paths}
    free=os.statvfs('/boot').f_bavail*os.statvfs('/boot').f_frsize
    filler=Path('/boot/enzimos-space-fixture')
    try:
        with filler.open('wb') as stream:
            for _ in range(max(0,free//1024**2-8)):stream.write(b'\0'*(1024**2))
            stream.flush();os.fsync(stream.fileno())
        try:native.run_update('/etc/pacman-foundation.conf','fdn-full-esp',{},Path('/proc/cmdline').read_text().strip())
        except Failure as exc:check('ESP space admission' in str(exc),'unexpected full-ESP failure')
        else:raise AssertionError('full ESP allowed package changes')
        check(output(['pacman','-Q'])==before,'full-ESP preflight changed packages')
        check(all(sha(p)==h for p,h in hashes.items()),'full-ESP preflight damaged boot resources')
        module_trial()
    finally:filler.unlink(missing_ok=True);os.sync()
    native.atomic_json(CONTROL/'usable-boot.json',{'root':native.config()['root_subvol'],'inventory':before,
        'kernels':native.installed_kernels(),'bios_first':1,'uefi_ids':['linux.conf','linux-lts.conf']})
    (CONTROL/'usable-boot-step').write_text('0')
    return {'real_fat_space_exhaustion':True,'package_state_unchanged':True,'boot_resources_unchanged':True}


def boot_write(kernels,check,module_trial):
    generation='fdn-boot-write';limited=False
    limits=resource.getrlimit(resource.RLIMIT_FSIZE);handler=signal.getsignal(signal.SIGXFSZ)
    real_boot_files=native.boot_files
    def limit_after_verification(stage,versions):
        nonlocal limited
        records=real_boot_files(stage,versions)
        # Run every real hook and initrd verification first. Limiting earlier also
        # constrains lsinitcpio's extraction child and misses the ESP-copy boundary.
        if (native.STATE/(generation+'-transaction-complete.json')).exists() and not limited:
            signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE,(8*1024**2,limits[1]));limited=True
        return records
    try:
        native.boot_files=limit_after_verification
        try:native.run_update('/etc/pacman-foundation.conf',generation,{'linux':kernels['NEW_REGULAR'],'linux-lts':kernels['NEW_LTS']},Path('/proc/cmdline').read_text().strip())
        except OSError as exc:check(exc.errno==errno.EFBIG,'not the injected mid-file write failure')
        else:raise AssertionError('boot write limit was not exercised')
    finally:
        native.boot_files=real_boot_files
        resource.setrlimit(resource.RLIMIT_FSIZE,limits);signal.signal(signal.SIGXFSZ,handler)
    failed=Path('/boot/enzimos/generations')/generation
    check(limited and (failed/'FAILED').exists() and not (failed/'READY.json').exists() and not (failed/'PUBLISHED.json').exists(),'partial boot files became a ready generation')
    check(any(p.name.endswith('.partial') and p.stat().st_size>0 for p in failed.iterdir()),'no partially written boot artifact observed')
    check('old-'+generation in Path('/boot/loader/loader.conf').read_text(),'coherent fallback was not retained')
    module_trial()
    native.repair_publication(generation)
    check((failed/'PUBLISHED.json').exists(),'verified publication retry failed')
    (CONTROL/'updated-generation').write_text(generation);(CONTROL/'boot-step').write_text('0')
    return {'mid_file_efbig':True,'partial_unselected':True,'old_fallback_retained':True,'verified_new_publication_repaired':True}
