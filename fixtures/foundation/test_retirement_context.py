#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Recovery guest controls for kernel-held filesystem claims; no generation deletion."""
import mmap
import os
import re
from pathlib import Path
import time

import native
import retirement_context as context
from test_mapped_references import register_file


def prepare(check):
    marker=Path('/home/enzimos-admin/foundation-home-marker')
    check(not marker.exists(),'fresh context fixture marker required')
    marker.write_text('PRESERVE-HOME-THROUGH-KERNEL-CLAIM-TEST\n');os.chown(marker,1000,1000)
    entry=Path('/boot/loader/entries/recovery.conf');check(entry.is_file(),'recovery entry missing')
    config=Path('/boot/limine/limine.conf');text=config.read_text();_,entries,_=native.limine_menu(text)
    matches=[i for i,row in enumerate(entries,1) if 'path: boot():/enzimos-recovery/kernel' in row['text']]
    check(len(matches)==1,'independent BIOS recovery entry ambiguous')
    Path('/boot/loader/loader.conf').write_text('default recovery.conf\ntimeout 0\neditor no\n')
    config.write_text(re.sub(r'^default_entry: .*$', 'default_entry: '+str(matches[0]),text,flags=re.M))
    os.sync();return {'independent_recovery_selected':True,'root_unchanged':True}


def qualify(check):
    device=Path(os.path.realpath('/dev/mapper/lab-root-crypt'))
    top=Path('/mnt');file=top/'fdn-root/usr/lib/systemd/systemd'
    def busy():
        try:
            with context.exclusive_device(device):pass
        except native.Failure as exc:check('still held by kernel' in str(exc),'wrong exclusive claim refusal: '+str(exc))
        else:raise AssertionError('live filesystem received exclusive claim')
    busy()
    fd=os.open(file,os.O_RDONLY)
    mapping=None;ring=None;remounted=False
    try:
        mapping=mmap.mmap(fd,4096,access=mmap.ACCESS_READ,trackfd=False)
        ring=register_file(fd)
    finally:os.close(fd)
    try:
        native.run(['umount','/etc/pacman.d/gnupg']);native.run(['umount','/var/lib/enzimos-control'])
        native.run(['umount','--lazy',top])
        check(mapping[:4]==b'\x7fELF','closed-FD detached mapping unavailable')
        busy();mapping.close();mapping=None
        # Only the registered kernel file remains; no source FD or mmap.
        busy();os.close(ring);ring=None
        deadline=time.monotonic()+10
        while True:
            try:
                with context.exclusive_device(device) as claimed:
                    check(claimed['kernel_exclusive_claim_held'] and not claimed['deletion_authorized'],'claim grants deletion')
                break
            except native.Failure as exc:
                if 'still held by kernel' not in str(exc) or time.monotonic()>deadline:raise
                time.sleep(0.05)
        native.run(['mount','-t','btrfs','-o','subvolid=5,nodiscard',device,top]);remounted=True
    finally:
        if mapping is not None:mapping.close()
        if ring is not None:os.close(ring)
        if not remounted:native.run(['mount','-t','btrfs','-o','subvolid=5,nodiscard',device,top])
        native.run(['mount','--bind','/mnt/fdn-control','/var/lib/enzimos-control'])
        native.run(['mount','--bind','/mnt/fdn-authority','/etc/pacman.d/gnupg'])
    busy()
    return {'mounted_claim_refused':True,'detached_mapping_claim_refused':True,
            'registered_file_only_claim_refused':True,'released_filesystem_claim_succeeded':True,
            'remount_claim_refused':True,'deletion_authorized':False,'retirement_enabled':False}
