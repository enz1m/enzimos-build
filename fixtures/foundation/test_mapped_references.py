#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only closed-FD mmap and io_uring registered-file protection controls."""
import ctypes
import mmap
import os
from pathlib import Path

import boot_inventory as boot
import native


def register_file(descriptor):
    # Linux x86_64 io_uring_params is120 bytes; zero flags request ordinary ring.
    # No KDF/MAC/seccomp/sysctl is changed to get a pass if the kernel refuses.
    if os.uname().machine!='x86_64':raise AssertionError('unqualified test syscall ABI')
    library=ctypes.CDLL('libc.so.6',use_errno=True);call=library.syscall;call.restype=ctypes.c_long
    parameters=ctypes.create_string_buffer(120)
    ring=call(ctypes.c_long(425),ctypes.c_uint(2),ctypes.byref(parameters))
    if ring<0:raise OSError(ctypes.get_errno(),'guest io_uring_setup refused')
    files=(ctypes.c_int*1)(descriptor)
    try:
        if call(ctypes.c_long(427),ctypes.c_int(ring),ctypes.c_uint(2),ctypes.byref(files),ctypes.c_uint(1))<0:
            raise OSError(ctypes.get_errno(),'guest io_uring_register refused')
        return int(ring)
    except BaseException:os.close(ring);raise


def qualify(check):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-40','wrong mapped reference candidate')
    inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
    top=Path('/run/enzimos/mapping-top');top.mkdir(mode=0o700)
    fs=native.output(['findmnt','-n','-o','UUID','/'])
    native.run(['mount','-t','btrfs','-o','subvolid=5,nodiscard','UUID='+fs,top])
    sub=top/'fdn-mapping-reference';native.run(['btrfs','subvolume','create',sub])
    (sub/'mapped').write_bytes(b'MAPPING-MUST-SURVIVE'+b'\0'*4096)
    (sub/'registered').write_bytes(b'KERNEL-REGISTERED-FILE\n')
    alias=Path('/run/enzimos/mapping-alias');alias.mkdir(mode=0o700)
    native.run(['mount','--bind',sub,alias]);native.run(['mount','--make-private',alias])
    mapping=None;ring=None
    try:
        fd=os.open(alias/'mapped',os.O_RDONLY)
        try:mapping=mmap.mmap(fd,4096,access=mmap.ACCESS_READ,trackfd=False)
        finally:os.close(fd)
        fd=os.open(alias/'registered',os.O_RDONLY)
        try:ring=register_file(fd)
        finally:os.close(fd)
        info=Path('/proc/self/fdinfo')/str(ring)
        check('UserFiles:\t1' in info.read_text(),'io_uring registered-file fixture missing')
        native.run(['umount','--lazy',alias])
        check(mapping[:20]==b'MAPPING-MUST-SURVIVE','mapping unavailable after close/detach')
        result=boot.process_references();own=[row for row in result['references'] if row['pid']==os.getpid()]
        check(any(row.get('origin')=='mapping' and row['kind']=='btrfs-handle' and row['mount'] is None for row in own),'closed-FD detached mapping lost')
        check(any(row['handle']=='fd:'+str(ring) and row['kind']=='kernel-object' and row['classification']=='io-uring-registered-files-needs-review' for row in own),'io_uring kernel object ignored')
        check('detached-or-foreign-Btrfs-handle' in result['blockers'] and 'io-uring-registered-files-needs-review' in result['blockers'],'kernel/mapping reference blockers missing')
        observation=boot.collect()
        check('io-uring-registered-files-needs-review' in observation['blockers'] and not observation['execution_available'],'outer collector granted unsafe retirement')
    finally:
        if mapping is not None:mapping.close()
        if ring is not None:os.close(ring)
        # Test-owned subvolume remains; no retirement functionality is exercised.
        native.run(['umount',top])
    check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'reference controls changed packages/authority')
    return {'closed_fd_detached_mapping_observed':True,'real_io_uring_file_registered':True,
            'kernel_object_blocks_retirement':True,'outer_collector_blocks':True,'packages_authority_preserved':True,
            'complete':False,'retirement_enabled':False}
