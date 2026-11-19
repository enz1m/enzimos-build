#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only lazy-detached Btrfs FD and held namespace detection; no deletion."""
import os
from pathlib import Path

import boot_inventory as boot
import native


def qualify(check):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-38','wrong process-reference candidate')
    inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
    top=Path('/run/enzimos/process-reference-top');top.mkdir(mode=0o700)
    uuid=native.output(['findmnt','-n','-o','UUID','/'])
    native.run(['mount','-t','btrfs','-o','subvolid=5,nodiscard','UUID='+uuid,top])
    path=top/'fdn-process-reference';native.run(['btrfs','subvolume','create',path])
    (path/'held-file').write_text('retained process reference\n')
    alias=Path('/run/enzimos/process-reference-alias');alias.mkdir(mode=0o700)
    native.run(['mount','--bind',path,alias]);native.run(['mount','--make-private',alias])
    fd=os.open(alias/'held-file',os.O_RDONLY);namespace=os.open('/proc/self/ns/mnt',os.O_RDONLY)
    try:
        native.run(['umount','--lazy',alias])
        check(os.read(fd,100)==b'retained process reference\n','detached descriptor lost original content')
        result=boot.process_references();own=[row for row in result['references'] if row['pid']==os.getpid()]
        check(any(row['handle']=='fd:'+str(fd) and row['kind']=='btrfs-handle' and row['mount'] is None for row in own),'detached Btrfs handle omitted')
        check(any(row['handle']=='fd:'+str(namespace) and row['kind']=='namespace-handle' for row in own),'held namespace omitted')
        check('detached-or-foreign-Btrfs-handle' in result['blockers'] and 'process-held-namespace-needs-review' in result['blockers'],'handle blockers missing')
        collected=boot.collect()
        check(collected['process_references']['references'] and 'detached-or-foreign-Btrfs-handle' in collected['blockers'],'outer collector lost handle blocker')
        check(not collected['complete'] and not collected['execution_available'],'handle sampling became deletion permission')
    finally:
        os.close(fd);os.close(namespace)
        # Retain the created subvolume, not an implicit retirement operation.
        native.run(['umount',top])
    check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'process inspection changed packages/authority')
    return {'detached_btrfs_fd_observed':True,'held_namespace_observed':True,'outer_collector_blocks':True,
            'packages_authority_preserved':True,'resource_retained':True,'complete':False,'retirement_enabled':False}
