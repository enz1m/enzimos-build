#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only Snapper dataset/lineage/read-only binding, no restic payload transfer."""
from pathlib import Path
import backup
import native


def qualify(check):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-39','wrong source-binding candidate')
    before=native.output(['pacman','-Q']);authority=native.authority_identity();seen=[]
    def refuse(action,fragment):
        try:action()
        except native.Failure as exc:check(fragment in str(exc),'wrong source refusal: '+str(exc))
        else:raise AssertionError('unsafe backup source accepted')
    with native.operation_lock(),backup.package_capture_lock():
        for name,path in (('root','/'),('home','/home')):
            source=backup.source_binding(name,path)
            number=native.snap(name,description='source identity fixture',cleanup='')
            snapshot=Path(path)/'.snapshots'/str(number)/'snapshot'
            identity=backup.snapshot_binding(name,path,number,source)
            seen.append(identity['uuid'])
            native.run(['btrfs','property','set','-ts',snapshot,'ro','false'])
            try:refuse(lambda:backup.snapshot_binding(name,path,number,source,identity),'read-only')
            finally:native.run(['btrfs','property','set','-ts',snapshot,'ro','true'])
            config=Path('/etc/snapper/configs')/name;body=config.read_bytes()
            config.write_bytes(body.replace(('SUBVOLUME="'+path+'"').encode(),b'SUBVOLUME="/different"'))
            try:refuse(lambda:backup.snapshot_binding(name,path,number,source,identity),'configuration/source mismatch')
            finally:config.write_bytes(body)
            refuse(lambda:backup.snapshot_binding(name,path,number,source,dict(identity,id=identity['id']+1)),'identity changed')
            check(backup.snapshot_binding(name,path,number,source,identity)==identity,'restored checks differ')
            # Cleanup only the exact fixture snapshot after checking binding again.
            native.run(['snapper','--no-dbus','-c',name,'delete',str(number)])
    check(len(set(seen))==2,'root/home snapshots not independent')
    check(native.output(['pacman','-Q'])==before and native.authority_identity()==authority,'source checks changed packages/authority')
    return {'root_home_exact_lineage':True,'writable_snapshot_refused':True,'config_mismatch_refused':True,
            'replacement_identity_refused':True,'packages_authority_preserved':True,'full_backup_requalified':False}
