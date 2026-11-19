#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real Snapper/restic cases against public disposable guest data."""
import errno
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import backup
import native
from native import run,output,sha,Failure

CONTROL=Path('/var/lib/enzimos-control')
DATA=Path('/var/lib/enzimos-fidelity')
CHECK=None


def metadata(path):
    p=Path(path);s=p.stat()
    return {'uid':s.st_uid,'gid':s.st_gid,'mode':s.st_mode & 0o7777,'sha256':sha(p),
            'acl':output(['getfacl','-cp',p]),'xattrs':output(['getfattr','--absolute-names','-d','-m','-', '--encoding=hex',p]).splitlines()[1:]}


def prepare_data():
    if not os.path.ismount('/backup-repository'):run(['mount','/backup-repository'])
    DATA.mkdir(exist_ok=True)
    (DATA/'owned.txt').write_text('ENZIMOS-BACKED-CONTENT-7dce98f\n')
    run(['chown','1000:1001',DATA/'owned.txt']);run(['chmod','0640',DATA/'owned.txt'])
    run(['setfacl','-m','u:1001:r',DATA/'owned.txt']);run(['setfattr','-n','user.enzimos','-v','fidelity-marker',DATA/'owned.txt'])
    shutil.copyfile('/usr/bin/true',DATA/'capability');(DATA/'capability').chmod(0o755)
    run(['setcap','cap_net_bind_service=ep',DATA/'capability'])
    os.link(DATA/'owned.txt',DATA/'hardlink');(DATA/'symlink').symlink_to('owned.txt')
    home=Path('/home/enzimos-admin/.var/app/org.enzimos.Fixture');home.mkdir(parents=True,exist_ok=True)
    (home/'hidden-data').write_text('hidden-home-in-backup\n');run(['chown','-R','1000:1000','/home/enzimos-admin/.var'])
    flatpak=Path('/var/lib/flatpak');flatpak.mkdir(exist_ok=True);(flatpak/'enzimos-fixture-data').write_text('representative-system-flatpak-path-not-an-installed-flatpak\n')
    cache=Path('/var/cache/pacman/pkg');cache.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(CONTROL/'native-policy.pkg.tar.zst',cache/'enzimos-local-policy.pkg.tar.zst')
    shutil.copyfile(CONTROL/'native-policy.pkg.tar.zst.sig',cache/'enzimos-local-policy.pkg.tar.zst.sig')
    extra=Path('/var/lib/enzimos-persistent');run(['btrfs','subvolume','create',extra])
    (extra/'nested-data').write_text('separately-snapshotted-nested-data\n')
    run(['snapper','--no-dbus','-c','appdata','create-config',extra])
    config=Path('/etc/enzimos/backup.json');c=json.loads(config.read_text());c['additional_sources']=[{'path':str(extra),'snapper_config':'appdata'}];config.write_text(json.dumps(c,indent=2)+'\n')
    swap=Path('/swap');run(['btrfs','subvolume','create',swap])
    run(['btrfs','filesystem','mkswapfile','--size','64M',swap/'swapfile'])
    (swap/'inactive-sleep-marker').write_text('NEVER-IN-BACKUP-SLEEP-IMAGE\n')
    Path('/var/tmp/enzimos-excluded-marker').write_text('NEVER-IN-BACKUP-TRANSIENT\n')
    Path('/home/enzimos-admin/foundation-home-marker').write_text('home-at-backup\n')
    run(['chown','1000:1000','/home/enzimos-admin/foundation-home-marker'])
    expected={'owned':metadata(DATA/'owned.txt'),'capability':metadata(DATA/'capability'),'inventory':output(['pacman','-Q']),
              'local_package_sha256':sha(cache/'enzimos-local-policy.pkg.tar.zst'),'authority_sha256':sha('/etc/pacman.d/gnupg/pubring.gpg')}
    (CONTROL/'backup-expected.json').write_text(json.dumps(expected,indent=2)+'\n')
    return {'real_local_package_cached':True,'representative_flatpak_paths_not_runtime_proof':True,'nested_dataset':str(extra),'inactive_real_swapfile':True}


def home_history():
    file=Path('/home/enzimos-admin/foundation-home-marker')
    before=backup.history()['snapshot'];file.write_text('newer-home-after-history\n')
    CHECK((Path('/home/.snapshots')/str(before)/'snapshot/enzimos-admin/foundation-home-marker').read_text()=='home-at-backup\n','independent home snapshot changed')
    disabled=CONTROL/'home-history.disabled';disabled.touch()
    try:CHECK(backup.history(True)['status']=='disabled-no-source-scan','disabled history scanned')
    finally:disabled.unlink()
    return {'snapper_home_snapshot':before,'independent':True,'pause_respected':True}


def create_backup():
    c=backup.read_config()
    if not Path(c['repository'],'config').exists():backup.initialize()
    result=backup.backup();identifier=result['snapshot_id'];(CONTROL/'backup-snapshot').write_text(identifier)
    backup.restic(c,['check','--read-data'])
    wrong=dict(os.environ,RESTIC_PASSWORD='DELIBERATELY-WRONG',RESTIC_REPOSITORY=c['repository'])
    wrong.pop('RESTIC_PASSWORD_FILE',None)
    rejected=subprocess.run(['restic','--no-cache','snapshots'],capture_output=True,text=True,env=wrong)
    CHECK(rejected.returncode!=0,'wrong restic password accepted')
    CHECK(not (CONTROL/'backup.enabled').exists(),'manual backup enabled future jobs')
    return {'snapshot':identifier,'encrypted_repository_checked':True,'wrong_password_rejected':True,'full_linux_file_backup':True}


def restore_fidelity():
    authority_before=native.authority_identity()
    identifier=(CONTROL/'backup-snapshot').read_text().strip()
    root=Path('/restore-target');root.mkdir(exist_ok=True)
    top=Path('/run/enzimos/restore-top');top.mkdir(parents=True,exist_ok=True)
    uuid=output(['findmnt','-n','-o','UUID','/'])
    run(['mount','-t','btrfs','-o','subvolid=5,nodiscard','UUID='+uuid,top])
    run(['btrfs','subvolume','create',top/'fdn-fidelity-restore'])
    run(['mount','-t','btrfs','-o','subvol=fdn-fidelity-restore,nodiscard','UUID='+uuid,root])
    try:
        import root_ownership
        import backup_destination
        target_uuid=root_ownership.observe(root,'fdn-fidelity-restore',uuid)['uuid']
        def refuse(action, fragment):
            try:action()
            except Failure as exc:CHECK(fragment in str(exc),'wrong restore guard refusal: '+str(exc))
            else:raise AssertionError('unsafe restore stage accepted')
        refuse(lambda:backup.restore_system(identifier,target_uuid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),'identity differs')
        CHECK(not any(root.iterdir()),'wrong-identity refusal wrote destination')
        sentinel=root/'partial';sentinel.write_text('partial restore requires review')
        refuse(lambda:backup.restore_system(identifier,target_uuid=target_uuid),'partial stages never replay')
        CHECK(sentinel.read_text()=='partial restore requires review','partial stage altered');sentinel.unlink()
        nested=root/'nested';nested.mkdir()
        run(['mount','-t','tmpfs','-o','size=1m,mode=0700','tmpfs',nested])
        try:refuse(lambda:backup.restore_system(identifier,target_uuid=target_uuid),'nested backup destination mount')
        finally:run(['umount',nested]);nested.rmdir()
        c=backup.read_config();bound=backup_destination.restore_target(c,target_uuid)
        run(['umount',root]);run(['mount','-t','btrfs','-o','subvol=fdn-fidelity-restore,nodiscard','UUID='+uuid,root])
        refuse(lambda:backup_destination.restore_target(c,target_uuid,bound),'changed during operation')
        backup.restore_system(identifier,target_uuid=target_uuid)
        restored=root/'backup-source/system';e=json.loads((CONTROL/'backup-expected.json').read_text())
        CHECK(not (restored/'etc/enzimos/backup.password').exists() and not (restored/'etc/enzimos/backup.json').exists(),'backup access material replayed')
        for key,name in [('owned','owned.txt'),('capability','capability')]:
            got=metadata(restored/'var/lib/enzimos-fidelity'/name)
            CHECK(got==e[key],'restored metadata differs: '+key)
        a=restored/'var/lib/enzimos-fidelity/owned.txt';b=a.with_name('hardlink')
        CHECK(a.stat().st_ino==b.stat().st_ino,'hardlink identity not restored')
        CHECK(os.readlink(a.with_name('symlink'))=='owned.txt','symlink not restored')
        CHECK(output(['pacman','--root',restored,'-Q'])==e['inventory'],'restored package database mismatch')
        CHECK(sha(restored/'var/cache/pacman/pkg/enzimos-local-policy.pkg.tar.zst')==e['local_package_sha256'],'real local package archive missing')
        CHECK((root/'backup-source/additional/appdata/nested-data').read_text()=='separately-snapshotted-nested-data\n','nested dataset was omitted')
        CHECK(not (root/'backup-source/home').exists(),'system restore unexpectedly restored home')
        CHECK(native.authority_identity()==authority_before,'live authority changed during staged restore')
    finally:
        run(['umount',root]);run(['btrfs','subvolume','delete',top/'fdn-fidelity-restore']);run(['umount',top])
    return {'owners_modes_acl_xattr_capabilities':True,'hardlinks_symlinks':True,'package_database_and_cached_local_package':True,'nested_dataset':True,'home_not_overwritten':True,
            'wrong_target_uuid_refused':True,'partial_stage_preserved':True,'nested_mount_refused':True,'mount_replacement_refused':True,'backup_access_not_restored':True}


def exclusions():
    c=backup.read_config();identifier=(CONTROL/'backup-snapshot').read_text().strip()
    listing=backup.restic(c,['ls','--json',identifier],capture=True).stdout
    (CONTROL/'backup-listing.jsonl').write_text(listing)
    paths=[]
    for line in listing.splitlines():
        row=json.loads(line)
        if row.get('type') in ('file','dir','symlink') and 'path' in row:paths.append(row['path'])
    for p in ('/backup-source/system/swap/swapfile','/backup-source/system/swap/inactive-sleep-marker','/backup-source/system/var/tmp/enzimos-excluded-marker','/backup-source/system/etc/pacman.d/gnupg/pubring.gpg','/backup-source/system/etc/enzimos/backup.password','/backup-source/system/etc/enzimos/backup.json'):
        CHECK(p not in paths,'excluded content present: '+p)
    CHECK(not any('/.snapshots/' in p for p in paths),'recursive snapshot history included')
    CHECK(not any(p.startswith('/backup-source/system/backup-repository/') for p in paths),'destination recursively included')
    CHECK('/backup-source/home/enzimos-admin/.var/app/org.enzimos.Fixture/hidden-data' in paths,'hidden home data omitted')
    CHECK('/backup-source/system/var/lib/flatpak/enzimos-fixture-data' in paths,'representative system Flatpak path omitted')
    return {'inactive_swap_sleep_transient_authority_excluded':True,'recursive_snapshots_destinations_excluded':True,'hidden_data_included':True,'backup_access_excluded':True}


def space_and_retention():
    c=backup.read_config();before={x['id'] for x in backup.snapshots(c)}
    # Real preflight failure without changing the repository, source or active backups.
    cfg=Path('/etc/enzimos/backup.json');saved=cfg.read_text();changed=dict(c,minimum_free_bytes=shutil.disk_usage('/backup-repository').free+1)
    cfg.write_text(json.dumps(changed)+'\n')
    try:
        try:backup.backup()
        except Failure as exc:CHECK('space admission' in str(exc),'unexpected space failure')
        else:raise AssertionError('space admission unexpectedly succeeded')
    finally:cfg.write_text(saved)
    CHECK({x['id'] for x in backup.snapshots(c)}==before,'space admission deleted prior backups')
    # Unknown nested subvolumes must fail, not quietly become an inventory-only omission.
    unknown=Path('/var/lib/enzimos-unaccounted');run(['btrfs','subvolume','create',unknown])
    try:
        try:backup.backup()
        except Failure as exc:CHECK('unconfigured nested' in str(exc),'wrong unconfigured-source failure')
        else:raise AssertionError('unconfigured nested data silently omitted')
    finally:run(['btrfs','subvolume','delete',unknown])
    # Inject a competing destination writer AFTER the real admission check. No
    # production guard is disabled. Logical zero-filled guest blocks still consume
    # Btrfs space; QEMU zero detection only avoids redundant host allocations.
    filler=Path('/backup-repository/enzimos-space-fixture')
    entropy=Path('/home/enzimos-admin/enzimos-entropy-fixture')
    with entropy.open('wb') as stream:
        for _ in range(128):stream.write(os.urandom(1024**2))
    real_layout=backup.source_layout
    def fill_after_admission(configuration):
        sources=real_layout(configuration)
        with filler.open('wb',buffering=0) as stream:
            block=b'\0'*(1024**2)
            try:
                for _ in range(2048):stream.write(block)
            except OSError as exc:
                if exc.errno!=errno.ENOSPC:raise
            stream.truncate(max(0,os.fstat(stream.fileno()).st_size-16*1024**2));os.fsync(stream.fileno())
        os.sync()
        return sources
    failure=''
    try:
        backup.source_layout=fill_after_admission
        try:backup.backup()
        except subprocess.CalledProcessError as exc:
            failure=exc.stderr or ''
            CHECK('no space left on device' in failure.lower(),'not a genuine destination ENOSPC failure: '+failure)
        else:raise AssertionError('insufficient real repository space unexpectedly succeeded')
        CHECK({x['id'] for x in backup.snapshots(c)}==before,'failed backup changed completed snapshot set')
    finally:
        backup.source_layout=real_layout
        filler.unlink(missing_ok=True);entropy.unlink(missing_ok=True);os.sync()
        run(['fstrim','/backup-repository'])
    backup.restic(c,['check','--read-data'])
    for i in range(3):
        Path('/home/enzimos-admin/retention-marker').write_text(str(i))
        backup.backup()
    cfg.write_text(json.dumps(dict(c,keep_last=2))+'\n')
    try:backup.retain()
    finally:cfg.write_text(saved)
    CHECK(len(backup.snapshots(c))==2,'restic retention did not preserve exactly two latest tagged snapshots')
    run(['snapper','--no-dbus','-c','root','set-config','NUMBER_LIMIT=2','NUMBER_LIMIT_IMPORTANT=2','NUMBER_MIN_AGE=0'])
    for i in range(5):native.snap('root',description='retention fixture '+str(i))
    run(['snapper','--no-dbus','-c','root','cleanup','number'])
    listing=output(['snapper','--no-dbus','-c','root','--csvout','list','--columns','number,cleanup'])
    CHECK(sum(1 for line in listing.splitlines() if 'number' in line)<=4,'Snapper number retention was unbounded')
    return {'preflight_failed_without_deleting_backups':True,'runtime_space_failure':failure,'unknown_nested_source_rejected':True,'restic_keep_last':2,'snapper_cleanup_exercised':True}


def break_root():
    c=backup.read_config();shots=backup.snapshots(c)
    # Select the latest COMPLETE backup; the backup job never enables future workers.
    selected=max(shots,key=lambda s:s['time'])['id'];(CONTROL/'backup-snapshot').write_text(selected)
    Path('/home/enzimos-admin/foundation-home-marker').write_text('NEWER-HOME-MUST-SURVIVE-ROOT-RESTORE\n')
    (CONTROL/'authority-epoch').write_text('CURRENT-AUTHORITY-AFTER-BACKUP\n')
    (CONTROL/'authority-current.sha256').write_text(sha('/etc/pacman.d/gnupg/pubring.gpg'))
    (CONTROL/'restore-source.json').write_text(json.dumps({'snapshot':selected,'root_uuid':output(['findmnt','-n','-o','UUID','/']),
        'backup_uuid':c['destination_uuid'],'inventory':output(['pacman','-Q'])},indent=2)+'\n')
    # Explicit recovery selection, independent of any executable in the main root.
    Path('/boot/loader/loader.conf').write_text('default recovery.conf\ntimeout 0\neditor no\n')
    limine=Path('/boot/limine/limine.conf');limine.write_text(__import__('re').sub(r'^default_entry: .*$', 'default_entry: 3',limine.read_text(),flags=__import__('re').M))
    top=Path('/run/enzimos/broken-root-top');top.mkdir(parents=True,exist_ok=True)
    run(['mount','-t','btrfs','-o','subvolid=5,nodiscard','UUID='+output(['findmnt','-n','-o','UUID','/']),top])
    try:
        CHECK((top/'fdn-root').is_dir() and not (top/'fdn-unusable').exists(),'unexpected root layout')
        (top/'fdn-root').rename(top/'fdn-unusable')
        CHECK(not (top/'fdn-root').exists(),'main boot subvolume still usable')
    finally:run(['umount',top])
    os.sync()
    return {'main_boot_subvolume_absent':True,'recovery_selected':True,'snapshot':selected,'automatic_fallback_tested':False}


def run_group(selection,case,check):
    global CHECK
    CHECK=check
    if not os.path.ismount('/backup-repository'):run(['mount','/backup-repository'])
    if selection=='backup-create':
        case('R-fixture',prepare_data);case('R1-home',home_history);case('R2',create_backup)
    elif selection=='backup-recapture':
        expected=CONTROL/'backup-expected.json';data=json.loads(expected.read_text());data['inventory']=output(['pacman','-Q'])
        expected.write_text(json.dumps(data,indent=2)+'\n')
        case('R2',create_backup)
    elif selection=='backup-legacy-fidelity':case('R3',restore_fidelity)
    elif selection=='backup-fidelity':case('R3',restore_fidelity);case('R5-exclusions',exclusions)
    elif selection=='backup-retention':case('R5-space-retention',space_and_retention)
    elif selection=='backup-break':case('R4-broken-root',break_root)
    else:raise ValueError('unknown backup group')
