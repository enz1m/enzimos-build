#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Self-contained guest-RAM diagnosis/recovery; never borrow installed executables."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import traceback
sys.path.insert(0,'/usr/lib/enzimos')
import native
import backup
from native import run,output,sha,atomic_json,atomic_text,root_options

CONTROL=Path('/var/lib/enzimos-control')
TARGET='/dev/disk/by-id/virtio-enzimos-lab-target'


def check(value,message):
    if not value:raise AssertionError(message)

def credential(prompt,path):
    value=output(['systemd-ask-password',prompt])
    Path(path).write_text(value);Path(path).chmod(0o600)

def header_hash():
    p=Path('/run/foundation-header.backup');p.unlink(missing_ok=True)
    run(['cryptsetup','luksHeaderBackup',TARGET+'-part3','--header-backup-file',p])
    result=sha(p);p.unlink();return result

def inventory(root):
    return output(['pacman','--root',root,'--config','/etc/enzimos/pacman-query.conf','-Q'])

def kernel_map(root):
    result={}
    for flavor in ('linux','linux-lts'):
        files=output(['pacman','--root',root,'--config','/etc/enzimos/pacman-query.conf','-Qlq',flavor]).splitlines()
        names=[re.search(r'/usr/lib/modules/([^/]+)/vmlinuz$',p) for p in files]
        names=[m[1] for m in names if m]
        check(len(names)==1,'ambiguous restored kernel package')
        result[flavor]=names[0]
    return result

def normalize_root(root,name):
    fstab=root/'etc/fstab';lines=[]
    for line in fstab.read_text().splitlines():
        parts=line.split()
        if parts and not parts[0].startswith('#') and len(parts)>=4 and parts[1]=='/':
            parts[3]=','.join([v for v in parts[3].split(',') if not v.startswith(('subvol=','subvolid='))]+['subvol='+name]);line=' '.join(parts)
        lines.append(line)
    atomic_text(fstab,'\n'.join(lines)+'\n')
    c=json.loads((root/'etc/enzimos/storage.json').read_text());c['root_subvol']=name
    check(c['filesystem_uuid']==output(['blkid','-s','UUID','-o','value','/dev/mapper/lab-root-crypt']),'do not replay stale filesystem identities')
    atomic_json(root/'etc/enzimos/storage.json',c)
    history=root/'.snapshots'
    if history.exists():
        check(not any(history.iterdir()),'unexpected restored recursive snapshots');history.rmdir()
    run(['btrfs','subvolume','create',history]);history.chmod(0o750)


def publish_restored(root,boot_source,name):
    kernels=kernel_map(root)
    folder=Path('/boot/enzimos/recovered')/name;folder.mkdir(parents=True,exist_ok=False)
    for flavor,version in kernels.items():
        kernel=boot_source/('vmlinuz-'+flavor);image=boot_source/('initramfs-'+flavor+'.img')
        check(sha(kernel)==sha(root/'usr/lib/modules'/version/'vmlinuz'),'restored root/kernel mismatch')
        listing=output(['lsinitcpio','--nocolor','--list',image])
        versions=set(re.findall(r'^(?:\./)?usr/lib/modules/([^/\n]+)/',listing,re.M))
        check(versions=={version},'restored initrd/module mismatch')
        shutil.copyfile(kernel,folder/kernel.name);shutil.copyfile(image,folder/image.name)
        for p in (folder/kernel.name,folder/image.name):
            with p.open('rb') as f:os.fsync(f.fileno())
    source_entry=Path('/boot/loader/entries/linux.conf').read_text()
    options=next(line[8:] for line in source_entry.splitlines() if line.startswith('options '))
    options=root_options(options,name)
    limine=Path('/boot/limine/limine.conf');old=limine.read_text();first=sum(x.startswith('/') for x in old.splitlines())+1
    addition=''
    for flavor in kernels:
        prefix='/enzimos/recovered/'+name
        atomic_text(Path('/boot/loader/entries')/(name+'-'+flavor+'.conf'),f'title enzimOS recovered {flavor}\nlinux {prefix}/vmlinuz-{flavor}\ninitrd {prefix}/initramfs-{flavor}.img\noptions {options}\n')
        addition+=f'/enzimOS recovered {name} {flavor}\n    protocol: linux\n    path: boot():{prefix}/vmlinuz-{flavor}\n    module_path: boot():{prefix}/initramfs-{flavor}.img\n    cmdline: {options}\n'
    atomic_text(limine,re.sub(r'^default_entry: .*$',f'default_entry: {first}',old,flags=re.M)+'\n'+addition)
    atomic_text('/boot/loader/loader.conf',f'default {name}-linux.conf\ntimeout 0\neditor no\n')
    atomic_json(CONTROL/'restored-boot.json',{'root':name,'kernels':kernels,'bios_first':first,'uefi_ids':[name+'-'+f+'.conf' for f in kernels]})
    os.sync();return kernels


def restore_restic():
    source=json.loads((CONTROL/'restore-source.json').read_text())
    check(not Path('/mnt/fdn-root').exists(),'main root is unexpectedly usable')
    check(source['root_uuid']==output(['blkid','-s','UUID','-o','value','/dev/mapper/lab-root-crypt']),'owned restore target UUID changed')
    Path('/backup-repository').mkdir(exist_ok=True)
    run(['mount','-t','btrfs','-o','nodiscard','/dev/disk/by-id/virtio-enzimos-lab-backup','/backup-repository'])
    check(output(['findmnt','-n','-o','UUID','/backup-repository'])==source['backup_uuid'],'wrong backup disk')
    for parent in (Path('/'), Path('/etc'), Path('/etc/enzimos')):
        info = parent.lstat()
        print('ENZIMOS_RECOVERY_CREDENTIAL_PARENT '+json.dumps({'path': str(parent), 'uid': info.st_uid, 'mode': oct(info.st_mode)}), flush=True)
    credential('ENZIMOS backup passphrase:','/etc/enzimos/backup.password')
    atomic_json('/etc/enzimos/backup.json',{'repository':'/backup-repository/restic','destination_uuid':source['backup_uuid'],'password_file':'/etc/enzimos/backup.password'})
    # The fixture supplies explicit storage configuration from its authenticated
    # source record; the packaged guard independently checks the mounted control.
    atomic_json('/etc/enzimos/storage.json', {'filesystem_uuid': source['root_uuid'],
        'root_subvol': 'fdn-root', 'home_subvol': 'lab-home',
        'authority_subvol': 'fdn-authority', 'control_subvol': 'fdn-control'})
    Path('/restore-target').mkdir(exist_ok=True)
    stage=Path('/mnt/fdn-restic-stage');run(['btrfs','subvolume','create',stage])
    run(['mount','--bind',stage,'/restore-target'])
    run(['apparmor_parser','-r','/etc/apparmor.d/enzimos-restic'])
    try:
        import root_ownership
        target_uuid=root_ownership.observe(Path('/restore-target'),'fdn-restic-stage',source['root_uuid'])['uuid']
        backup.restore_system(source['snapshot'],target_uuid=target_uuid)
        staged=Path('/restore-target/backup-source/system/etc/enzimos')
        check(not (staged/'backup.password').exists() and not (staged/'backup.json').exists(),'recovery replayed backup access material')
        root=Path('/mnt/fdn-restored');run(['btrfs','subvolume','create',root])
        run(['cp','-a','--reflink=always','/restore-target/backup-source/system/.',root])
        check(inventory(root)==source['inventory'],'restic restored package state differs')
        scope=json.loads(Path('/restore-target/backup-source/inventory/scope.json').read_text())
        for config,path,slot in scope['sources']:
            if not slot.startswith('additional/'):continue
            destination=root/path.lstrip('/')
            if destination.exists():
                check(not any(destination.iterdir()),'nested placeholder unexpectedly populated');destination.rmdir()
            run(['btrfs','subvolume','create',destination]);run(['cp','-a','--reflink=always','/restore-target/backup-source/'+slot+'/.',destination])
            history=destination/'.snapshots'
            if history.exists():history.rmdir()
            run(['btrfs','subvolume','create',history]);history.chmod(0o750)
        normalize_root(root,'fdn-restored')
        kernels=publish_restored(root,Path('/restore-target/backup-source/boot'),'fdn-restored')
        return {'restored_root':'fdn-restored','snapshot':source['snapshot'],'kernels':kernels,'unusable_main_root':True,'restic_content_restore':True,'restore_target_uuid_bound':True,'backup_access_not_restored':True}
    finally:
        Path('/etc/enzimos/backup.password').unlink(missing_ok=True)
        run(['umount','/restore-target'])
        run(['btrfs','subvolume','delete',stage])


def restore_snapper():
    info=json.loads((CONTROL/'interrupted-update.json').read_text())
    old=info['fallback'];snapshot=Path('/mnt/fdn-root/.snapshots')/str(old['snapshot'])/'snapshot'
    check(output(['btrfs','property','get','-ts',snapshot,'ro'])=='ro=true','Snapper source is not read-only')
    target=Path('/mnt/fdn-snapper-restored');run(['btrfs','subvolume','snapshot',snapshot,target])
    check(inventory(target)==info['old_inventory'],'interrupted transaction snapshot state differs')
    normalize_root(target,'fdn-snapper-restored')
    kernels=publish_restored(target,Path('/boot/enzimos/generations')/old['generation'],'fdn-snapper-restored')
    return {'restored_root':'fdn-snapper-restored','snapper_source':old['snapshot'],'kernels':kernels}


def restore_packaged(selection):
    import recovery_stage
    source=json.loads((CONTROL/'packaged-recovery-source.json').read_text());identifier=source['id']
    journal=CONTROL/'recovery-jobs'/(identifier+'.json');job=json.loads(journal.read_text());plan=job['plan']
    check(not Path('/mnt/fdn-root/usr/lib/systemd/systemd').exists(),'main init is not broken')
    recovery_stage.TOP.mkdir(mode=0o700,parents=True,exist_ok=True)
    run(['mount','--bind','/mnt',recovery_stage.TOP])
    before=sha(journal);boot_before={str(p):sha(p) for p in Path('/boot').rglob('*') if p.is_file()}
    if selection=='recovery-packaged-pending':
        check(job['phase']=='root-recorded' and job['history'] is None,'interrupted staging boundary changed')
        try:recovery_stage.stage(identifier,source['plan_sha256'])
        except native.Failure as exc:check('no automatic replay' in str(exc),'wrong interrupted staging refusal')
        else:raise AssertionError('partial staging was automatically replayed')
        check(sha(journal)==before and all(sha(path)==value for path,value in boot_before.items()),'pending refusal changed journal/boot')
        check(output(['pacman','--root','/mnt/fdn-root','--config','/etc/enzimos/pacman-query.conf','-Q'])==source['current_inventory'],'pending recovery changed main packages')
        return {'pending_phase':job['phase'],'automatic_replay_refused':True,'journal_boot_unchanged':True,
                'main_packages_preserved':True,'retirement_enabled':False}
    if selection=='recovery-packaged-cut':
        def interrupt(phase,_):
            if phase!='root-recorded':return
            os.sync();print('ENZIMOS_RECOVERY_STAGE_CUT_READY root-recorded',flush=True)
            import time
            while True:time.sleep(1)
        recovery_stage.stage(identifier,source['plan_sha256'],interrupt)
        raise AssertionError('packaged recovery cut was not reached')
    # Stale previews and substituted source identity must refuse before any journal/root write.
    for digest in ('f'*64,):
        try:recovery_stage.stage(identifier,digest)
        except native.Failure as exc:check('stale recovery preview' in str(exc),'wrong stale preview refusal')
        else:raise AssertionError('stale recovery preview accepted')
    snapshot=Path('/mnt')/plan['source_birth']['snapshot']['object']['path']
    run(['btrfs','property','set','-ts',snapshot,'ro','false'])
    try:
        try:recovery_stage.stage(identifier,source['plan_sha256'])
        except native.Failure as exc:check('read-only' in str(exc),'wrong writable snapshot refusal')
        else:raise AssertionError('writable recovery source accepted')
    finally:run(['btrfs','property','set','-ts',snapshot,'ro','true'])
    check(sha(journal)==before and not (Path('/mnt')/plan['target_name']).exists(),'preflight refusal created root or changed plan')
    phases=[]
    result=recovery_stage.stage(identifier,source['plan_sha256'],lambda phase,_:phases.append(phase))
    staged=json.loads(journal.read_text())
    check(phases==['creating','root-recorded','staged'] and staged['phase']=='staged','packaged staging phases missing')
    check(all(sha(path)==value for path,value in boot_before.items()),'packaged staging changed boot files')
    check(output(['pacman','--root','/mnt/fdn-root','--config','/etc/enzimos/pacman-query.conf','-Q'])==source['current_inventory'],'failed main root packages changed')
    root=Path('/mnt')/plan['target_name']
    check((root/'usr/lib/systemd/systemd').is_file(),'staged root did not recover init')
    (CONTROL/'packaged-recovery-inventory.txt').write_text(inventory(root))
    # Only lab code publishes the staged root; the package explicitly offers no
    # activation/replay endpoint. Copy only the lab boot verifier, not new policy.
    verifier=Path('/usr/lib/enzimos-lab/foundation_test.py')
    shutil.copyfile(verifier,root/'usr/lib/enzimos-lab/foundation_test.py')
    shutil.copyfile('/usr/lib/enzimos-lab/test_recovery_stage.py',root/'usr/lib/enzimos-lab/test_recovery_stage.py')
    # The bounded ESP already retains these verified artifacts. Reuse them rather
    # than copying another kernel/initrd cohort or deleting a bootable generation.
    kernels=plan['material']['kernels'];name=plan['target_name']
    options=root_options(plan['material']['options'],name)
    options=' '.join(word for word in options.split() if not word.startswith('enzimos.generation='))
    limine=Path('/boot/limine/limine.conf');old=limine.read_text();header,entries,_=native.limine_menu(old);first=len(entries)+1
    addition='';prefix='/enzimos/generations/'+plan['generation']
    for flavor in kernels:
        atomic_text(Path('/boot/loader/entries')/(name+'-'+flavor+'.conf'),f'title enzimOS staged lab {flavor}\nlinux {prefix}/vmlinuz-{flavor}\ninitrd {prefix}/initramfs-{flavor}.img\noptions {options}\n')
        addition+=f'/enzimOS staged lab {name} {flavor}\n protocol: linux\n path: boot():{prefix}/vmlinuz-{flavor}\n module_path: boot():{prefix}/initramfs-{flavor}.img\n cmdline: {options}\n'
    atomic_text(limine,re.sub(r'^default_entry: .*$',f'default_entry: {first}',old,flags=re.M)+'\n'+addition)
    atomic_text('/boot/loader/loader.conf',f'default {name}-linux.conf\ntimeout 0\neditor no\n')
    atomic_json(CONTROL/'restored-boot.json',{'root':name,'kernels':kernels,'bios_first':first,'uefi_ids':[name+'-'+flavor+'.conf' for flavor in kernels]})
    return {'packaged_stage':result,'phases':phases,'stale_preview_refused':True,'writable_source_refused':True,
            'refusals_preserved_plan':True,'packaged_stage_preserved_boot':True,'broken_main_root_preserved':True,
            'main_package_inventory_preserved':True,'boot_activation':'lab-fixture-only','kernels':kernels}


def confirm_recovery_image():
    import recovery_image as image
    import recovery_stage
    source=json.loads((CONTROL/'image-test.json').read_text());identifier=source['id']
    recovery_stage.TOP.mkdir(mode=0o700,parents=True,exist_ok=True);run(['mount','--bind','/mnt',recovery_stage.TOP])
    record_path=image.directory()/(identifier+'.json');before=sha(record_path)
    print('ENZIMOS_RECOVERY_COMMAND_LINE '+json.dumps({'running':Path('/proc/cmdline').read_text().strip(),
          'published':image.records()[identifier]['options']}),flush=True)
    entry=Path('/boot/loader/entries')/(identifier+'.conf');text=entry.read_text()
    atomic_text(entry,text.replace('title ','title CHANGED ',1))
    try:
        try:image.confirm_current()
        except native.Failure as exc:check('UEFI entry drift' in str(exc),'wrong changed-entry refusal')
        else:raise AssertionError('changed entry confirmed')
        check(sha(record_path)==before,'changed-entry refusal modified record')
    finally:atomic_text(entry,text)
    embedded=image.EMBEDDED.read_bytes();identity=json.loads(embedded)
    key=next(iter(identity['policy_files']));identity['policy_files'][key]='f'*64
    import errno
    embedded_readonly=False
    try:image.EMBEDDED.write_text(json.dumps(identity))
    except OSError as exc:
        check(exc.errno==errno.EROFS and image.EMBEDDED.read_bytes()==embedded,'unexpected embedded identity write failure')
        embedded_readonly=True
    else:
        try:
            try:image.confirm_current()
            except native.Failure as exc:check('not publisher-recorded' in str(exc),'wrong embedded-descriptor refusal')
            else:raise AssertionError('changed embedded identity confirmed')
        finally:image.EMBEDDED.write_bytes(embedded)
    check(sha(record_path)==before,'changed-identity refusal modified record')
    result=image.confirm_current();first=image.records()[identifier]['observations'][result['mode']]['first']
    again=image.confirm_current()
    check(image.records()[identifier]['observations'][result['mode']]['first']==first and again['observation']==result['observation'],'first confirmation not preserved')
    check(inventory(Path('/mnt/fdn-root'))==source['inventory'] and native.authority_identity()==source['authority'],'confirmation changed installed packages/authority')
    check(sha('/boot/enzimos-recovery/initrd.img')==source['old_recovery_sha256'],'confirmation overwrote old recovery')
    return {'confirmation':result,'changed_entry_refused_without_record_write':True,'changed_descriptor_refused':True,
            'embedded_identity_readonly':embedded_readonly,'first_observation_preserved':True,'installed_packages_authority_unchanged':True,'old_recovery_preserved':True,
            'observed_modes':sorted(image.records()[identifier]['observations']),'retirement_enabled':False}


def diagnose():
    credential_record=CONTROL/'backup-credentials/receipt-interrupted.json'
    if credential_record.is_file():
        check(not credential_record.is_symlink() and credential_record.stat().st_size<16384,'credential diagnostic record bound')
        value=json.loads(credential_record.read_text());path=Path('/mnt/fdn-root/etc/enzimos/backup.next-password');info=path.lstat()
        observed={'device':info.st_dev,'inode':info.st_ino,'size':info.st_size,'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}
        print('ENZIMOS_DIAGNOSTIC_CREDENTIAL_IDENTITY '+json.dumps({'recorded':value['input_identity'],'readonly_observed':observed,
              'changed_fields':sorted(k for k in observed if k in value['input_identity'] and observed[k]!=value['input_identity'][k]),
              'root':output(['btrfs','subvolume','show','/mnt/fdn-root'])}),flush=True)
    if (CONTROL/'activation-source.json').exists():
        for name in ('lab-home', 'fdn-authority', 'fdn-control'):
            path=Path('/mnt')/name;info=path.lstat()
            print('ENZIMOS_ACTIVATION_PROTECTED_STAT '+json.dumps({'path':name,'uid':info.st_uid,'gid':info.st_gid,'mode':oct(info.st_mode),'symlink':path.is_symlink()}),flush=True)
    publication=CONTROL/'publication-cut.json'
    if publication.exists():
        source=json.loads(publication.read_text());Path('/boot').mkdir(exist_ok=True)
        run(['mount','-t','vfat','-o','ro',TARGET+'-part2','/boot'])
        changes=[{'path':name,'before':value,'after':sha(name) if Path(name).is_file() else None}
                 for name,value in source['boot_before'].items() if not Path(name).is_file() or sha(name)!=value]
        print('ENZIMOS_PUBLICATION_BOOT_DRIFT '+json.dumps(changes),flush=True)
    births=CONTROL/'root-births'
    if births.is_dir():
        records=sorted(births.iterdir());check(len(records)<=80,'birth diagnostic count bound')
        for path in records:
            check(path.is_file() and not path.is_symlink() and path.stat().st_size<=16384,'birth diagnostic file bound')
            print('ENZIMOS_DIAGNOSTIC_BIRTH '+path.name+' '+path.read_text(),flush=True)
            name=json.loads(path.read_text())['target_name']
            check(re.fullmatch(r'enzimos-old-[A-Za-z0-9._-]{1,70}',name),'invalid diagnostic birth path')
            for candidate in (Path('/mnt')/name,Path('/mnt')/name/'.snapshots'):
                if candidate.exists():
                    info=candidate.lstat()
                    print('ENZIMOS_DIAGNOSTIC_BIRTH_STAT '+json.dumps({'path':str(candidate),'inode':info.st_ino,'device':info.st_dev,'mode':oct(info.st_mode),'ismount_heuristic':os.path.ismount(candidate)}),flush=True)
        print('ENZIMOS_DIAGNOSTIC_MOUNT_TARGETS\n'+output(['findmnt','-r','-n','-o','TARGET']),flush=True)
        for switches in (['-u','-q'],['-a','-u','-q'],['-r','-u','-q'],['-a','-r','-u','-q']):
            print('ENZIMOS_DIAGNOSTIC_SUBVOLUMES '+repr(switches)+'\n'+output(['btrfs','subvolume','list',*switches,'/mnt/fdn-root']),flush=True)
    history=Path('/mnt/fdn-root/.snapshots')
    if history.is_dir():
        rows={p.parent.name:p.read_text() for p in sorted(history.glob('*/info.xml')) if p.stat().st_size<8192}
        print('ENZIMOS_DIAGNOSTIC_SNAPPER '+json.dumps(rows),flush=True)
    for file in ('var/log/pacman-foundation.log','var/lib/enzimos/fdn-success-pacman.log'):
        p=Path('/mnt/fdn-root')/file
        if p.exists():
            text=p.read_text(errors='replace')
            print('ENZIMOS_DIAGNOSTIC_FILE '+file+'\n'+text[-30000:],flush=True)
    extra=CONTROL/'defaults-tests'
    if extra.is_dir():
        for p in sorted(extra.iterdir())[:12]:
            if p.is_file() and p.suffix in ('.txt','.log'):
                print('ENZIMOS_DIAGNOSTIC_FILE '+str(p)+'\n'+p.read_text(errors='replace')[-16000:],flush=True)
    journal=Path('/mnt/fdn-root/var/log/journal')
    if journal.is_dir():
        result=subprocess.run(['journalctl','--directory',str(journal),'--no-pager','-n','120','-g','polkit|pam_|faillock'],capture_output=True,text=True)
        print('ENZIMOS_DIAGNOSTIC_JOURNAL\n'+result.stdout[-24000:],flush=True)
    worker=CONTROL/'recovery-api-cut.json'
    if worker.is_file():
        import recovery_stage
        before=json.loads(worker.read_text());roots=recovery_stage.subvolumes('/mnt')
        print('ENZIMOS_DIAGNOSTIC_RECOVERY_ROOT_DIFF '+json.dumps({'added':sorted(set(roots)-set(before['roots'])),'removed':sorted(set(before['roots'])-set(roots)),
            'changed':[name for name in roots if name in before['roots'] and roots[name]!=before['roots'][name]]}),flush=True)
        Path('/boot').mkdir(exist_ok=True);run(['mount','-t','vfat','-o','ro',TARGET+'-part2','/boot'])
        boot={str(p):sha(p) for folder in ('/boot/loader/entries','/boot/limine') for p in Path(folder).iterdir() if p.is_file()}
        print('ENZIMOS_DIAGNOSTIC_RECOVERY_BOOT_DIFF '+json.dumps({'added':sorted(set(boot)-set(before['boot'])),'removed':sorted(set(before['boot'])-set(boot)),
            'changed':[name for name in boot if name in before['boot'] and boot[name]!=before['boot'][name]]}),flush=True)
    print('ENZIMOS_DIAGNOSTIC_INVENTORY\n'+inventory(Path('/mnt/fdn-root')),flush=True)
    return {'readonly_diagnostic':True}


def main():
    print('ENZIMOS_FOUNDATION_RECOVERY_RAM_STARTED root-locked',flush=True)
    selection=Path('/sys/firmware/qemu_fw_cfg/by_name/opt/enzimos/case/raw').read_bytes().decode().strip('\x00\n')
    readonly=selection=='diagnose'
    try:
        check(not Path('/dev/mapper/lab-root-crypt').exists(),'root was already unlocked')
        check(not Path('/dev/disk/by-id/virtio-enzimos-lab-payload').exists(),'recovery must not depend on payload ISO')
        check(output(['blockdev','--getsize64',TARGET])==str(8*1024**3),'unexpected virtual root device')
        Path('/etc/enzimos').mkdir(parents=True,exist_ok=True)
        Path('/etc/enzimos/pacman-query.conf').write_text('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\n')
        credential('ENZIMOS recovery passphrase:','/run/root-password')
        args=['cryptsetup','open','--key-file','/run/root-password']+(['--readonly'] if readonly else [])+[TARGET+'-part3','lab-root-crypt']
        run(args);Path('/run/root-password').unlink()
        Path('/mnt').mkdir(exist_ok=True)
        run(['mount','-t','btrfs','-o','subvolid=5,nodiscard'+(',ro,rescue=nologreplay' if readonly else ''),'/dev/mapper/lab-root-crypt','/mnt'])
        CONTROL.mkdir(parents=True,exist_ok=True);Path('/etc/pacman.d/gnupg').mkdir(parents=True,exist_ok=True)
        run(['mount','--bind','/mnt/fdn-control',CONTROL]);run(['mount','--bind','/mnt/fdn-authority','/etc/pacman.d/gnupg'])
        if readonly:detail=diagnose()
        else:
            before_header=header_hash();authority=native.authority_identity()
            home=Path('/mnt/lab-home/enzimos-admin/foundation-home-marker');home_before=home.read_bytes()
            Path('/boot').mkdir(exist_ok=True);run(['mount','-t','vfat',TARGET+'-part2','/boot'])
            boot_authority={p:sha(p) for p in ('/boot/EFI/BOOT/BOOTX64.EFI','/boot/limine/limine-bios.sys')}
            if selection in ('recovery-workflow','recovery-workflow-lts','recovery-workflow-cut-stage','recovery-workflow-cut-publish','recovery-workflow-review'):
                import test_recovery_workflow
                detail=test_recovery_workflow.qualify(check,selection)
            elif selection in ('recovery-activation','recovery-activation-lts','recovery-activation-cut'):
                import test_recovery_activation
                detail=test_recovery_activation.recover(check,selection)
            elif selection=='recovery-retirement-context':
                import test_retirement_context
                detail=test_retirement_context.qualify(check)
            elif selection=='recovery-staged-review':
                import test_staged_review
                detail=test_staged_review.qualify(check)
            elif selection=='recovery-image-confirm':detail=confirm_recovery_image()
            elif selection in ('recovery-packaged','recovery-packaged-cut','recovery-packaged-pending'):detail=restore_packaged(selection)
            elif selection=='recovery-restic':detail=restore_restic()
            elif selection=='recovery-snapper':detail=restore_snapper()
            else:raise ValueError('unknown independent recovery case')
            check(home.read_bytes()==home_before,'newer home overwritten')
            check(native.authority_identity()==authority,'current package authority changed')
            check(header_hash()==before_header,'LUKS header bytes changed')
            check(all(sha(p)==v for p,v in boot_authority.items()),'current loader authority overwritten')
            check(not (CONTROL/'backup.enabled').exists(),'restore activated future backup jobs')
            detail.update(newer_home_preserved=True,current_authority_preserved=True,current_loader_preserved=True,luks_header_bytes_preserved=True,backup_jobs_enabled=False)
            atomic_json(CONTROL/'recovery-result.json',detail)
        result={'case':selection,'status':'PASS','results':[{'case':'B3-workflow' if selection.startswith('recovery-workflow') else 'L9-exclusive' if selection=='recovery-retirement-context' else 'R4-restic' if selection=='recovery-restic' else 'U4-recovery' if selection=='recovery-snapper' else 'R6-packaged-stage' if selection=='recovery-packaged' else 'R6-pending' if selection=='recovery-packaged-pending' else 'R7-confirm' if selection=='recovery-image-confirm' else 'R10-review' if selection=='recovery-staged-review' else 'R11-activation' if selection in ('recovery-activation','recovery-activation-lts') else 'diagnostic','status':'PASS','detail':detail}]}
    except BaseException as exc:
        traceback.print_exc();result={'case':selection,'status':'FAIL','error':str(exc),'results':[]}
        print('ENZIMOS_FOUNDATION_FAILURE recovery '+str(exc),flush=True)
    print('ENZIMOS_FOUNDATION_RESULT='+json.dumps(result,separators=(',',':')),flush=True)
    os.sync();run(['systemctl','--no-block','poweroff'])

if __name__=='__main__':main()
