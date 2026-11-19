#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""A real package transaction on an ADOPTED restored root.

adopted-update: a signed guest-local lab repository serves the next native-policy release
and its exact-version backend; native.run_update creates a fallback of the adopted root,
upgrades it and publishes/selects a new generation. adopted-update-boot: the next boot runs
that generation on the restored root and confirms it. Disposable lab signing key only."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import native
import generation_registry as registry
import recovery_activation as activation
from test_credential_review import pause_history,restore_history
from test_root_retirement import quiet_maintenance

GENERATION='upd-adopted'
STATE=Path('/var/lib/enzimos-control/adopted-update-fixture.json')
REPO=Path('/var/lib/enzimos-lab-repo')
CONFIG=Path('/etc/pacman-adopted-update.conf')
KEY=Path('/run/adopted-update-signing')


def adopted(check):
    values=[row for row in activation.records().values() if row['phase']=='adopted']
    check(len(values)==1,'exactly one adopted restored root required')
    root=values[0]['intent']['job']['root']
    check(registry.bounded_query(['findmnt','-n','-o','FSROOT','--mountpoint','/'])=='/'+root['path'],'not running on the adopted restored root')
    return root


def lab_repository(check,payload):
    payload=Path(payload);summary=json.loads((payload/'update-payload.json').read_text())
    KEY.mkdir(mode=0o700)
    native.run(['gpg','--homedir',KEY,'--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key','enzimOS DISPOSABLE adopted-update lab repository','ed25519','sign','1d'])
    subprocess.run(['gpg','--homedir','/etc/pacman.d/gnupg','--batch','--no-autostart','--import'],input=subprocess.check_output(['gpg','--homedir',str(KEY),'--batch','--export']),check=True)
    fingerprint=next(line.split(':')[9] for line in native.output(['gpg','--homedir',KEY,'--with-colons','--list-keys']).splitlines() if line.startswith('fpr:'))
    native.run(['gpg','--homedir','/etc/pacman.d/gnupg','--batch','--no-autostart','--import-ownertrust'],input=fingerprint+':5:\n')
    REPO.mkdir(mode=0o755);packages=[]
    for label,row in summary.items():
        source=payload/('update-'+label+'.pkg.tar.zst');check(native.sha(source)==row['sha256'],'update package drift: '+label)
        name=json.loads((payload/('update-'+label+'-build.json')).read_text())['package'].rsplit('/',1)[-1]
        target=REPO/name;shutil.copyfile(source,target);target.chmod(0o644)
        native.run(['gpg','--homedir',KEY,'--batch','--detach-sign','--output',str(target)+'.sig',target]);packages.append(str(target))
    native.run(['repo-add','-q',REPO/'enzimos-lab.db.tar.gz',*packages])
    CONFIG.write_text('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly DatabaseOptional\nLocalFileSigLevel = Required TrustedOnly\n'
                      'CacheDir = /var/cache/pacman/pkg/\nLogFile = /var/log/pacman-adopted-update.log\n\n[enzimos-lab]\nServer = file://'+str(REPO)+'\n')
    return summary


def drop_lab_recovery(check):
    """LAB-ONLY cleanup, not product state: the disposable disk image carries a legacy lab
    recovery image (/boot/enzimos-recovery, ~133 MiB) outside every publisher record. The
    512 MiB lab ESP cannot also hold an update's staged boot files, so remove it and its two
    lab loader entries (BIOS default preserved by title) before the update."""
    import re
    folder=Path('/boot/enzimos-recovery')
    if not folder.is_dir():return False
    with native.operation_lock():
        uefi=Path('/boot/loader/entries/recovery.conf')
        if uefi.exists():
            check('/enzimos-recovery/' in uefi.read_text(),'unexpected lab recovery UEFI entry');check('default recovery.conf' not in Path('/boot/loader/loader.conf').read_text(),'lab recovery is the UEFI default')
            uefi.unlink()
        limine=Path('/boot/limine/limine.conf');header,entries,selected=native.limine_menu(limine.read_text())
        chosen=entries[selected-1]['title'];keep=[e for e in entries if 'boot():/enzimos-recovery/' not in e['text']]
        titles=[e['title'] for e in keep];check(chosen in titles,'lab recovery entry is the BIOS default')
        header=re.sub(r'^default_entry:[ \t]*[0-9]+[ \t]*$','default_entry: '+str(titles.index(chosen)+1),header,flags=re.M)
        native.atomic_text(limine,header+''.join(e['text'] for e in keep));shutil.rmtree(folder);os.sync()
    return True


def make_room(check):
    """As an administrator would: retire the oldest retirable boot generations (packaged,
    plan-digest-bound; roots are kept) until the update's fallback + new generation fit."""
    import boot_retirement
    retired=[]
    def count():return len([p for p in Path('/boot/enzimos/generations').iterdir() if p.is_dir() and not p.is_symlink()])
    while count()+2>native.MAX_BOOT_GENERATIONS:
        catalog=registry.status()['catalog']['generations'];plans={}
        for name in sorted(catalog,key=lambda n:catalog[n]['ordinal']):
            plans[name]=boot_retirement.plan(name)
            if plans[name]['retirable']:break
        else:check(False,'no retirable boot generation: '+json.dumps({n:p['protection'] for n,p in plans.items()}))
        result=boot_retirement.retire(name,plans[name]['plan_sha256']);check(result['status']=='retirement-complete' and result['root_subvolume_retained'],'boot retirement')
        retired.append(name)
    return retired


def update(check,payload):
    root=adopted(check);history=pause_history(check);quiet_maintenance(check)
    before=native.output(['pacman','-Q'])
    retired=make_room(check);lab_recovery_removed=drop_lab_recovery(check)
    summary=lab_repository(check,payload)
    options=' '.join(word for word in Path('/proc/cmdline').read_text().split() if not word.startswith('enzimos.'))
    check(native.upgrade_candidates(CONFIG),'lab repository offers no upgrade')
    # Diagnostic: the update's ESP admission needs 2x the staged boot files + 32 MiB.
    print('ENZIMOS_LAB_ESP '+json.dumps({'free':shutil.disk_usage('/boot').free,'total':shutil.disk_usage('/boot').total,
        'dirs':{str(p.relative_to('/boot')):sum(f.stat().st_size for f in p.rglob('*') if f.is_file()) for p in [*Path('/boot').iterdir(),*Path('/boot/enzimos').glob('*/*')] if p.is_dir()}}),flush=True)
    native.run_update(CONFIG,GENERATION,native.installed_kernels(),options)
    versions={label:native.output(['pacman','-Q','enzimos-'+label]) for label in summary}
    for label,row in summary.items():check(versions[label]=='enzimos-'+label+' 0.1.0-'+str(row['release']),'package not upgraded: '+label)
    catalog=registry.status()['catalog']['generations']
    check(catalog.get(GENERATION,{}).get('state')=='ready' and catalog.get('old-'+GENERATION,{}).get('state')=='ready','new/fallback generations not registered')
    check(catalog[GENERATION]['material']['root_identity']['uuid']==root['uuid'],'new generation is not bound to the adopted root')
    check(catalog['old-'+GENERATION]['material']['root_identity']['uuid']!=root['uuid'],'fallback is not a separate root')
    check(native.generation_selected(GENERATION),'new generation not selected')
    native.atomic_json(STATE,{'boot_id':native.boot_id(),'root':root,'versions':versions,'before':before,'history':history,
                              'inventory':native.output(['pacman','-Q'])})
    os.sync()
    return {'boot_generations_retired_first':retired,'lab_only_recovery_removed_for_esp_space':lab_recovery_removed,'adopted_root_updated':True,'real_package_transaction':True,'signed_lab_repository':True,'fallback_of_adopted_root':True,
            'new_generation_selected':True,'packages':versions,'production_keys_used':False}


def boot(check):
    saved=json.loads(STATE.read_text());check(saved['boot_id']!=native.boot_id(),'later boot required')
    check(registry.current_marker()==GENERATION,'next boot is not the new generation')
    confirmed=registry.confirm_current();check(confirmed['generation']==GENERATION,'new generation confirmation')
    check(registry.bounded_query(['findmnt','-n','-o','FSROOT','--mountpoint','/'])=='/'+saved['root']['path'],'new generation does not run on the adopted root')
    check(native.output(['pacman','-Q'])==saved['inventory'],'booted inventory differs from the transaction result')
    STATE.unlink();restore_history(check,saved['history'])
    return {'later_boot':True,'new_generation_booted':True,'generation_confirmed':True,'adopted_root_kept':True,'inventory_matches_transaction':True}


def qualify(check,selection,payload):
    return update(check,payload) if selection=='adopted-update' else boot(check)
