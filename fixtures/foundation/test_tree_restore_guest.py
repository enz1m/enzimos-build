#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Directory tree restore through the backend with real polkit (payload-script).

A tiny lab point (exact whole-system scope/tag/host, NOT a full-system backup) holds a small
directory tree from enzimos-admin's home (nested dirs, files, a relative symlink) and a
second directory containing a FIFO. Through the API: planning the FIFO tree refuses before
any job exists; the good tree is exported (schema24) as a bounded tar in private staging,
granted (schema20) and delivered (schema21) as ONE new private file. The delivered archive
is parsed, never extracted into the home; historical modes stay data. Restart dedup."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import native
import backup
import generation_registry as registry
from test_credential_review import pause_history,restore_history
from test_root_retirement import quiet_maintenance
import test_root_api69 as api

HOME=Path('/home/enzimos-admin');GRANT='tree-grant';OUTPUT=HOME/('enzimos-restored-'+GRANT+'.bin')
TREE={'project/readme.txt':b'enzimOS tree restore readme\n','project/src/main.txt':b'main body\n','project/src/deep/leaf.txt':b'leaf\n'}


def lab_point(check):
    config=backup.read_config()
    if not Path(config['repository'],'config').exists():backup.initialize()
    before={row['id'] for row in backup.snapshots(config)}
    sources=[Path('/run/lab-tree-point')/name for name in ('system','home','boot','inventory')]
    for folder in sources:folder.mkdir(parents=True,exist_ok=True)
    (sources[3]/'packages.txt').write_text(native.output(['pacman','-Q'])+'\n')
    home=sources[1]/'enzimos-admin'
    for name,body in TREE.items():
        path=home/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(body)
    (home/'project/src/link').symlink_to('main.txt')
    (home/'with-fifo').mkdir();(home/'with-fifo/ok.txt').write_bytes(b'ok\n');os.mkfifo(home/'with-fifo/pipe')
    env=dict(PATH='/usr/bin',HOME='/nonexistent',LANG='C.UTF-8',RESTIC_REPOSITORY=config['repository'],RESTIC_PASSWORD_FILE=config['password_file'],GOMAXPROCS='1')
    Path('/backup-source').mkdir(exist_ok=True)
    for folder in sources:
        target=Path('/backup-source')/folder.name;target.mkdir(exist_ok=True);native.run(['mount','--bind',folder,target])
    try:subprocess.run(['restic','--no-cache','backup','--host','enzimos','--tag','enzimos-whole-linux',*[str(Path('/backup-source')/f.name) for f in sources]],env=env,check=True,stdout=subprocess.DEVNULL)
    finally:
        for folder in sources:native.run(['umount',Path('/backup-source')/folder.name])
    added=[row['id'] for row in backup.snapshots(config) if row['id'] not in before];check(len(added)==1,'lab point not created')
    return config,added[0]


def diagnose(config,snapshot):
    """Lab-only failure diagnostic (the backend never exposes native error text)."""
    import backup_selective as selective
    path='/backup-source/home/enzimos-admin/project'
    try:selective.export_tree('tree-diagnostic',snapshot,path)
    except Exception as exc:print('ENZIMOS_LAB_TREE_ERROR '+type(exc).__name__+': '+str(exc)[:2000],flush=True)
    env=dict(PATH='/usr/bin',HOME='/nonexistent',LANG='C.UTF-8',RESTIC_REPOSITORY=config['repository'],RESTIC_PASSWORD_FILE=config['password_file'],GOMAXPROCS='1')
    body=subprocess.run(['restic','--no-cache','dump',snapshot,path],env=env,capture_output=True).stdout
    try:
        with tarfile.open(fileobj=io.BytesIO(body),mode='r:') as archive:
            print('ENZIMOS_LAB_TREE_MEMBERS '+json.dumps([(m.name,m.type.decode(errors='replace'),m.size) for m in archive]),flush=True)
    except Exception as exc:print('ENZIMOS_LAB_TREE_DUMP '+str(len(body))+' '+type(exc).__name__+' '+body[:200].hex(),flush=True)
    print('ENZIMOS_LAB_TREE_LS '+subprocess.run(['restic','--no-cache','ls','--json','--recursive',snapshot,path],env=env,capture_output=True,text=True).stdout[-3000:],flush=True)


def run(check,payload):
    api.install(check,payload);history=pause_history(check);quiet_maintenance(check)
    native.run(['mount','/backup-repository'])
    try:
        config,snapshot=lab_point(check);points=sorted(row['id'] for row in backup.snapshots(config))
        inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
        api.write_selections({'24':{'id':'tree-export','snapshot':snapshot,'path':'/backup-source/home/enzimos-admin/project'},
                              'fifo':'/backup-source/home/enzimos-admin/with-fifo','uid':1000})
        try:
            api.denials(check);cancelled=api.authenticated(check,'auth-cancel')
            check(not (registry.CONTROL/'restore-exports'/'tree-export').exists(),'denied/cancelled requests exported')
            try:done=api.authenticated(check,'tree')
            except AssertionError:
                diagnose(config,snapshot);raise
            result=done['result']
            check(result['export']['entries']==7,'tree entry count: '+json.dumps(result['export']))
            check(OUTPUT.stat().st_uid==1000 and OUTPUT.stat().st_mode&0o777==0o600,'tree archive ownership/mode')
            check(subprocess.run(['runuser','-u','enzimos-user','--','test','-r',OUTPUT]).returncode!=0,'other user can read the tree archive')
            with tarfile.open(OUTPUT,mode='r:') as archive:
                members={m.name.lstrip('./').lstrip('/').rstrip('/'):m for m in archive}
                files={name:archive.extractfile(m).read() for name,m in members.items() if m.isreg()}
                links={name:m.linkname for name,m in members.items() if m.issym()}
            prefix='backup-source/home/enzimos-admin/'
            relative={(k[len(prefix):] if k.startswith(prefix) else k):v for k,v in files.items()}
            check(relative==TREE,'tree archive contents: '+json.dumps(sorted(members)))
            check(list(links.values())==['main.txt'],'tree archive symlink')
            check(not (HOME/'project').exists() and not (HOME/'with-fifo').exists(),'tree restore extracted into the live home')
            ledger={str(p):native.sha(p) for p in (registry.CONTROL/'backend-operations').glob('*.json')}
            native.run(['systemctl','restart',api.UNIT]);completed=api.authenticated(check,'tree-completed')
            check(all(native.sha(Path(p))==v for p,v in ledger.items()),'restart changed ledger records')
            check(sorted(row['id'] for row in backup.snapshots(config))==points and native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,
                  'tree restore changed points/packages/authority')
        finally:native.run(['systemctl','stop',api.UNIT])
    finally:
        native.run(['umount','/backup-repository']);restore_history(check,history)
    return {'tree_restore_api':True,'real_polkit_prompts':cancelled['password_prompts']+done['password_prompts']+completed['password_prompts'],
            'special_file_tree_refused_at_planning':True,'bounded_tar_export':True,'archive_matches_listing':True,'single_new_private_file':True,
            'other_user_cannot_read':True,'not_extracted_into_home':True,'completed_restart_deduplicated':True,'denied_and_cancelled_no_state':True,
            'points_packages_authority_preserved':True,'lab_point_not_full_system_backup':True,'metadata_restored':False}
