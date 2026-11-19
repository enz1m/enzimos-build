#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only real supervisor deaths, durable cancellation and later-boot refusal."""
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import time
import native
import backup
import backup_delivery as d
import backup_selective
from test_credential_review import pause_history,restore_history

STATE=Path('/var/lib/enzimos-control/delivery-lifecycle-fixture.json')
BOUNDARIES=('before-arm','after-drop','partial-copy')


def refuse(check,action,fragment):
    try:action()
    except (native.Failure,OSError) as exc:check(fragment in str(exc),'wrong delivery refusal: '+str(exc));return
    raise AssertionError('delivery negative control succeeded')


def wait_child(check,pid):
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        waited,status=os.waitpid(pid,os.WNOHANG)
        if waited:return status
        time.sleep(.05)
    raise AssertionError('delivery process survived supervisor death')


def kill_trial(check,boundary,export,content):
    identifier='death-'+boundary;granted=d.grant(identifier,export,1001)
    events,writer=os.pipe();reader,gate=os.pipe();parent=None;child=None
    parent=os.fork()
    if parent==0:
        try:
            os.dup2(writer,1);os.dup2(reader,0)
            for fd in (events,writer,reader,gate):
                if fd>2:os.close(fd)
            original=d.child_copy;raw_write=os.write
            def ready():
                raw_write(1,(json.dumps({'pid':os.getpid(),'uid':os.getuid(),'boundary':boundary})+'\n').encode())
                os.read(0,1)
            def copy(*args):
                if boundary=='before-arm':ready()
                if boundary=='after-drop':
                    old_arm=d.arm_parent_death
                    def arm(*values):
                        old_arm(*values)
                        if os.geteuid()==1001:ready()
                    d.arm_parent_death=arm
                if boundary=='partial-copy':
                    fired=False
                    def write(fd,data):
                        nonlocal fired
                        if not fired and os.geteuid()==1001 and fd not in (1,2):
                            fired=True;count=raw_write(fd,data[:max(1,len(data)//2)]);os.fsync(fd);ready();return count
                        return raw_write(fd,data)
                    d.os.write=write
                original(*args)
            d.child_copy=copy
            d.deliver(identifier,granted['grant_sha256']);os._exit(3)
        except BaseException:os._exit(4)
    os.close(writer);os.close(reader)
    try:
        data=b'';deadline=time.monotonic()+90
        while b'\n' not in data:
            check(time.monotonic()<deadline,'delivery boundary readiness timeout')
            if not select.select([events],[],[],.2)[0]:continue
            chunk=os.read(events,1024);check(bool(chunk) and len(data)+len(chunk)<=4096,'delivery readiness failed');data+=chunk
        event=json.loads(data.split(b'\n')[0]);child=event['pid']
        check(event['boundary']==boundary and event['uid']==(0 if boundary=='before-arm' else 1001),'wrong real delivery boundary/privileges')
        os.kill(parent,signal.SIGKILL);_,status=os.waitpid(parent,0);parent=None
        check(os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL,'supervisor was not killed')
        if boundary=='before-arm':os.write(gate,b'x')
        status=wait_child(check,child);child=None
        if boundary=='before-arm':check(os.WIFEXITED(status) and os.WEXITSTATUS(status)==1,'pre-arm orphan continued')
        else:check(os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL,'armed child survived parent')
        target=Path('/home/enzimos-user')/granted['filename']
        if boundary=='partial-copy':
            output=target.read_bytes();check(0<len(output)<len(content) and content.startswith(output),'partial output mismatch')
            check(target.stat().st_uid==1001 and target.stat().st_mode&0o777==0o600,'partial output permissions')
        else:check(not target.exists(),'pre-copy death created output')
        check(d.status(identifier)['status']=='uncertain','dead supervisor not uncertain')
        refuse(check,lambda:d.deliver(identifier,granted['grant_sha256']),'no replay')
        refuse(check,lambda:d.cancel(identifier,granted['grant_sha256']),'already entered')
        print('ENZIMOS_DELIVERY_SUPERVISOR_KILL '+json.dumps({'boundary':boundary,'child_terminated':True,'partial_output':boundary=='partial-copy'}),flush=True)
        return granted
    finally:
        for pid in (parent,child):
            if pid is not None:
                try:os.kill(pid,signal.SIGKILL)
                except ProcessLookupError:pass
                try:os.waitpid(pid,0)
                except ChildProcessError:pass
        os.close(events);os.close(gate)


def material(config,grants):
    rows={}
    for grant in grants:
        path=Path('/home/enzimos-user')/grant['filename']
        rows[grant['id']]={'journal':native.sha(d.directory()/(grant['id']+'.json')),
                          'output':None if not path.exists() else {'sha256':native.sha(path),'bytes':path.stat().st_size,'uid':path.stat().st_uid,'mode':path.stat().st_mode&0o777}}
    return {'grants':rows,'points':sorted(row['id'] for row in backup.snapshots(config)),
            'inventory':native.output(['pacman','-Q']),'authority':native.authority_identity()}


def qualify(check,selection):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-56','wrong delivery candidate')
    native.run(['mount','/backup-repository']);config=backup.read_config();schedule=pause_history(check)
    try:
        if selection=='delivery-lifecycle-review':
            saved=json.loads(STATE.read_text());check(saved['boot_id']!=native.boot_id(),'later boot required')
            grants=saved['grants'];check(material(config,grants)==saved['material'],'later boot delivery material changed')
            for granted in grants:
                state=d.status(granted['id'])['status']
                expected='uncertain' if (granted['id'].startswith('death-') or granted['id']=='collision') else 'cancelled' if granted['id']=='cancel-unused' else 'complete' if granted['id']=='positive' else 'expired'
                check(state==expected,'wrong later delivery status')
                refuse(check,lambda:d.deliver(granted['id'],granted['grant_sha256']),'boot changed' if expected=='expired' else 'no replay')
            check(material(config,grants)==saved['material'],'later review changed output or journals')
        else:
            protected={'points':sorted(row['id'] for row in backup.snapshots(config)),'inventory':native.output(['pacman','-Q']),'authority':native.authority_identity()}
            snapshot=max(backup.snapshots(config),key=lambda row:row['time'])['id']
            backup_selective.export('delivery-source',snapshot,'/backup-source/home/enzimos-admin/.var/app/org.enzimos.Fixture/hidden-data')
            content=(d.registry.CONTROL/'restore-exports/delivery-source/content.bin').read_bytes();check(len(content)>1,'partial test needs bytes')
            # Subreaping is confined to this fixture's supervisor and copy descendants.
            library=ctypes.CDLL(None,use_errno=True);check(library.prctl(36,1,0,0,0)==0,'fixture subreaper setup failed')
            try:grants=[kill_trial(check,boundary,'delivery-source',content) for boundary in BOUNDARIES]
            finally:check(library.prctl(36,0,0,0,0)==0,'fixture subreaper restore failed')
            cancelled=d.grant('cancel-unused','delivery-source',1001);grants.append(cancelled)
            refuse(check,lambda:d.cancel(cancelled['id'],'0'*64),'stale')
            d.cancel(cancelled['id'],cancelled['grant_sha256']);receipt=native.sha(d.directory()/(cancelled['id']+'.json'))
            d.cancel(cancelled['id'],cancelled['grant_sha256']);check(native.sha(d.directory()/(cancelled['id']+'.json'))==receipt,'cancel retry wrote receipt')
            refuse(check,lambda:d.deliver(cancelled['id'],cancelled['grant_sha256']),'no replay')
            check(not (Path('/home/enzimos-user')/cancelled['filename']).exists(),'cancel created output')
            positive=d.grant('positive','delivery-source',1001);grants.append(positive);d.deliver(positive['id'],positive['grant_sha256'])
            target=Path('/home/enzimos-user')/positive['filename'];check(target.read_bytes()==content and target.stat().st_uid==1001 and target.stat().st_mode&0o777==0o600,'positive delivery failed')
            check(subprocess.run(['runuser','-u','enzimos-admin','--','test','-r',target]).returncode!=0,'other user can read delivery')
            collision=d.grant('collision','delivery-source',1001);grants.append(collision)
            existing=Path('/home/enzimos-user')/collision['filename'];existing.write_bytes(b'KEEP-EXISTING');os.chown(existing,1001,1001);existing.chmod(0o600)
            refuse(check,lambda:d.deliver(collision['id'],collision['grant_sha256']),'delivery incomplete')
            check(existing.read_bytes()==b'KEEP-EXISTING','delivery overwrote collision')
            grants.append(d.grant('expires','delivery-source',1001))
            for action in ('status','cancel'):
                args=['runuser','-u','enzimos-user','--','python','/usr/lib/enzimos/backup_delivery.py',action,'--id',cancelled['id']]
                if action=='cancel':args+=['--grant-sha256',cancelled['grant_sha256']]
                result=subprocess.run(args,capture_output=True,text=True)
                check(result.returncode!=0 and 'root authorization required' in result.stderr,'ordinary delivery lifecycle allowed')
            observed=material(config,grants);check(all(observed[key]==value for key,value in protected.items()),'delivery changed points/packages/authority')
            native.atomic_json(STATE,{'boot_id':native.boot_id(),'grants':grants,'material':material(config,grants)})
        return {'later_boot':selection=='delivery-lifecycle-review','supervisor_deaths':3 if selection=='delivery-lifecycle' else 0,
                'uncertain_no_retry':True,'cancellation_no_output':True,'positive_private_delivery':True,'grant_expiry_checked':selection=='delivery-lifecycle-review',
                'receipt_output_points_packages_authority_preserved':True,'copy_replayed':False,'physical_power_loss':False}
    finally:restore_history(check,schedule)
