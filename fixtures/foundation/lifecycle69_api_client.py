#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real native69/backend15 root-retirement API client: prepare, coordinator stage and finish
with fresh polkit authorization per call; no root/password material."""
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import termios
import threading
import time
import dbus
import dbus.bus
import dbus.lowlevel
NAME='org.enzimos.System1';PATH='/org/enzimos/System1';ID='9'*31+'0'


def main(mode):
    assert os.getuid()==os.geteuid()==(1001 if mode=='deny-user' else 1000)
    bus=dbus.bus.BusConnection('unix:path=/run/dbus/system_bus_socket');assert bus.get_unix_user(bus.get_name_owner(NAME))==0
    operations={4:'recovery-prepare',12:'root-retire-prepare',13:'root-retire-stage',14:'root-retire-finish',15:'remote-rotation-review',16:'remote-rotation-advance',17:'recovery-run-stage',18:'recovery-run-finish',19:'file-restore-export',20:'file-restore-grant',21:'file-restore-deliver',22:'remote-replicate',23:'remote-retrieve',24:'tree-restore-export'}
    selections=json.loads(Path('/run/lifecycle69-selections.json').read_text())
    def request(action,identifier=ID,digest=None,interactive=False,selection=None,version=12):
        return json.dumps({'schema':version,'operation':operations[version],'action':action,'request_id':identifier,'plan_sha256':digest,'allow_interaction':interactive,'selection':selection})
    def call(body):
        message=dbus.lowlevel.MethodCallMessage(NAME,PATH,NAME,'Operation');message.append(body,signature='s')
        return json.loads(bus.send_message_with_reply_and_block(message,120).get_args_list()[0])
    def denied(body,reason):
        try:call(body)
        except dbus.DBusException as exc:assert exc.get_dbus_name()==NAME+'.Refused' and exc.get_dbus_message()==reason,exc
        else:raise AssertionError('request did not refuse')
    for version in [v for v in operations if str(v) in selections and isinstance(selections[str(v)],dict)]:
        denied(request('plan',selection=selections[str(version)],version=version),'not-authorized')
        if mode.startswith('deny'):denied(request('plan',selection=selections[str(version)],interactive=True,version=version),'not-authorized')
    if mode.startswith('deny'):
        print('ENZIMOS_LIFECYCLE69_API_CLIENT='+json.dumps({'mode':mode,'denied':True}),flush=True);return
    session=os.environ.get('XDG_SESSION_ID');assert session
    info=subprocess.check_output(['loginctl','show-session',session,'-p','Active','-p','Remote','-p','User','-p','Seat','-p','VTNr'],text=True)
    assert all(value in info for value in ('Active=yes','Remote=no','User=1000','Seat=seat0','VTNr=2')),info
    pid=os.getpid();start=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]
    reader,writer=os.pipe();agent,terminal=pty.fork()
    if agent==0:
        os.set_inheritable(writer,True);os.execvp('pkttyagent',['pkttyagent','--process',f'{pid},{start}','--notify-fd',str(writer)])
    os.close(writer);transcript=bytearray();prompts=[];errors=[];done=threading.Event()
    def answer():
        try:
            while not done.is_set():
                if not select.select([terminal],[],[],.1)[0]:continue
                try:data=os.read(terminal,4096)
                except OSError:return
                if not data:return
                transcript.extend(data);assert len(transcript)<131072
                number=transcript.count(b'Password:')
                if number>len(prompts):
                    limit=time.monotonic()+5
                    while termios.tcgetattr(terminal)[3]&termios.ECHO and time.monotonic()<limit:time.sleep(.02)
                    assert not termios.tcgetattr(terminal)[3]&termios.ECHO
                    os.write(terminal,b'\x03' if mode=='auth-cancel' else b'ENZIMOS-PUBLIC-LAB-ADMIN\n');prompts.append(number)
        except Exception as exc:errors.append(type(exc).__name__)
    pump=threading.Thread(target=answer);pump.start();calls=[]
    try:
        assert select.select([reader],[],[],45)[0] and os.read(reader,1)==b''
        def authorized(version,action,identifier,digest=None,expected=None):
            body=request(action,identifier,digest,True,selections[str(version)] if action=='plan' else None,version)
            if expected:denied(body,expected);value=None
            else:value=call(body)
            calls.append(action);denied(request('status',identifier,version=version),'not-authorized');return value
        result={}
        def job(version,identifier,selection,drafts=True):
            selections[str(version)]=selection
            if drafts:
                draft=identifier[:-1]+'0';planned=authorized(version,'plan',draft)
                assert planned['state']=='planned' and 'plan' not in planned
                assert authorized(version,'cancel',draft,planned['plan_sha256'])['state']=='cancelled'
                authorized(version,'submit',draft,planned['plan_sha256'],expected='job-transition-refused')
            plan=authorized(version,'plan',identifier)
            authorized(version,'submit',identifier,'0'*64,expected='job-plan-changed')
            queued=authorized(version,'submit',identifier,plan['plan_sha256']);assert queued['state']=='queued'
            limit=time.monotonic()+600
            while True:
                time.sleep(5);value=authorized(version,'status',identifier)
                if value['state'] not in ('queued','running') or time.monotonic()>limit:break
            assert value['state']=='completed',value
            assert authorized(version,'submit',identifier,plan['plan_sha256'])==value
            return value['result']
        if mode=='auth-cancel':authorized(min(int(k) for k in selections if k.isdigit()),'plan','a'*32,expected='not-authorized')
        elif mode=='stage':
            prepared=job(12,'c'*32,selections['12'])
            assert prepared['status']=='root-retirement-prepared' and prepared['deleted'] is False,prepared
            # Staging before a ready image refuses at planning; nothing is recorded.
            selections['13']=dict(selections['13'],id=prepared['id'],image='ri-'+'0'*64)
            authorized(13,'plan','d'*31+'1',expected='job-plan-changed')
            staged=job(13,'d'*32,dict(selections['13'],image=selections['image']))
            assert staged['status']=='root-retirement-coordinator-staged' and staged['reboot_required'] is True,staged
            # A pending root retirement blocks re-preparation through the API too.
            authorized(12,'plan','e'*32,expected='job-plan-changed')
            result.update({'prepare':prepared,'stage':staged})
        elif mode=='finish':
            finished=job(14,'f'*32,{'id':selections['13']['id']},drafts=False)
            assert finished['status']=='root-retirement-complete',finished
            result['finish']=finished
        elif mode=='remote':
            review=job(15,'1'*32,{'rotation':'remote'})
            assert review['phase']=='switching' and review['next_action']=='switch',review
            selections['16']={'rotation':'remote','review_sha256':'0'*64,'action':'switch'}
            authorized(16,'plan','2'*31+'1',expected='job-plan-changed')
            switched=job(16,'2'*32,{'rotation':'remote','review_sha256':review['review_sha256'],'action':'switch'})
            assert switched['status']=='remote-rotation-switched' and switched['old_remote_repository_deleted'] is False,switched
            second=job(15,'3'*32,{'rotation':'remote'},drafts=False);assert second['next_action']=='discard',second
            discarded=job(16,'4'*32,{'rotation':'remote','review_sha256':second['review_sha256'],'action':'discard'},drafts=False)
            assert discarded['status']=='remote-rotation-complete',discarded
            result.update({'review':review,'switch':switched,'review-2':second,'discard':discarded})
        elif mode=='run-stage':
            prepared=job(4,'5'*32,selections['4'],drafts=False)
            assert prepared['activation_available'] is False,prepared
            selections['17']=dict(selections['17'],id=prepared['recovery_id'],plan_sha256='0'*64)
            authorized(17,'plan','6'*31+'1',expected='job-plan-changed')
            staged=job(17,'6'*32,dict(selections['17'],plan_sha256=prepared['plan_sha256']))
            assert staged['status']=='recovery-run-staged' and staged['reboot_required'] is True,staged
            result.update({'prepare':prepared,'stage':staged})
        elif mode=='run-finish':
            finished=job(18,'7'*32,{'id':selections['18']['id']},drafts=False)
            assert finished['status']=='recovery-run-complete' and finished['old_roots_retired'] is False,finished
            result['finish']=finished
        elif mode=='restore':
            exported=job(19,'8'*32,selections['19'])
            assert exported['status']=='private-file-export-complete' and exported['sha256']==selections['expected_sha256'],exported
            # A reused export ID refuses at planning (never adopted/replayed).
            authorized(19,'plan','8'*31+'1',expected='job-plan-changed')
            selections['20']=dict(selections['20'],export='missing-export')
            authorized(20,'plan','9'*31+'1',expected='job-plan-changed')
            granted=job(20,'9'*32,dict(selections['20'],export=exported['id']))
            assert granted['recipient_uid']==1000 and granted['filename']=='enzimos-restored-'+granted['id']+'.bin',granted
            selections['21']={'id':granted['id'],'grant_sha256':'0'*64}
            authorized(21,'plan','b'*31+'1',expected='job-plan-changed')
            delivered=job(21,'b'*32,{'id':granted['id'],'grant_sha256':granted['grant_sha256']})
            assert delivered['status']=='delivered-new-private-file' and delivered['overwritten'] is False and delivered['metadata_restored'] is False and delivered['sha256']==exported['sha256'],delivered
            selections['21']={'id':granted['id'],'grant_sha256':granted['grant_sha256']}
            authorized(21,'plan','b'*31+'2',expected='job-plan-changed')
            collision=job(20,'c'*32,{'id':selections['collision'],'export':exported['id'],'uid':1000},drafts=False)
            selections['21']={'id':collision['id'],'grant_sha256':collision['grant_sha256']}
            plan=authorized(21,'plan','d'*32);assert authorized(21,'submit','d'*32,plan['plan_sha256'])['state']=='queued'
            limit=time.monotonic()+300
            while True:
                time.sleep(5);value=authorized(21,'status','d'*32)
                if value['state'] not in ('queued','running') or time.monotonic()>limit:break
            assert value['state']=='uncertain' and value['result'] is None,value
            authorized(21,'submit','d'*32,plan['plan_sha256'],expected='job-transition-refused')
            result.update({'export':exported,'grant':granted,'deliver':delivered,'collision_grant':collision,'collision_state':value['state']})
        elif mode=='nas':
            replicated=job(22,'ab'*16,selections['22'])
            assert replicated['status']=='recovery-point-replicated' and replicated['source_snapshot']==selections['22']['snapshot'],replicated
            retrieved=job(23,'ac'*16,selections['23'])
            assert retrieved['status']=='remote-point-retrieved-to-local' and retrieved['automatic_retry'] is False,retrieved
            authorized(23,'plan','ac'*15+'ad',expected='job-plan-changed')
            exported=job(19,'ae'*16,{'id':'nas-export','snapshot':retrieved['local_snapshot'],'path':selections['path']},drafts=False)
            assert exported['sha256']==selections['expected_sha256'],exported
            granted=job(20,'af'*16,{'id':'nas-grant','export':'nas-export','uid':1000},drafts=False)
            delivered=job(21,'ba'*16,{'id':'nas-grant','grant_sha256':granted['grant_sha256']},drafts=False)
            assert delivered['status']=='delivered-new-private-file' and delivered['sha256']==exported['sha256'] and delivered['overwritten'] is False,delivered
            result.update({'replicate':replicated,'retrieve':retrieved,'export':exported,'grant':granted,'deliver':delivered})
        elif mode=='tree':
            fifo=dict(selections['24'],id='fifo-export',path=selections['fifo'])
            saved=selections['24'];selections['24']=fifo
            authorized(24,'plan','c9'*16,expected='job-plan-changed')
            exported=job(24,'ca'*16,saved)
            assert exported['status']=='private-tree-export-complete' and exported['entries']>=1,exported
            granted=job(20,'cb'*16,{'id':'tree-grant','export':'tree-export','uid':selections['uid']},drafts=False)
            delivered=job(21,'cc'*16,{'id':'tree-grant','grant_sha256':granted['grant_sha256']},drafts=False)
            assert delivered['status']=='delivered-new-private-file' and delivered['sha256']==exported['sha256'] and delivered['bytes']==exported['bytes'],delivered
            result.update({'export':exported,'grant':granted,'deliver':delivered})
        elif mode=='tree-completed':
            for version,identifier in ((24,'ca'*16),(20,'cb'*16),(21,'cc'*16)):
                value=authorized(version,'status',identifier);assert value['state']=='completed'
                assert authorized(version,'submit',identifier,value['plan_sha256'])==value;result[identifier]=value['result']
        elif mode=='nas-completed':
            for version,identifier in ((22,'ab'*16),(23,'ac'*16),(19,'ae'*16),(20,'af'*16),(21,'ba'*16)):
                value=authorized(version,'status',identifier);assert value['state']=='completed'
                assert authorized(version,'submit',identifier,value['plan_sha256'])==value;result[identifier]=value['result']
        elif mode=='restore-completed':
            for version,identifier in ((19,'8'*32),(20,'9'*32),(21,'b'*32),(20,'c'*32)):
                value=authorized(version,'status',identifier);assert value['state']=='completed'
                assert authorized(version,'submit',identifier,value['plan_sha256'])==value;result[identifier]=value['result']
            value=authorized(21,'status','d'*32);assert value['state']=='uncertain',value
            authorized(21,'submit','d'*32,value['plan_sha256'],expected='job-transition-refused');result['d'*32]=value['state']
        elif mode=='run-completed':
            for version,identifier in ((4,'5'*32),(17,'6'*32),(18,'7'*32)):
                value=authorized(version,'status',identifier);assert value['state']=='completed'
                assert authorized(version,'submit',identifier,value['plan_sha256'])==value;result[identifier]=value['result']
        elif mode=='remote-completed':
            for version,identifier in ((15,'1'*32),(16,'2'*32),(15,'3'*32),(16,'4'*32)):
                value=authorized(version,'status',identifier);assert value['state']=='completed'
                assert authorized(version,'submit',identifier,value['plan_sha256'])==value;result[identifier]=value['result']
        elif mode=='completed':
            for version,identifier in ((12,'c'*32),(13,'d'*32),(14,'f'*32)):
                value=authorized(version,'status',identifier);assert value['state']=='completed'
                assert authorized(version,'submit',identifier,value['plan_sha256'])==value;result[identifier]=value['result']
        else:raise AssertionError('unknown lifecycle client mode')
        assert not errors and len(prompts)==len(calls),(errors,prompts,calls)
        print('ENZIMOS_LIFECYCLE69_API_CLIENT='+json.dumps({'mode':mode,'password_prompts':len(prompts),'fresh_authorization':True,'result':result}),flush=True)
    finally:
        print('ENZIMOS_LIFECYCLE69_API_AGENT\n'+transcript.decode(errors='replace'),flush=True);done.set();pump.join(2);os.close(reader)
        try:os.kill(agent,15)
        except ProcessLookupError:pass
        os.waitpid(agent,0);os.close(terminal);bus.close()


if __name__=='__main__':main(sys.argv[1])
