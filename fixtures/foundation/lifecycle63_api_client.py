#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real native63/backend13 lifecycle API client: boot retirement and compromise-rotation
review/advance with fresh polkit authorization per call; no root/password material."""
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
    operations={9:'boot-retire',10:'rotation-review',11:'rotation-advance'}
    selections=json.loads(Path('/run/lifecycle63-selections.json').read_text())
    def request(action,identifier=ID,digest=None,interactive=False,selection=None,version=9):
        return json.dumps({'schema':version,'operation':operations[version],'action':action,'request_id':identifier,'plan_sha256':digest,'allow_interaction':interactive,'selection':selection})
    def call(body):
        message=dbus.lowlevel.MethodCallMessage(NAME,PATH,NAME,'Operation');message.append(body,signature='s')
        return json.loads(bus.send_message_with_reply_and_block(message,120).get_args_list()[0])
    def denied(body,reason):
        try:call(body)
        except dbus.DBusException as exc:assert exc.get_dbus_name()==NAME+'.Refused' and exc.get_dbus_message()==reason,exc
        else:raise AssertionError('request did not refuse')
    for version in operations:
        denied(request('plan',selection=selections[str(version)],version=version),'not-authorized')
        if mode.startswith('deny'):denied(request('plan',selection=selections[str(version)],interactive=True,version=version),'not-authorized')
    if mode.startswith('deny'):
        print('ENZIMOS_LIFECYCLE63_API_CLIENT='+json.dumps({'mode':mode,'denied':True}),flush=True);return
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
        if mode=='auth-cancel':authorized(9,'plan','a'*32,expected='not-authorized')
        elif mode=='execute':
            def job(version,identifier,selection):
                selections[str(version)]=selection
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
            result['boot-retire']=job(9,'9'*32,selections['9'])
            assert result['boot-retire']['status']=='retirement-complete' and result['boot-retire']['root_subvolume_retained'] is True
            review=job(10,'a'*32,{'id':selections['10']['id']});assert review['next_action']=='switch' and review['boundary']==0,review
            switched=job(11,'b'*32,{'id':review['rotation'],'review_sha256':review['review_sha256'],'action':'switch'})
            assert switched['status']=='rotation-switched' and switched['old_access_revoked'] is False
            second=job(10,'c'*32,{'id':review['rotation']});assert second['next_action']=='discard',second
            discarded=job(11,'d'*32,{'id':review['rotation'],'review_sha256':second['review_sha256'],'action':'discard'})
            assert discarded['status']=='rotation-complete'
            result.update({'rotation-review':review,'rotation-switch':switched,'rotation-review-2':second,'rotation-discard':discarded})
        elif mode=='completed':
            for version,identifier in ((9,'9'*32),(10,'a'*32),(11,'b'*32),(10,'c'*32),(11,'d'*32)):
                value=authorized(version,'status',identifier);assert value['state']=='completed'
                assert authorized(version,'submit',identifier,value['plan_sha256'])==value;result[identifier]=value['result']
        else:raise AssertionError('unknown lifecycle client mode')
        assert not errors and len(prompts)==len(calls),(errors,prompts,calls)
        print('ENZIMOS_LIFECYCLE63_API_CLIENT='+json.dumps({'mode':mode,'password_prompts':len(prompts),'fresh_authorization':True,'result':result}),flush=True)
    finally:
        print('ENZIMOS_LIFECYCLE63_API_AGENT\n'+transcript.decode(errors='replace'),flush=True);done.set();pump.join(2);os.close(reader)
        try:os.kill(agent,15)
        except ProcessLookupError:pass
        os.waitpid(agent,0);os.close(terminal);bus.close()


if __name__=='__main__':main(sys.argv[1])
