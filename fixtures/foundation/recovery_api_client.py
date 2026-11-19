#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real recovery-plan API client, no stage/mount/activation permission."""
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
NAME='org.enzimos.System1';PATH='/org/enzimos/System1';ID='2'*32


def main(mode):
    assert os.getuid()==os.geteuid()==(1001 if mode=='deny-user' else 1000)
    bus=dbus.bus.BusConnection('unix:path=/run/dbus/system_bus_socket');assert bus.get_unix_user(bus.get_name_owner(NAME))==0
    def request(action,identifier=ID,digest=None,interactive=False,selection=None):
        return json.dumps({'schema':4,'operation':'recovery-prepare','action':action,'request_id':identifier,'plan_sha256':digest,'allow_interaction':interactive,'selection':selection})
    def call(body):
        message=dbus.lowlevel.MethodCallMessage(NAME,PATH,NAME,'Operation');message.append(body,signature='s')
        return json.loads(bus.send_message_with_reply_and_block(message,120).get_args_list()[0])
    def denied(body,reason):
        try:call(body)
        except dbus.DBusException as exc:assert exc.get_dbus_name()==NAME+'.Refused' and exc.get_dbus_message()==reason,exc
        else:raise AssertionError('request did not refuse')
    selection={'birth':'fdn-success','generation':'old-fdn-success'}
    denied(request('plan',selection=selection),'not-authorized')
    if mode.startswith('deny'):
        denied(request('plan',selection=selection,interactive=True),'not-authorized')
        print('ENZIMOS_RECOVERY_API_CLIENT='+json.dumps({'mode':mode,'denied':True}),flush=True);return
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
                    os.write(terminal,b'ENZIMOS-PUBLIC-LAB-ADMIN\n');prompts.append(number)
        except Exception as exc:errors.append(type(exc).__name__)
    pump=threading.Thread(target=answer);pump.start();calls=[]
    try:
        assert select.select([reader],[],[],45)[0] and os.read(reader,1)==b''
        def authorized(action,identifier=ID,digest=None,expected=None):
            body=request(action,identifier,digest,True,selection if action=='plan' else None)
            if expected:denied(body,expected);result=None
            else:result=call(body)
            calls.append(action);denied(request('status',identifier),'not-authorized');return result
        if mode=='plan-cancel':
            planned=authorized('plan');assert planned['state']=='planned';assert 'plan' not in planned
            authorized('submit',digest='0'*64,expected='job-plan-changed')
            assert authorized('cancel',digest=planned['plan_sha256'])['state']=='cancelled'
            authorized('submit',digest=planned['plan_sha256'],expected='job-transition-refused');result={}
        elif mode=='prepare':
            identifier='3'*32;plan=authorized('plan',identifier);queued=authorized('submit',identifier,plan['plan_sha256']);assert queued['state']=='queued'
            limit=time.monotonic()+180
            while True:
                time.sleep(10);status=authorized('status',identifier)
                if status['state']!='running' or time.monotonic()>limit:break
            assert status['state']=='completed',status
            assert status['result']['activation_available'] is False
            assert authorized('submit',identifier,plan['plan_sha256'])==status;result=status
        elif mode=='completed':
            status=authorized('status','3'*32);assert status['state']=='completed'
            assert authorized('submit','3'*32,status['plan_sha256'])==status;result=status
        else:raise AssertionError('unknown mode')
        assert not errors and len(prompts)==len(calls),(errors,prompts,calls)
        print('ENZIMOS_RECOVERY_API_CLIENT='+json.dumps({'mode':mode,'password_prompts':len(prompts),'fresh_authorization':True,'result':result}),flush=True)
    finally:
        print('ENZIMOS_RECOVERY_API_AGENT\n'+transcript.decode(errors='replace'),flush=True);done.set();pump.join(2);os.close(reader)
        try:os.kill(agent,15)
        except ProcessLookupError:pass
        os.waitpid(agent,0);os.close(terminal);bus.close()


if __name__=='__main__':main(sys.argv[1])
