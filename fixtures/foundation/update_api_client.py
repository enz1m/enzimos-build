#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real polkit client for a closed admitted local live-update job."""
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
NAME='org.enzimos.System1';PATH='/org/enzimos/System1'


def main(mode):
    assert os.getuid()==os.geteuid()==(1001 if mode=='deny-user' else 1000)
    bus=dbus.bus.BusConnection('unix:path=/run/dbus/system_bus_socket');assert bus.get_unix_user(bus.get_name_owner(NAME))==0
    def request(action,identifier='4'*32,digest=None,interactive=False):return json.dumps({'schema':5,'operation':'update-apply','action':action,'request_id':identifier,'plan_sha256':digest,'allow_interaction':interactive})
    def call(body):
        message=dbus.lowlevel.MethodCallMessage(NAME,PATH,NAME,'Operation');message.append(body,signature='s')
        return json.loads(bus.send_message_with_reply_and_block(message,120).get_args_list()[0])
    def denied(body,reason):
        try:call(body)
        except dbus.DBusException as exc:assert exc.get_dbus_name()==NAME+'.Refused' and exc.get_dbus_message()==reason,exc
        else:raise AssertionError('expected refusal')
    denied(request('plan'),'not-authorized')
    if mode.startswith('deny'):
        denied(request('plan',interactive=True),'not-authorized');print('ENZIMOS_UPDATE_API_CLIENT='+json.dumps({'mode':mode,'denied':True}),flush=True);return
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
                transcript.extend(data);assert len(transcript)<196608
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
        def authorized(action,identifier='4'*32,digest=None,expected=None):
            body=request(action,identifier,digest,True)
            if expected:denied(body,expected);result=None
            else:result=call(body)
            calls.append(action);denied(request('status',identifier),'not-authorized');return result
        if mode=='plan-cancel':
            plan=authorized('plan');authorized('submit',digest='0'*64,expected='job-plan-changed');assert authorized('cancel',digest=plan['plan_sha256'])['state']=='cancelled';result={}
        elif mode=='update':
            identifier='5'*32;plan=authorized('plan',identifier);assert authorized('submit',identifier,plan['plan_sha256'])['state']=='queued'
            limit=time.monotonic()+2100;seen=set()
            while True:
                time.sleep(30);status=authorized('status',identifier);seen.add(status['progress'])
                if status['state']!='running' or time.monotonic()>limit:break
            assert status['state']=='completed' and status['result']['status']=='prepared-not-rebooted',status
            assert status['result']['reboot_requested'] is False
            assert authorized('submit',identifier,plan['plan_sha256'])==status
            result={'job':status,'progress':sorted(seen)}
        elif mode=='completed':
            status=authorized('status','5'*32);assert status['state']=='completed'
            assert authorized('submit','5'*32,status['plan_sha256'])==status;result=status
        else:raise AssertionError('unknown mode')
        assert not errors and len(prompts)==len(calls),(errors,len(prompts),len(calls))
        print('ENZIMOS_UPDATE_API_CLIENT='+json.dumps({'mode':mode,'password_prompts':len(prompts),'fresh_authorization':True,'result':result}),flush=True)
    finally:
        print('ENZIMOS_UPDATE_API_AGENT\n'+transcript.decode(errors='replace'),flush=True);done.set();pump.join(2);os.close(reader)
        try:os.kill(agent,15)
        except ProcessLookupError:pass
        os.waitpid(agent,0);os.close(terminal);bus.close()


if __name__=='__main__':main(sys.argv[1])
