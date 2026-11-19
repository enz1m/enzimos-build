#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real system-bus backup client, public LAB password in active seat0/VT2 only."""
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

NAME='org.enzimos.System1';PATH='/org/enzimos/System1';ID='d'*32


def main(mode):
    assert os.getuid()==os.geteuid()==(1001 if mode=='deny-user' else 1000)
    bus=dbus.bus.BusConnection('unix:path=/run/dbus/system_bus_socket')
    assert bus.get_unix_user(bus.get_name_owner(NAME))==0
    calls=[]
    def request(action,identifier=ID,digest=None,interactive=False,**extra):
        value=dict(schema=3,operation='backup-create',action=action,request_id=identifier,plan_sha256=digest,allow_interaction=interactive,**extra)
        return json.dumps(value)
    def call(body):
        message=dbus.lowlevel.MethodCallMessage(NAME,PATH,NAME,'Operation');message.append(body,signature='s')
        return json.loads(bus.send_message_with_reply_and_block(message,120).get_args_list()[0])
    def denied(body,reason):
        try:call(body)
        except dbus.DBusException as exc:
            assert exc.get_dbus_name()==NAME+'.Refused' and exc.get_dbus_message()==reason,exc
            assert 'Traceback' not in str(exc)
        else:raise AssertionError('expected refusal')
    denied(request('plan'),'not-authorized');denied(request('plan',uid=0),'request-fields')
    if mode.startswith('deny'):
        denied(request('plan',interactive=True),'not-authorized')
        print('ENZIMOS_BACKUP_API_CLIENT='+json.dumps({'mode':mode,'denied':True}),flush=True);return
    session=os.environ.get('XDG_SESSION_ID');assert session
    properties=subprocess.check_output(['loginctl','show-session',session,'-p','Active','-p','Remote','-p','User','-p','Seat','-p','VTNr'],text=True)
    assert all(value in properties for value in ('Active=yes','Remote=no','User=1000','Seat=seat0','VTNr=2')),properties
    pid=os.getpid();start=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]
    reader,writer=os.pipe();agent,terminal=pty.fork()
    if agent==0:
        os.set_inheritable(writer,True);os.execvp('pkttyagent',['pkttyagent','--process',f'{pid},{start}','--notify-fd',str(writer)])
    os.close(writer);transcript=bytearray();prompts=[];errors=[];done=threading.Event()
    def answer():
        try:
            while not done.is_set():
                if not select.select([terminal],[],[],0.1)[0]:continue
                try:body=os.read(terminal,4096)
                except OSError:return
                if not body:return
                transcript.extend(body);assert len(transcript)<131072
                number=transcript.count(b'Password:')
                if number>len(prompts):
                    limit=time.monotonic()+5
                    while termios.tcgetattr(terminal)[3]&termios.ECHO and time.monotonic()<limit:time.sleep(.02)
                    assert not termios.tcgetattr(terminal)[3]&termios.ECHO
                    os.write(terminal,b'\x03' if mode=='auth-cancel' else b'ENZIMOS-PUBLIC-LAB-ADMIN\n');prompts.append(number)
        except Exception as exc:errors.append(type(exc).__name__)
    pump=threading.Thread(target=answer);pump.start()
    try:
        assert select.select([reader],[],[],45)[0] and os.read(reader,1)==b''
        def authorized(action,identifier=ID,digest=None,expected=None):
            body=request(action,identifier,digest,True)
            if expected is not None:denied(body,expected);reply=None
            else:reply=call(body)
            calls.append(action)
            denied(request('status',identifier),'not-authorized')
            return reply
        result={}
        if mode=='locked-session':
            # Parent fixture changes the actual logind LockedHint after the
            # ordinary client/agent is ready, without granting policy exceptions.
            print('ENZIMOS_BACKUP_API_LOCK_READY '+session,flush=True)
            limit=time.monotonic()+30
            while subprocess.check_output(['loginctl','show-session',session,'-p','LockedHint','--value'],text=True).strip()!='yes' and time.monotonic()<limit:time.sleep(.1)
            assert subprocess.check_output(['loginctl','show-session',session,'-p','LockedHint','--value'],text=True).strip()=='yes'
            denied(request('plan',interactive=True),'not-authorized');result={'locked_session_refused':True}
        elif mode=='disconnect-auth':
            other=dbus.bus.BusConnection('unix:path=/run/dbus/system_bus_socket')
            message=dbus.lowlevel.MethodCallMessage(NAME,PATH,NAME,'Operation');message.append(request('plan','6'*32,interactive=True),signature='s')
            other.send_message(message);other.flush();other.close();time.sleep(3);result={'disconnected_before_reply':True}
        elif mode=='kill-submit':
            plan=authorized('plan','7'*32);result=authorized('submit','7'*32,plan['plan_sha256']);assert result['state']=='queued'
            print('ENZIMOS_BACKUP_API_KILL_SUBMITTED',flush=True)
        elif mode=='kill-review':
            result=authorized('status','7'*32);assert result['state']=='uncertain'
            authorized('submit','7'*32,result['plan_sha256'],expected='job-transition-refused')
        elif mode=='auth-cancel':authorized('plan',expected='not-authorized')
        elif mode=='plan-cancel':
            planned=authorized('plan');assert planned['state']=='planned' and 'plan' not in planned
            assert authorized('status')['state']=='planned'
            authorized('submit',digest='0'*64,expected='job-plan-changed')
            cancelled=authorized('cancel',digest=planned['plan_sha256']);assert cancelled['state']=='cancelled'
            authorized('submit',digest=planned['plan_sha256'],expected='job-transition-refused')
        elif mode=='run':
            identifier='e'*32
            planned=authorized('plan',identifier);competitor=authorized('plan','f'*32)
            result=authorized('submit',identifier,planned['plan_sha256']);assert result['state']=='queued'
            # A worker starts after the queued result; cancellation refuses once
            # backend entry is durably recorded, rather than claiming rollback.
            time.sleep(2);status=authorized('status',identifier);assert status['state']=='running',status
            authorized('cancel',identifier,planned['plan_sha256'],expected='job-transition-refused')
            authorized('submit','f'*32,competitor['plan_sha256'],expected='service-busy')
            seen={status['progress']};limit=time.monotonic()+1250
            while status['state']=='running' and time.monotonic()<limit:
                time.sleep(30);status=authorized('status',identifier);seen.add(status['progress'])
            assert status['state']=='completed',status
            repeated=authorized('submit',identifier,planned['plan_sha256']);assert repeated==status
            result={'completed':status,'observed_progress':sorted(seen),'no_duplicate_submission':True}
        elif mode=='completed':
            status=authorized('status','e'*32);assert status['state']=='completed'
            assert authorized('submit','e'*32,status['plan_sha256'])==status;result=status
        else:raise AssertionError('unknown mode')
        assert not errors and len(prompts)==len(calls),(errors,len(prompts),calls)
        print('ENZIMOS_BACKUP_API_CLIENT='+json.dumps({'mode':mode,'password_prompts':len(prompts),'fresh_authorization':True,'result':result}),flush=True)
    finally:
        print('ENZIMOS_BACKUP_API_AGENT\n'+transcript.decode(errors='replace'),flush=True)
        done.set();pump.join(2);os.close(reader)
        try:os.kill(agent,15)
        except ProcessLookupError:pass
        os.waitpid(agent,0);os.close(terminal);bus.close()


if __name__=='__main__':main(sys.argv[1])
