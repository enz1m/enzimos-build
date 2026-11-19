#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Ordinary-user real system-bus/polkit guest probe; only public LAB credentials."""
import json
import os
from pathlib import Path
import select
import pty
import threading
import time
import termios
import subprocess
import sys
import dbus
import dbus.bus
import dbus.lowlevel

BUS_NAME = 'org.enzimos.System1'
PATH = '/org/enzimos/System1'
REQUEST = {'schema': 1, 'operation': 'home-history-create', 'allow_interaction': False}


def main(mode):
    assert os.getuid() == os.geteuid() == (1001 if mode == 'deny-user' else 1000)
    bus = dbus.bus.BusConnection('unix:path=/run/dbus/system_bus_socket')
    assert bus.get_unix_user(bus.get_name_owner(BUS_NAME)) == 0
    def call(body, member='Execute', signature='s'):
        message = dbus.lowlevel.MethodCallMessage(BUS_NAME, PATH, BUS_NAME, member)
        if signature:message.append(body, signature=signature)
        return json.loads(bus.send_message_with_reply_and_block(message, 120).get_args_list()[0])
    def denied(body, expected, **kw):
        try:call(body, **kw)
        except dbus.DBusException as exc:
            assert exc.get_dbus_name() == BUS_NAME+'.Refused', exc
            assert exc.get_dbus_message() == expected, exc
            assert 'Traceback' not in str(exc), exc
        else:raise AssertionError('refused API request succeeded')
    caps = call(None, 'GetCapabilities', '')
    assert caps['runtime_qualified'] is False and caps['arbitrary_command_or_path'] is False
    denied(json.dumps(REQUEST), 'not-authorized')
    denied(json.dumps(dict(REQUEST, uid=0)), 'request-fields')
    denied(7, 'wire-signature', signature='i')
    if mode.startswith('deny'):
        denied(json.dumps(dict(REQUEST, allow_interaction=True)), 'not-authorized')
        print('ENZIMOS_API_CLIENT='+json.dumps({'mode': mode, 'denied': True, 'malformed_refused': True}), flush=True)
        return
    # systemd-run/PAM creates a real logind session. No polkit rule is injected.
    session = os.environ.get('XDG_SESSION_ID')
    assert session, 'missing real logind session'
    props = subprocess.check_output(['loginctl', 'show-session', session, '-p', 'Active', '-p', 'Remote', '-p', 'User', '-p', 'Seat', '-p', 'VTNr'], text=True)
    print('ENZIMOS_API_SESSION '+props.replace('\n', ' '), flush=True)
    assert 'Active=yes' in props and 'Remote=no' in props and 'User=1000' in props and 'Seat=seat0' in props and 'VTNr=2' in props, props
    pid = os.getpid();start = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19]
    reader, writer = os.pipe()
    agent, terminal = pty.fork()
    if agent == 0:
        os.set_inheritable(writer, True)
        os.execvp('pkttyagent', ['pkttyagent', '--process', f'{pid},{start}', '--notify-fd', str(writer)])
    os.close(writer)
    transcript = bytearray();prompts = [];errors = [];done = threading.Event()
    def answer():
        try:
            while not done.is_set():
                if not select.select([terminal], [], [], 0.1)[0]:continue
                try:data = os.read(terminal, 4096)
                except OSError:return
                if not data:return
                transcript.extend(data)
                assert len(transcript) < 65536, 'agent transcript bound'
                count = transcript.count(b'Password:')
                if count > len(prompts):
                    limit = time.monotonic()+5
                    while termios.tcgetattr(terminal)[3] & termios.ECHO and time.monotonic() < limit:time.sleep(0.02)
                    assert not termios.tcgetattr(terminal)[3] & termios.ECHO, 'agent password echo'
                    os.write(terminal, b'\x03' if mode == 'cancel' else b'ENZIMOS-PUBLIC-LAB-ADMIN\n');prompts.append(count)
        except Exception as exc:errors.append(str(exc))
    pump = threading.Thread(target=answer);pump.start()
    try:
        assert select.select([reader], [], [], 45)[0] and os.read(reader, 1) == b'', 'agent registration failed'
        print('ENZIMOS_API_AGENT_READY', flush=True)
        shots = []
        job_result = None
        for _ in range(2 if mode == 'allow' else 1):
            body = json.dumps(dict(REQUEST, allow_interaction=True))
            if mode.startswith('jobs-'):
                identifier = ('a' if mode in ('jobs-submit', 'jobs-repeat') else 'b')*32
                job_body = json.dumps({'schema':2,'operation':'home-history-create','action':'status' if mode=='jobs-status' else 'submit',
                                       'request_id':identifier,'allow_interaction':True})
                if mode in ('jobs-locked','jobs-retry'):denied(job_body,'job-result-uncertain-no-replay',member='Job')
                else:
                    job_result=call(job_body,'Job');assert job_result['schema']==2 and job_result['request_id']==identifier
                    assert job_result['state']==('uncertain' if mode=='jobs-status' else 'completed')
            elif mode == 'cancel':denied(body, 'not-authorized')
            elif mode == 'locked':denied(body, 'backend-result-unknown-do-not-retry-automatically')
            else:
                reply = call(body);assert reply['status'] == 'completed' and type(reply['snapshot']) is int
                shots.append(reply['snapshot'])
            # auth_admin (not auth_admin_keep) must not leave a noninteractive grant.
            denied(json.dumps(REQUEST), 'not-authorized')
        assert len(set(shots)) == len(shots)
        assert not errors and len(prompts) == (2 if mode == 'allow' else 1), (errors, len(prompts))
        print('ENZIMOS_API_CLIENT='+json.dumps({'mode': mode, 'snapshots': shots, 'active_local_admin': True,
              'no_retained_authorization': True, 'password_prompts': len(prompts), 'lock_refused': mode == 'locked', 'authentication_cancelled': mode == 'cancel', 'job_result':job_result}), flush=True)
    finally:
        print('ENZIMOS_API_AGENT_TRANSCRIPT\n'+transcript.decode(errors='replace'), flush=True)
        done.set();pump.join(timeout=2);os.close(reader)
        try:os.kill(agent, 15)
        except ProcessLookupError:pass
        os.waitpid(agent, 0);os.close(terminal);bus.close()


if __name__ == '__main__':
    assert len(sys.argv) == 2 and sys.argv[1] in ('deny-user', 'deny-admin', 'allow', 'locked', 'cancel', 'jobs-submit', 'jobs-repeat', 'jobs-locked', 'jobs-status', 'jobs-retry')
    main(sys.argv[1])
