#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""TEST client: the Settings app's use of org.enzimos.System1 (Query + schemas 25-27)."""
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
NAME = 'org.enzimos.System1';PATH = '/org/enzimos/System1';PASSWORD = b'ENZIMOS-PUBLIC-TEST-ADMIN\n'


def call(bus, member, body):
    message = dbus.lowlevel.MethodCallMessage(NAME, PATH, NAME, member);message.append(body, signature='s')
    return json.loads(bus.send_message_with_reply_and_block(message, 180).get_args_list()[0])


def refused(bus, member, body):
    try:call(bus, member, body)
    except dbus.DBusException as exc:return exc.get_dbus_message()
    raise AssertionError('request did not refuse')


def denied():
    bus = dbus.SystemBus()
    reason = refused(bus, 'Query', json.dumps({'schema': 1, 'query': 'system'}))
    assert reason == 'not-authorized', reason
    print('ENZIMOS_SETTINGS_DENIED_PASS', reason, flush=True)


def admin():
    bus = dbus.SystemBus();results = {}
    # Read-only queries activate the backend without administrator authorization.
    for query in ('system', 'history', 'backups', 'network-trust'):
        results[query] = call(bus, 'Query', json.dumps({'schema': 1, 'query': query}))['result']
    system = results['system']
    assert system['packages']['enzimos-native-policy'] and system['packages']['enzimos-system-backend'] and system['firmware'] in ('uefi', 'bios'), system
    assert results['history']['home_history']['enabled'] is True and results['backups']['local_configured'] is False, results
    uuid = Path('/run/enzimos-test-lan.uuid').read_text().strip()
    lan = [row for row in results['network-trust']['connections'] if row['connection'] == uuid]
    assert len(lan) == 1 and lan[0]['trusted'] is False, results['network-trust']
    print('ENZIMOS_SETTINGS_QUERIES', json.dumps({'packages': system['packages'], 'generations': len(system['generations']),
          'recovery_images_ready': system['recovery_images_ready'], 'history': results['history']['home_history']}), flush=True)
    # Bind the authorization agent to this process identity, including its start time.
    pid = os.getpid();start = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19]
    reader, writer = os.pipe();agent, terminal = pty.fork()
    if agent == 0:
        os.set_inheritable(writer, True);os.execvp('pkttyagent', ['pkttyagent', '--process', f'{pid},{start}', '--notify-fd', str(writer)])
    os.close(writer);prompts = [];transcript = bytearray();done = threading.Event()
    def answer():
        while not done.is_set():
            if not select.select([terminal], [], [], .1)[0]:continue
            try:data = os.read(terminal, 4096)
            except OSError:return
            if not data:return
            transcript.extend(data)
            if transcript.count(b'Password:') > len(prompts):
                limit = time.monotonic()+5
                while termios.tcgetattr(terminal)[3] & termios.ECHO and time.monotonic() < limit:time.sleep(.02)
                os.write(terminal, PASSWORD);prompts.append(1)
    pump = threading.Thread(target=answer);pump.start()
    try:
        assert select.select([reader], [], [], 45)[0] and os.read(reader, 1) == b''
        def job(version, operation, identifier, selection):
            body = lambda action, digest=None: json.dumps({'schema': version, 'operation': operation, 'action': action, 'request_id': identifier, 'plan_sha256': digest,
                                                           'allow_interaction': True, 'selection': selection if action == 'plan' else None})
            plan = call(bus, 'Operation', body('plan'));queued = call(bus, 'Operation', body('submit', plan['plan_sha256']))
            assert queued['state'] == 'queued', queued
            for _ in range(120):
                time.sleep(1);value = call(bus, 'Operation', body('status'))
                if value['state'] not in ('queued', 'running'):break
            assert value['state'] == 'completed', value
            return value['result']
        trusted = job(25, 'network-trust-set', 'a1'*16, {'connection': uuid, 'trusted': True})
        assert trusted['trusted'] is True and trusted['zone'] == 'enzimos-trusted', trusted
        after = call(bus, 'Query', json.dumps({'schema': 1, 'query': 'network-trust'}))['result']
        assert [r['trusted'] for r in after['connections'] if r['connection'] == uuid] == [True], after
        paused = job(26, 'home-history-set', 'a2'*16, {'enabled': False});assert paused['enabled'] is False, paused
        assert call(bus, 'Query', json.dumps({'schema': 1, 'query': 'history'}))['result']['home_history']['enabled'] is False
        resumed = job(26, 'home-history-set', 'a3'*16, {'enabled': True});assert resumed['enabled'] is True, resumed
        untrusted = job(25, 'network-trust-set', 'a4'*16, {'connection': uuid, 'trusted': False});assert untrusted['trusted'] is False, untrusted
        # No backup destination is configured on a fresh install: opting in refuses at planning.
        body = json.dumps({'schema': 27, 'operation': 'backup-schedule-set', 'action': 'plan', 'request_id': 'a5'*16, 'plan_sha256': None, 'allow_interaction': True, 'selection': {'enabled': True}})
        reason = refused(bus, 'Operation', body);assert reason == 'job-plan-changed', reason
        assert 1 <= len(prompts) <= 4, ('one password prompt per change at most', len(prompts))
        print('ENZIMOS_SETTINGS_CLIENT_PASS', json.dumps({'password_prompts': len(prompts), 'network_trust': [trusted, untrusted], 'home_history': [paused, resumed],
              'backup_schedule_without_destination': reason}), flush=True)
    finally:
        done.set();pump.join(2);os.close(reader)
        try:os.kill(agent, 15)
        except ProcessLookupError:pass
        os.waitpid(agent, 0);os.close(terminal)


if __name__ == '__main__':
    {'denied': denied, 'admin': admin}[sys.argv[1]]()
