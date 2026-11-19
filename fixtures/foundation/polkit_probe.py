#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Unprivileged, explicitly registered text agent for a bounded guest test."""
import os
from pathlib import Path
import select
import subprocess
import sys

if os.getuid()!=1000 or os.geteuid()!=1000:
    raise RuntimeError('fixture agent must run as the ordinary admin, not root')
pid=os.getpid()
start=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]
reader,writer=os.pipe()
agent=subprocess.Popen(['pkttyagent','--process',f'{pid},{start}','--notify-fd',str(writer)],pass_fds=(writer,))
os.close(writer)
try:
    if not select.select([reader],[],[],45)[0] or os.read(reader,1)!=b'':
        raise RuntimeError('text agent registration did not finish')
    if agent.poll() is not None:raise RuntimeError('text agent exited during registration')
    print('ENZIMOS_POLKIT_REGISTERED_AGENT_READY',flush=True)
    result=subprocess.run(['pkexec','--disable-internal-agent','/usr/bin/id','-u'],stdin=subprocess.DEVNULL)
    raise SystemExit(result.returncode)
finally:
    os.close(reader)
    agent.terminate()
    try:agent.wait(timeout=5)
    except subprocess.TimeoutExpired:agent.kill();agent.wait(timeout=5)
