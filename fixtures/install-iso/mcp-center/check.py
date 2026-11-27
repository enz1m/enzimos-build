# SPDX-License-Identifier: MIT
"""Installed-package/user-service/adapter qualification in a disposable guest."""
import hashlib,json,pwd,select,stat,subprocess,time
from pathlib import Path
expected=json.loads(Path('/run/enzimos-testpayload/expected-build.json').read_text())
for rel,identity in expected['files'].items():
    p=Path('/')/rel;assert hashlib.sha256(p.read_bytes()).hexdigest()==identity['sha256']
    assert stat.S_IMODE(p.stat().st_mode)==identity['mode']
expected_version=f'enzui-mcp-center {expected["version"]}-{expected["release"]}'
assert subprocess.check_output(['pacman','-Q','enzui-mcp-center'],text=True).strip()==expected_version
uid=pwd.getpwnam('admin').pw_uid
assert Path('/home/admin/.config/systemd/user/default.target.wants/enzui-center.service').is_symlink()
subprocess.run(['systemctl','start',f'user@{uid}.service'],check=True)
env=['runuser','-u','admin','--','env',f'XDG_RUNTIME_DIR=/run/user/{uid}',f'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus','HOME=/home/admin','XDG_STATE_HOME=/home/admin/.local/state']
sock=Path(f'/run/user/{uid}/enzui/center.sock')
control=Path('/home/admin/.local/state/enzui/control.credential.json')
for _ in range(30):
    if sock.exists() and control.exists() and subprocess.run(env+['systemctl','--user','is-active','--quiet','enzui-center.service']).returncode==0:break
    time.sleep(1)
else:
    subprocess.run(env+['journalctl','--user','--no-pager','-n','25','-u','enzui-center.service'])
    raise AssertionError('user broker did not become ready')
sock=Path(f'/run/user/{uid}/enzui/center.sock');assert stat.S_IMODE(sock.stat().st_mode)==0o600 and sock.stat().st_uid==uid
assert stat.S_IMODE(sock.parent.stat().st_mode)==0o700
control=Path('/home/admin/.local/state/enzui/control.credential.json');assert control.stat().st_uid==uid and stat.S_IMODE(control.stat().st_mode)==0o600
subprocess.run(env+['enzui-center','credentials'],check=True,stdout=subprocess.DEVNULL)
assistant=control.parent/'agents/dev.enzui.Assistant.credential.json'
assert assistant.stat().st_uid==uid and stat.S_IMODE(assistant.stat().st_mode)==0o600
assert not Path('/home/admin/.config/enzui/agents/dev.enzui.Assistant.credential.json').exists()
assistant_identity=hashlib.sha256(assistant.read_bytes()).hexdigest()
p=subprocess.Popen(env+['enzui-mcp','--credential',str(assistant)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
def send(body):p.stdin.write(json.dumps(body)+'\n');p.stdin.flush()
send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'fixture','version':'1'}}})
assert select.select([p.stdout],[],[],10)[0], 'MCP response timeout'
r=json.loads(p.stdout.readline());assert r['id']==1 and 'result' in r
send({'jsonrpc':'2.0','method':'notifications/initialized'})
send({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})
assert select.select([p.stdout],[],[],10)[0], 'MCP response timeout'
r=json.loads(p.stdout.readline());assert {t['name'] for t in r['result']['tools']}=={'enzui_apps','enzui_functions','enzui_function','enzui_call'}
send({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'enzui_apps','arguments':{}}})
assert select.select([p.stdout],[],[],10)[0], 'MCP app discovery timeout'
r=json.loads(p.stdout.readline());assert r['id']==3 and 'result' in r and not r['result'].get('isError')
p.stdin.close();assert p.wait(timeout=10)==0
control_identity=hashlib.sha256(control.read_bytes()).hexdigest()
subprocess.run(env+['systemctl','--user','restart','enzui-center.service'],check=True)
time.sleep(1)
subprocess.run(env+['enzui-center','credentials'],check=True,stdout=subprocess.DEVNULL)
assert hashlib.sha256(control.read_bytes()).hexdigest()==control_identity
assert hashlib.sha256(assistant.read_bytes()).hexdigest()==assistant_identity
print('ENZIMOS_MCP_CENTER_PASS',flush=True)
