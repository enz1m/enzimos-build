# SPDX-License-Identifier: MIT
"""Real greetd login, installed compositor/plugin and polkit agent qualification."""
import hashlib,json,os,subprocess,time
from pathlib import Path
ROOT=Path('/usr/share/enzui')
report=json.loads((ROOT/'desktop-snapshot.json').read_text())
for name,identity in report['binaries'].items():
    assert hashlib.sha256((ROOT/'bin'/name).read_bytes()).hexdigest()==identity
assert hashlib.sha256((ROOT/'bin/Hyprland').read_bytes()).hexdigest()==report['compositor_sha256']
assert hashlib.sha256((ROOT/'plugins/enzui-pointer-events.so').read_bytes()).hexdigest()==report['plugin_sha256']
def wait(label,check,limit=120):
    for _ in range(limit):
        if check():return
        time.sleep(1)
    raise AssertionError(label)
def alive(name,user):
    return subprocess.run(['pgrep','-u',user,'-f',str(ROOT/'bin'/name)],stdout=subprocess.DEVNULL).returncode==0
wait('greeter missing',lambda:alive('enzui-greeter','greeter'))
print('ENZIMOS_DESKTOP_GREETER_UP',flush=True)
wait('desktop login missing',lambda:alive('enzui-shell','admin'),limit=180)
print('ENZIMOS_DESKTOP_SESSION_UP',flush=True)
wait('polkit agent missing',lambda:alive('enzui-polkit-agent','admin'))
wait('wallpaper missing',lambda:alive('enzui-wallpaper','admin'))
instances=list(Path('/run/user/1000/hypr').glob('*'))
assert len(instances)==1
instance=instances[0].name
def ctl(*args):
    return subprocess.check_output(['runuser','-u','admin','--','env','XDG_RUNTIME_DIR=/run/user/1000',f'HYPRLAND_INSTANCE_SIGNATURE={instance}','/usr/bin/hyprctl',*args],text=True)
assert report['pointer_plugin_functional_in_installed_session'] is False
assert ctl('--batch','repl return hl.plugin and hl.plugin.enzui_sidebar_scene ~= nil or false').strip()=='false'
time.sleep(8)
assert 'Authentication' not in ctl('-j','clients')
status='/home/admin/.local/state/enzui/auth-fixture-status'
command=f"pkexec /usr/bin/true; printf '%s\\n' \"$?\" > {status}"
ctl('dispatch','hl.dsp.exec_cmd('+json.dumps(command)+')')
wait('polkit dialog missing',lambda:'dev.enzui.Authentication' in ctl('-j','clients'))
print('ENZIMOS_DESKTOP_AUTH_UP',flush=True)
wait('polkit approval missing',lambda:Path(status).exists() and Path(status).stat().st_size>0,limit=150)
assert Path(status).read_text().strip()=='0'
print('ENZIMOS_DESKTOP_AUTH_PASS',flush=True)
# Environment inherited by systemd/D-Bus activation must target this compositor.
env=subprocess.check_output(['runuser','-u','admin','--','env','XDG_RUNTIME_DIR=/run/user/1000','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus','systemctl','--user','show-environment'],text=True)
assert f'HYPRLAND_INSTANCE_SIGNATURE={instance}' in env and 'WAYLAND_DISPLAY=' in env
print('ENZIMOS_DESKTOP_REFRESH_PASS',flush=True)
