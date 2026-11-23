# SPDX-License-Identifier: MIT
"""Real greetd login, installed compositor/plugin and polkit agent qualification."""
import hashlib,json,os,subprocess,time,pwd
from pathlib import Path
ROOT=Path('/usr/share/enzui')
report=json.loads((ROOT/'manifest.json').read_text())
adapters=json.loads((ROOT/'os-integration.json').read_text())['adapter_hashes']
for row in report['files']:
    rel=row['path'].lstrip('/')
    if rel in adapters:continue
    p=Path('/')/rel
    assert hashlib.sha256(p.read_bytes()).hexdigest()==row['sha256'], rel
for rel,digest in adapters.items():assert hashlib.sha256((Path('/')/rel).read_bytes()).hexdigest()==digest,rel
BIN=Path(report['layout']['bin'])
comp=Path(report['layout']['compositor'])
for rel,digest in json.loads((ROOT/'os-integration.json').read_text())['compatibility_libraries'].items():assert hashlib.sha256((Path('/')/rel).read_bytes()).hexdigest()==digest
for binary in [*(BIN.iterdir()),*(Path(report['layout']['apps']).iterdir()),next(p for p in (comp/'hyprland-current-build/enz-hyprland',comp/'hyprland-current-build/Hyprland') if p.exists())]:
    if binary.read_bytes()[:4]!=b'\x7fELF':continue
    links=subprocess.run(['ldd',str(binary)],env={**os.environ,'LD_LIBRARY_PATH':str(comp/'prefix/lib')},capture_output=True,text=True)
    assert links.returncode==0 and 'not found' not in links.stdout+links.stderr,(str(binary),links.stdout,links.stderr)

def wait(label,check,limit=120):
    for _ in range(limit):
        if check():return
        time.sleep(1)
    raise AssertionError(label)
def alive(name,user):
    uid=pwd.getpwnam(user).pw_uid
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():continue
        try:
            if proc.stat().st_uid==uid and (proc/'exe').resolve()==BIN/name:return True
        except (FileNotFoundError,PermissionError,ProcessLookupError):pass
    return False
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
assert ctl('--batch','repl return hl.plugin and hl.plugin.enzui_sidebar_scene ~= nil or false').strip()=='true'
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
apps = set(subprocess.check_output(
    ['flatpak', 'list', '--system', '--app', '--columns=application'], text=True
).splitlines())
selection = Path('/usr/share/enzimos')
declared = set((selection / 'default-flatpaks.txt').read_text().split())
if (selection / 'enzimos-flatpaks.txt').is_file():
    declared.update((selection / 'enzimos-flatpaks.txt').read_text().split())
assert apps == declared and 'app.zen_browser.zen' in apps, (apps, declared)

session_mime_env = [
    line for line in env.splitlines()
    if line.startswith(('XDG_CURRENT_DESKTOP=', 'XDG_DATA_DIRS='))
]
assert len(session_mime_env) == 2, session_mime_env
browser = 'org.enzim.Browser' if 'org.enzim.Browser' in apps else 'app.zen_browser.zen'
video = 'io.github.enzui.Video' if 'io.github.enzui.Video' in apps else 'org.enzimos.Photos'
for app, types in (
    (browser, ('x-scheme-handler/http', 'x-scheme-handler/https', 'text/html', 'application/xhtml+xml')),
    ('io.github.enzui.Mail', ('x-scheme-handler/mailto',)),
    ('io.github.enzui.Calendar', ('text/calendar',)),
    ('io.github.enzui.Reader', ('application/pdf', 'application/epub+zip')),
    ('io.github.enzui.Music', ('audio/ogg', 'audio/flac')),
    ('org.enzimos.Photos', ('image/png', 'image/avif')),
    (video, ('video/mp4', 'video/webm')),
    ('io.github.enzui.Remote', ('application/x-rdp',)),
):
    if app not in apps:
        continue
    desktop = app + '.desktop'
    assert (Path('/var/lib/flatpak/exports/share/applications') / desktop).is_file(), desktop
    for mime in types:
        default = subprocess.check_output(
            ['runuser', '-u', 'admin', '--', 'env', *session_mime_env, 'xdg-mime', 'query', 'default', mime],
            text=True,
        ).strip()
        assert default == desktop, (mime, desktop, default)
units=subprocess.check_output(['runuser','-u','admin','--','env','XDG_RUNTIME_DIR=/run/user/1000','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus','systemctl','--user','list-units','--no-legend','enzui-platform-desktop-*.service'],text=True)
assert 'running' in units,units
ctl('dispatch','hl.dsp.exec_cmd('+json.dumps('flatpak run app.zen_browser.zen --no-remote about:blank')+')')
wait('Zen browser missing',lambda:'zen' in ctl('-j','clients').lower(),limit=120)
print('ENZIMOS_DESKTOP_APP_UP',flush=True)
time.sleep(30)
print('ENZIMOS_ZEN_PORTAL_REVIEW_READY',flush=True)
wait('native browser portal missing',lambda:'dev.enzui.FileChooser' in ctl('-j','clients'),limit=300)
print('ENZIMOS_ZEN_NATIVE_PORTAL_UP',flush=True)
wait('native browser portal close',lambda:'dev.enzui.FileChooser' not in ctl('-j','clients'),limit=300)
ctl('dispatch','hl.dsp.exec_cmd('+json.dumps('ENZUI_SETTINGS_PAGE=agents/permissions enzui-settings')+')')
wait('Settings missing',lambda:alive('enzui-settings','admin'))
print('ENZIMOS_SETTINGS_AGENTS_UP',flush=True)
wait('interactive review completion',lambda:Path('/home/admin/zen-reviewed').exists(),limit=600)
print('ENZIMOS_DESKTOP_ZEN_PASS',flush=True)
