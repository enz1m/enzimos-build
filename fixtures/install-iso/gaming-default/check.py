# SPDX-License-Identifier: MIT
"""Verify a fresh image's actual gaming policy; no overlays or package installs."""
import hashlib
import json
from pathlib import Path
import subprocess
import time

CD = Path('/run/enzimos-testpayload')
USER = ['runuser', '-u', 'admin', '--', 'env', 'XDG_RUNTIME_DIR=/run/user/1000',
        'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus']

def run(argv):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, (argv, p.returncode, p.stderr[-1000:])
    return p.stdout

inventory = json.loads((CD / 'policy-hashes.json').read_text())
assert len(inventory) == 9
for relative, expected in inventory.items():
    assert relative.startswith('usr/') and '..' not in Path(relative).parts
    assert hashlib.sha256((Path('/') / relative).read_bytes()).hexdigest() == expected
assert run(['pacman', '-Q', 'steam-devices']).strip() == 'steam-devices 1.0.0.87-3'
for absent in ('steam', 'gamescope', 'linuxconsole'):
    assert subprocess.run(['pacman', '-Q', absent], capture_output=True).returncode != 0
assert Path('/sys/module/uinput').is_dir() and Path('/sys/module/joydev').is_dir()
assert 'input' not in run(['id', '-nG', 'admin']).split()
for unit in ('enzimos-backup', 'enzimos-scrub', 'enzimos-deferred', 'enzimos-home-history'):
    assert run(['systemctl', 'show', unit + '.service', '-p', 'Slice', '--value']).strip() == 'enzimosbackground.slice'
print('ENZIMOS_GAMING_DEFAULT_OK exact-nine-files-signed-controller-package-minimal-modules-and-system-slices', flush=True)
print('ENZIMOS_GAMING_DEFAULT_READY normal-admin-login', flush=True)
deadline = time.monotonic() + 600
while time.monotonic() < deadline:
    if not Path('/run/user/1000/bus').is_socket():
        time.sleep(.3)
        continue
    session = run(['loginctl', 'show-user', 'admin', '-p', 'Display', '--value']).strip()
    text = run(['loginctl', 'show-session', session, '-p', 'Active', '-p', 'Type']) if session else ''
    if 'Active=yes' in text and 'Type=wayland' in text and Path('/run/user/1000/bus').exists(): break
    time.sleep(.3)
else: raise AssertionError('normal login deadline')
assert run(USER + ['systemctl', '--user', 'show', 'background.slice', '-p', 'CPUWeight', '-p', 'IOWeight']).splitlines() == ['CPUWeight=20', 'IOWeight=10']
inference = run(USER + ['systemctl', '--user', 'show', 'enzimos-inference.service', '-p', 'Slice', '-p', 'Nice', '-p', 'IOSchedulingClass'])
assert 'Slice=background.slice' in inference and 'Nice=15' in inference and any(x in inference for x in ('IOSchedulingClass=idle', 'IOSchedulingClass=3'))
run(USER + ['python', '-c', "import os; f=os.open('/dev/uinput',os.O_WRONLY|os.O_NONBLOCK);os.close(f)"])
denied = subprocess.run(['runuser', '-u', 'nobody', '--', 'python', '-c', "import os;os.open('/dev/uinput',os.O_WRONLY|os.O_NONBLOCK)"], capture_output=True, text=True)
assert denied.returncode != 0 and 'PermissionError' in denied.stderr
check = json.loads(run(USER + ['enzimos-gaming-check']))
assert check['uinput_writable'] and check['ntsync_accessible'] and check['user_namespaces_available'] and not check['changes_made']
assert check['packages']['steam'] is None and not check['steam_flatpak_installed']
print(json.dumps(check), flush=True)
print('ENZIMOS_GAMING_DEFAULT_PASS', flush=True)
