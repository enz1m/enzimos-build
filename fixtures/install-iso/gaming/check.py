# SPDX-License-Identifier: MIT
"""Explicit installed gaming fixture; no host or physical hardware claims."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time

CD = Path('/run/enzimos-testpayload')
LAB = Path('/var/tmp/enzimos-gaming-lab')
USER = ['runuser', '-u', 'admin', '--', 'env', 'XDG_RUNTIME_DIR=/run/user/1000',
        'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus']
children = []


def run(argv, timeout=90):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    assert result.returncode == 0, (Path(argv[0]).name, result.returncode, result.stderr[-3000:])
    return result.stdout


def wait(predicate, seconds=600):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate(): return
        time.sleep(.2)
    raise AssertionError('readiness deadline')


def mark(value):
    print('ENZIMOS_GAMING_OK ' + value, flush=True)


try:
    all_modes = ['native', 'flatpak', 'proton', 'load']
    modes = json.loads((CD / 'modes.json').read_text()) if (CD / 'modes.json').is_file() else all_modes
    assert isinstance(modes, list) and modes and len(set(modes)) == len(modes) and all(m in all_modes + ['steam-native', 'steam-flatpak'] for m in modes)
    display = json.loads((CD / 'flatpak-display.json').read_text()) if (CD / 'flatpak-display.json').is_file() else None
    assert display in (None, 'x11')
    print('ENZIMOS_GAMING_SELECTED_MODES ' + json.dumps(modes), flush=True)
    LAB.mkdir(mode=0o755)
    inventory = json.loads((CD / 'package-inventory.json').read_text())
    packages = []
    for row in inventory:
        p = CD / 'packages' / row['filename']
        assert hashlib.sha256(p.read_bytes()).hexdigest() == row['sha256']
        packages.append(str(p))
    run(['pacman', '--noconfirm', '-U', '--needed', *packages], timeout=240)
    overlay = CD / 'os-integration'
    for p in overlay.rglob('*'):
        if p.is_file():
            target = Path('/') / p.relative_to(overlay)
            assert not target.is_symlink()
            if (CD / 'policy-already-installed').is_file():
                assert hashlib.sha256(target.read_bytes()).hexdigest() == hashlib.sha256(p.read_bytes()).hexdigest()
            else:
                target.parent.mkdir(parents=True, exist_ok=True); shutil.copy2(p, target)
    run(['systemctl', 'daemon-reload'])
    run(['modprobe', 'uinput']); run(['modprobe', 'joydev'])
    run(['udevadm', 'control', '--reload'])
    run(['udevadm', 'trigger', '--subsystem-match=misc'])
    rule = Path('/usr/lib/udev/rules.d/60-steam-input.rules').read_text()
    assert 'MODE="0666"' not in rule and 'TAG+="uaccess"' in rule and 'KERNEL=="uinput"' in rule
    run(['udevadm', 'verify', '/usr/lib/udev/rules.d/60-steam-input.rules'])
    run(['systemd-analyze', 'verify', '/usr/lib/systemd/system/enzimosbackground.slice'])
    assert 'gamemode' in run(['id', '-nG', 'admin']).split()
    assert 'input' not in run(['id', '-nG', 'admin']).split()
    mark('signed-device-rules-modules-and-no-input-group')
    print(run(['gamescope', '--version']), flush=True)
    mark('optional-gamescope-version-executable')
    # Normal remote definition/signatures and offline collection lookup, exactly
    # as used by the installer. This optional fixture is never a default app.
    run(['flatpak', 'remote-add', '--system', '--if-not-exists', 'flathub', str(CD / 'flathub.flatpakrepo')])
    run(['flatpak', 'remote-modify', '--system', '--collection-id=org.flathub.Stable', 'flathub'])
    run(['flatpak', 'install', '--system', '--noninteractive', '--sideload-repo=' + str(CD / 'steam-repo'), 'flathub', 'com.valvesoftware.Steam'], timeout=480)
    assert run(['flatpak', 'info', '--show-commit', 'com.valvesoftware.Steam']).strip() == (CD / 'steam-commit').read_text().strip()
    mark('actual-signed-native-steam-and-flatpak-install')
    # Offline app installation can omit optional related graphics extensions.
    # Require the signed default Mesa pair in this CPU/virtual-GPU fixture;
    # these remain Steam test dependencies, never default OS gaming apps.
    runtime = run(['flatpak', 'info', '--system', '--show-runtime', 'com.valvesoftware.Steam']).strip().split('/')
    assert len(runtime) == 3 and runtime[:2] == ['org.freedesktop.Platform', 'x86_64'], runtime
    branch = runtime[2]
    for extension in ('org.freedesktop.Platform.GL.default', 'org.freedesktop.Platform.GL32.default'):
        pin = CD / 'steam-repo/refs/mirrors/org.flathub.Stable/runtime' / extension / 'x86_64' / branch
        assert pin.is_file() and not pin.is_symlink(), pin
        expected = pin.read_text().strip()
        assert len(expected) == 64 and all(c in '0123456789abcdef' for c in expected)
        run(['flatpak', 'install', '--system', '--noninteractive', '--sideload-repo=' + str(CD / 'steam-repo'), 'flathub', extension + '//' + branch], timeout=480)
        assert run(['flatpak', 'info', '--system', '--show-commit', extension + '//' + branch]).strip() == expected
    mark('actual-signed-default-Mesa-64-and-32bit-extensions')

    data = LAB / 'fixtures'; data.mkdir(mode=0o755)
    inputs = []
    if any(m in ('native', 'flatpak', 'load') for m in modes): inputs += ['gameprobe', 'abi32']
    if 'load' in modes: inputs += ['model.gguf']
    if 'proton' in modes: inputs += ['mfprobe.exe', 'av.mp4']
    for name in inputs:
        shutil.copyfile(CD / name, data / name)
        (data / name).chmod(0o755 if name in ('gameprobe', 'abi32') else 0o644)
    if 'proton' in modes:
        artifact = json.loads((CD / 'proton-artifact.json').read_text())
        archive = CD / artifact['filename']
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == artifact['sha256']
        with tarfile.open(archive) as package:
            package.extractall(data, filter='data')
    clients = LAB / 'clients'; clients.mkdir(mode=0o700); os.chown(clients, 1000, 1000)
    def graphic_ready():
        if not Path('/run/user/1000/bus').is_socket(): return False
        session = run(['loginctl', 'show-user', 'admin', '-p', 'Display', '--value']).strip()
        return bool(session) and 'Active=yes' in run(['loginctl', 'show-session', session, '-p', 'Active'])
    wait(graphic_ready)
    run(USER + ['systemctl', '--user', 'daemon-reload'])
    # Effective provider permissions must be granted to a real logged-in seat.
    run(USER + ['python', '-c', 'import os; f=os.open("/dev/uinput",os.O_WRONLY);os.close(f)'])
    run(['useradd', '-m', 'gamingother'])
    denied = subprocess.run(['runuser', '-u', 'gamingother', '--', 'python', '-c', 'import os;os.open("/dev/uinput",os.O_WRONLY)'], capture_output=True, text=True)
    assert denied.returncode != 0 and 'PermissionError' in denied.stderr
    mark('active-seat-uinput-granted-other-account-denied')
    if any(m in ('native', 'flatpak', 'load') for m in modes):
        writer = subprocess.Popen(['python', str(CD / 'uinput.py')], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        children.append(writer); wait(lambda: (LAB / 'pad-created').exists(), 30)
        wait(lambda: any('enzimOS fixture gamepad' in (p / 'device/name').read_text() for p in Path('/sys/class/input').glob('event*')), 30)
    failures = []
    for mode in modes:
        print('ENZIMOS_GAMING_NATIVE_TERMINAL_COMMAND python /run/enzimos-testpayload/client.py ' + mode + (' x11' if mode == 'flatpak' and display == 'x11' else ''), flush=True)
        print('ENZIMOS_GAMING_READY ' + mode, flush=True)
        output = clients / (mode + '.json')
        wait(output.is_file, 1800)
        assert not output.is_symlink() and output.stat().st_uid == 1000 and output.stat().st_size < 65536
        result = json.loads(output.read_text())
        print(json.dumps(result), flush=True)
        assert result['uid'] == 1000
        if result['status'] != 'PASS': failures.append(mode)
        else: mark('actual-' + mode)
    text = run(USER + ['enzimos-gaming-check'])
    diag = json.loads(text); assert diag['changes_made'] is False and diag['uinput_writable'] and diag['user_namespaces_available']
    assert diag['steam_flatpak_installed'] and diag['packages']['steam-devices']
    print(text, flush=True)
    mark('read-only-diagnostics')
    assert not failures, failures
    print('ENZIMOS_GAMING_PASS' if modes == all_modes else 'ENZIMOS_GAMING_SELECTED_PASS', flush=True)
finally:
    for child in children:
        if child.poll() is None: child.terminate()
    run(['journalctl', '-b', '-u', 'gamemoded.service', '--no-pager', '-n', '12'])
