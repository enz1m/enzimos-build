# SPDX-License-Identifier: MIT
"""Installed OS provider acceptance with real manual greetd authentication."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import time

ENV = ['runuser', '-u', 'admin', '--', 'env', 'XDG_RUNTIME_DIR=/run/user/1000',
       'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus']

def command(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=30, **kwargs).stdout

def user(argv, **kwargs):
    return command(ENV + argv, **kwargs)

def wait(label, check, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(1)
    raise AssertionError(label)

def alive(name, account):
    uid = pwd.getpwnam(account).pw_uid
    for p in Path('/proc').iterdir():
        if not p.name.isdecimal():
            continue
        try:
            if p.stat().st_uid == uid and (p / 'exe').resolve().name == name:
                return True
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            pass
    return False

# A private test overlay must preserve installed root ownership rather than
# copying the host builder UID into system directories or authentication files.
for path in ['/etc/sudoers.d', '/etc/pam.d/greetd', '/usr/lib/enzui/enzui-greeter-session',
             '/usr/share/dbus-1/interfaces/com.endlessm.ParentalControls.AppFilter.xml']:
    assert Path(path).stat().st_uid == 0, path
extension = Path('/usr/share/accountsservice/interfaces/com.endlessm.ParentalControls.AppFilter.xml')
assert extension.is_symlink() and str(extension.readlink()) == '../../dbus-1/interfaces/' + extension.name
providers = ['enzimos-keyring', 'libsecret', 'libmalcontent', 'noto-fonts-cjk', 'fcitx5',
             'fcitx5-gtk', 'fcitx5-qt', 'fcitx5-chinese-addons', 'fcitx5-mozc',
             'udisks2', 'gst-plugins-base', 'gst-plugins-good', 'gst-plugins-ugly',
             'gst-plugin-pipewire', 'gst-libav', 'colord', 'enzimos-activity-service', 'enzimos-update-client']
command(['pacman', '-Q', *providers])
assert json.loads(command(['/usr/lib/enzimos-native/enzimos-policy', 'desktop', 'setup', '--root', '/']))['changed'] == []
for service in ['greetd', 'enzui-lock', 'passwd']:
    assert Path('/etc/pam.d', service).read_text().count('pam_oo7.so') == (3 if service == 'greetd' else 2 if service == 'enzui-lock' else 1)
assert 'Hidden=true' in Path('/etc/xdg/autostart/org.fcitx.Fcitx5.desktop').read_text()
for entry in ['fcitx5-configtool.desktop', 'qv4l2.desktop', 'qvidcap.desktop']:
    assert 'NoDisplay=true' in Path('/usr/share/applications', entry).read_text()
assert 'Storage=none' in command(['systemd-analyze', 'cat-config', 'systemd/coredump.conf'])
assert 'PercentageCritical=5' in Path('/etc/UPower/UPower.conf').read_text()
assert command(['flatpak', 'list', '--system', '--app', '--columns=application']).splitlines() == ['app.zen_browser.zen']
print('ENZIMOS_PARITY_PROVIDERS_PASS', flush=True)
wait('native greeter', lambda: alive('enzui-greeter', 'greeter'))
print('ENZIMOS_PARITY_GREETER_READY', flush=True)
wait('real account login', lambda: alive('enzui-shell', 'admin'), seconds=600)
wait('polkit agent', lambda: alive('enzui-polkit-agent', 'admin'))
time.sleep(8)
manager = user(['systemctl', '--user', 'show-environment'])
for setting in ['XMODIFIERS=@im=fcitx', 'QT_IM_MODULE=fcitx', 'SDL_IM_MODULE=fcitx']:
    assert setting in manager, (setting, manager)
assert 'GTK_IM_MODULE=' not in manager
wait('activity socket readiness', lambda: Path('/run/user/1000/enzui-activity/service.sock').is_socket())
time.sleep(4)
assert user(['systemctl', '--user', 'is-active', 'enzimos-activity.service']).strip() == 'active'
assert Path('/run/user/1000/enzui-activity/service.sock').is_socket()
assert subprocess.run(ENV + ['systemctl', '--user', 'is-active', '--quiet', 'enzimos-input-method.service']).returncode != 0
print('ENZIMOS_PARITY_SESSION_PASS', flush=True)
secret = 'disposable-keyring-fixture-value'
user(['secret-tool', 'store', '--label=enzimOS disposable keyring fixture', 'enzimos-fixture', 'parity'], input=secret)
assert user(['secret-tool', 'lookup', 'enzimos-fixture', 'parity']).strip() == secret
user(['secret-tool', 'clear', 'enzimos-fixture', 'parity'])
print('ENZIMOS_PARITY_KEYRING_PASS', flush=True)
# Exercise the metadata-only collector without exporting any journal message/core.
report = json.loads(user(['/usr/lib/enzimos-native/enzimos-policy', 'desktop', 'crash-reports']))
assert report['raw_core_access'] is False
assert 'MESSAGE' not in json.dumps(report)
print('ENZIMOS_PARITY_CRASH_QUERY_PASS', flush=True)
# Wheel membership does not grant journal-reader access. This controlled crash
# checks actual per-UID discovery instead of accepting an empty report as proof.
assert not {'adm', 'systemd-journal'} & set(user(['id', '-Gn']).split())
probe = subprocess.run(ENV + ['sh', '-c',
    'ulimit -c unlimited; sleep 60 & p=$!; echo $p; kill -SEGV $p; wait $p'],
    capture_output=True, text=True, timeout=10)
assert probe.returncode in (139, -11), probe.returncode
crashed_pid = probe.stdout.strip()
assert crashed_pid.isdecimal()
wait('actual current-UID crash metadata', lambda: any(
    row['pid'] == crashed_pid for row in json.loads(user([
        '/usr/lib/enzimos-native/enzimos-policy', 'desktop', 'crash-reports']))['reports']), seconds=45)
print('ENZIMOS_PARITY_CRASH_DISCOVERY_PASS', flush=True)
# No provider policy is preconfigured for the administrator account.
user(['gdbus', 'call', '--system', '--dest', 'org.freedesktop.Accounts',
      '--object-path', '/org/freedesktop/Accounts', '--method', 'org.freedesktop.Accounts.FindUserById', '1000'])
parental = user(['gdbus', 'introspect', '--system', '--dest', 'org.freedesktop.Accounts',
                 '--object-path', '/org/freedesktop/Accounts/User1000'])
assert 'com.endlessm.ParentalControls.AppFilter' in parental
print('ENZIMOS_PARITY_PARENTAL_PROVIDER_PASS', flush=True)
# Exercise encoders and decoding, rather than only checking plugin filenames.
command(['gst-launch-1.0', '-q', 'videotestsrc', 'num-buffers=30', '!',
         'video/x-raw,width=320,height=180,framerate=30/1', '!', 'videoconvert', '!',
         'x264enc', 'tune=zerolatency', '!', 'mp4mux', '!', 'filesink',
         'location=/run/enzimos-parity-codec.mp4'])
command(['gst-launch-1.0', '-q', 'filesrc', 'location=/run/enzimos-parity-codec.mp4',
         '!', 'qtdemux', '!', 'avdec_h264', '!', 'fakesink'])
command(['gst-launch-1.0', '-q', 'audiotestsrc', 'num-buffers=20', '!',
         'audioconvert', '!', 'avenc_aac', '!', 'fakesink'])
Path('/run/enzimos-parity-codec.mp4').unlink()
print('ENZIMOS_PARITY_CODECS_PASS', flush=True)
# An explicitly enrolled disposable catalog uses public metadata only. Its
# signing keys remain on the host. This verifies the installed unprivileged CLI.
public = Path('/run/enzimos-testpayload/plugin-public')
if public.is_dir():
    directory = Path('/home/admin/.enzimos-parity-plugin')
    directory.mkdir(parents=True, exist_ok=False)
    os.chown(directory, 1000, 1000)
    directory.chmod(0o700)
    root = directory / 'root.json'
    root.write_bytes((public / 'metadata/root.json').read_bytes())
    root.chmod(0o600)
    os.chown(root, 1000, 1000)
    config = directory / 'catalog.json'
    config.write_text(json.dumps({'schema': 1, 'root': str(root),
        'state': str(directory / 'state'), 'metadata_url': 'http://127.0.0.1:18882/metadata/',
        'targets_url': 'http://127.0.0.1:18882/targets/', 'lab_http': True}))
    config.chmod(0o600)
    os.chown(config, 1000, 1000)
    server = subprocess.Popen(['enzimos-updates', 'serve', '--repository', str(public), '--port', '18882'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1)
        assert server.poll() is None
        catalog = json.loads(user(['enzimos-updates', 'plugin-check', '--config', str(config)]))
        assert catalog['catalog']['plugins'][0]['id'] == 'cpu-meter'
        result = json.loads(user(['enzimos-updates', 'plugin-download', '--config', str(config), '--id', 'cpu-meter']))
        downloaded = Path(result['download']['path'])
        assert hashlib.sha256(downloaded.read_bytes()).hexdigest() == result['download']['sha256']
        assert downloaded.stat().st_uid == 1000 and downloaded.stat().st_mode & 0o077 == 0
        assert result['installed'] is False and result['enabled'] is False and result['permissions_granted'] is False
        print('ENZIMOS_PARITY_PLUGIN_CATALOG_PASS', flush=True)
    finally:
        server.terminate()
        server.wait(timeout=5)

# The exact fresh private USB was partitioned before account login so its
# initial presence does not qualify as hotplug. Real desktop authorization follows.
fixture = json.loads(Path('/run/enzimos-parity-usb.json').read_text())
assert fixture['fixture_only'] is True and fixture['previously_empty'] is True
device = fixture['filesystem']
assert command(['lsblk', '-no', 'PKNAME', device]).strip() == Path(fixture['disk']).name
assert command(['blkid', '-s', 'LABEL', '-o', 'value', device]).strip() == 'enzimos-testusb'
# Polkit resolves active logind sessions from the caller PID. runuser creates
# a separate inactive PAM session, so perform this acceptance from the real
# native Terminal process rather than manufacturing an active-session bypass.
Path('/run/enzimos-parity-usb-device').write_text(device)
Path('/run/enzimos-parity-usb-device').chmod(0o644)
print('ENZIMOS_PARITY_UDISKS_READY', flush=True)
wait('actual desktop USB mount/unmount acknowledgement',
     lambda: Path('/home/admin/parity-udisks-reviewed').is_file(), seconds=900)
assert not Path('/run/media/admin/enzimos-testusb').exists()
if Path('/run/enzimos-testpayload/activity-publisher.so').is_file():
    # The private replay controller reuses its sole QMP owner for this fixed USB.
    print('ENZIMOS_PARITY_USB_REPLUG_READY', flush=True)
    wait('shell hotplug automount', lambda: Path('/run/media/admin/enzimos-testusb/lost+found').is_dir())
    print('ENZIMOS_PARITY_USB_HOTPLUG_READY', flush=True)
    wait('native drive notification / eject visual acknowledgement',
         lambda: Path('/home/admin/parity-hotplug-reviewed').is_file(), seconds=900)
    assert not Path('/run/media/admin/enzimos-testusb').exists()
    print('ENZIMOS_PARITY_USB_HOTPLUG_PASS', flush=True)
print('ENZIMOS_PARITY_UDISKS_PASS', flush=True)
# Interactive checks can open native Settings and exercise the account IM switch.
instances = list(Path('/run/user/1000/hypr').glob('*'))
assert len(instances) == 1
signature = instances[0].name
def dispatch(expression):
    return user(['env', 'HYPRLAND_INSTANCE_SIGNATURE=' + signature, 'hyprctl', 'dispatch', expression])

def clients():
    return user(['env', 'HYPRLAND_INSTANCE_SIGNATURE=' + signature, 'hyprctl', '-j', 'clients'])

dispatch('hl.dsp.exec_cmd("flatpak run app.zen_browser.zen --no-remote about:blank")')
wait('real Zen launch', lambda: 'zen' in clients().lower())
print('ENZIMOS_PARITY_ZEN_VISUAL_READY', flush=True)
wait('Zen visual acknowledgement', lambda: Path('/home/admin/parity-zen-reviewed').is_file(), seconds=900)
user(['flatpak', 'kill', 'app.zen_browser.zen'])
dispatch('hl.dsp.exec_cmd("enzui-settings")')
print('ENZIMOS_PARITY_VISUAL_READY', flush=True)
wait('visual acknowledgement', lambda: Path('/home/admin/parity-reviewed').is_file(), seconds=900)
print('ENZIMOS_DESKTOP_PARITY_PASS', flush=True)
