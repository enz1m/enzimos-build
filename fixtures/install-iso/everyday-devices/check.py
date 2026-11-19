# SPDX-License-Identifier: MIT
"""Real services/protocols inside one disposable guest; no host/device claims."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

CD = Path('/run/enzimos-testpayload')
LAB = Path('/run/enzimos-everyday-lab')
ENV = ['runuser', '-u', 'admin', '--', 'env', 'XDG_RUNTIME_DIR=/run/user/1000',
       'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus']
children = []


def run(argv, timeout=60, input=None, ok=True):
    result = subprocess.run(argv, input=input, text=True, capture_output=True, timeout=timeout)
    if ok and result.returncode:
        print('ENZIMOS_EVERYDAY_COMMAND_DIAGNOSTIC ' + Path(argv[0]).name + '\n' + result.stdout[-6000:] + result.stderr[-6000:], flush=True)
        raise AssertionError(f'{Path(argv[0]).name} failed ({result.returncode}): {result.stderr[-600:]}')
    return result


def start(argv, name):
    output = (LAB / (name + '.log')).open('wb')
    child = subprocess.Popen(argv, stdout=output, stderr=output, start_new_session=True)
    output.close()
    children.append(child)
    return child


def wait(check, seconds=30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.25)
    raise AssertionError('service readiness deadline')


def mark(value):
    print('ENZIMOS_EVERYDAY_OK ' + value, flush=True)


def fixture_packages():
    rows = json.loads((CD / 'fixture-packages.json').read_text())
    paths = []
    for row in rows:
        p = CD / 'packages' / row['filename']
        assert hashlib.sha256(p.read_bytes()).hexdigest() == row['sha256']
        paths.append(str(p))
    # Real installed keyring/signature verification, never SigLevel=Never.
    run(['pacman', '--noconfirm', '-U', '--needed', *paths], timeout=180)


def foundation():
    run(['pacman', '-Q', 'cups', 'cups-filters', 'ghostscript', 'cups-pk-helper', 'ipp-usb',
         'openssh', 'networkmanager-openvpn', 'networkmanager-openconnect'])
    run(['cupsd', '-t'])
    run(['firewall-offline-cmd', '--check-config'])
    assert {'enz-mdns-trust', 'enz-mdns-block'} <= set(run(['firewall-cmd', '--get-policies']).stdout.split())
    for unit in ['cups.socket', 'avahi-daemon.service', 'ipp-usb.service']:
        assert run(['systemctl', 'is-enabled', unit]).stdout.strip() == 'enabled'
    run(['systemctl', 'start', 'cups.service'])
    assert 'scheduler is running' in run(['lpstat', '-r']).stdout
    sockets = run(['ss', '-ltnp']).stdout
    for line in sockets.splitlines():
        if ':631 ' in line:
            assert any(address in line for address in ['127.0.0.1:631', '[::1]:631']), line
    config = Path('/etc/cups/cupsd.conf').read_text()
    for setting in ['Browsing No', 'WebInterface No', 'DefaultShared No', 'PreserveJobFiles No']:
        assert setting in config
    assert run(['systemctl', 'is-active', 'sshd.service'], ok=False).returncode != 0
    assert run(['systemctl', 'is-active', 'smb.service'], ok=False).returncode != 0
    assert 'interface=loopback' in Path('/etc/ipp-usb/ipp-usb.conf').read_text()
    assert 'uri=http://ping.archlinux.org/nm-check.txt' in Path('/etc/NetworkManager/conf.d/30-enzimos-connectivity.conf').read_text()
    assert 'mdns' not in Path('/etc/firewalld/zones/public.xml').read_text()
    assert 'mdns' in Path('/etc/firewalld/zones/enzimos-trusted.xml').read_text()
    mark('installed-local-service-policy')


def mount_service():
    """enzimos-mount replaces GVfs's SMB/SFTP/MTP backends (D-117).

    Its real protocol, device and failure flows need an active local login
    (polkit allow_active), which a root-driven runuser process is not; they are
    qualified in the dedicated VM (tools/mount_vm.py check). Here: the installed
    service is complete, registered, enabled with the session and GVfs's
    competing backends and metadata daemon are absent.
    """
    run(['pacman', '-Q', 'enzimos-mount', 'enzimos-aft-mtp', 'sshfs', 'smbclient', 'libmtp', 'ifuse', 'usbmuxd'])
    for gone in ['gvfs', 'gvfs-smb', 'gvfs-mtp', 'android-file-transfer']:
        assert run(['pacman', '-Q', gone], ok=False).returncode != 0, gone
    activatable = run(['busctl', '--system', 'call', 'org.freedesktop.DBus', '/org/freedesktop/DBus',
                       'org.freedesktop.DBus', 'ListActivatableNames']).stdout
    assert 'org.enzimos.MountSystem1' in activatable
    assert Path('/usr/share/dbus-1/services/org.enzimos.Mount1.service').is_file()
    assert run(['pkaction', '--action-id', 'org.enzimos.mount.user-mount', '--verbose']).stdout.count('implicit active:   yes') == 1
    wants = Path('/usr/lib/systemd/user/enzui-session.target.wants/enzimos-mountd.service')
    assert wants.is_symlink() and os.readlink(wants) == '../enzimos-mountd.service'
    assert run(['systemctl', 'is-active', 'enzimos-mount-cleanup.service']).stdout.strip() == 'active'
    assert run(['pkaction', '--action-id', 'org.enzimos.mount.boot-mount', '--verbose']).stdout.count('implicit active:   auth_admin_keep') == 1
    assert Path('/usr/lib/systemd/user/gvfs-metadata.service.d/50-enzimos-disabled.conf').is_file()
    # The root service starts on demand and exits when idle; nothing listens.
    assert run(['systemctl', 'is-active', 'enzimos-mount-system.service'], ok=False).returncode != 0
    help_text = run(['enzimos-mount', '--help']).stdout
    assert 'connect URI' in help_text
    mark('mount-service-installed-not-protocol-qualified-here')


def print_queue(check_conversion=True):
    spool = LAB / 'printer'
    spool.mkdir()
    printer = start(['ippeveprinter', '-p', '8631', '-f', 'application/pdf', '-d', str(spool), '-k',
                     'enzimOS Fixture Printer'], 'printer')
    wait(lambda: ':8631 ' in run(['ss', '-ltn']).stdout)
    discovered = run(['ippfind', '-T', '4', '_ipp._tcp', '--print'], timeout=15, ok=False)
    assert ':8631/' in discovered.stdout, discovered.stdout + discovered.stderr
    mark('real-dns-sd-printer-discovery')
    uri = next(line.strip() for line in discovered.stdout.splitlines() if ':8631/' in line)
    run(['lpadmin', '-p', 'everyday-test', '-E', '-v', uri, '-m', 'everywhere'])
    run(['lpadmin', '-p', 'everyday-test', '-o', 'printer-is-shared=false'])
    run(['lpoptions', '-d', 'everyday-test'])
    page = Path('/usr/share/cups/data/default-testpage.pdf')
    if not page.is_file():
        page = Path('/usr/share/cups/data/testprint')
    assert page.is_file()
    result = run(ENV + ['lp', '-d', 'everyday-test', str(page)])
    assert 'everyday-test-' in result.stdout
    wait(lambda: bool(list(spool.glob('*'))) and not run(['lpstat', '-W', 'not-completed', '-o', 'everyday-test']).stdout.strip(), 60)
    run(['cupsdisable', 'everyday-test'])
    held = run(ENV + ['lp', '-d', 'everyday-test', str(page)])
    job = held.stdout.split('everyday-test-', 1)[1].split()[0]
    assert job.isdecimal()
    assert 'everyday-test-' + job in run(ENV + ['lpstat', '-o', 'everyday-test']).stdout
    run(ENV + ['cancel', 'everyday-test-' + job])
    assert 'everyday-test-' + job not in run(['lpstat', '-o', 'everyday-test']).stdout
    run(['cupsenable', 'everyday-test'])
    mark('real-driverless-job-owner-cancel-and-queue')
    if not check_conversion:
        return printer
    # Native Text emits PostScript; driverless hardware may accept only PWG
    # raster. Test actual conversion, not merely the presence of Ghostscript.
    postscript = LAB / 'native-text.ps'
    postscript.write_text('%!PS-Adobe-3.0\n%%Pages: 1\n/Helvetica findfont 12 scalefont setfont\n72 720 moveto (enzimOS native text print) show\nshowpage\n%%EOF\n')
    before = set(spool.iterdir())
    run(ENV + ['lp', '-d', 'everyday-test', str(postscript)])
    wait(lambda: bool(set(spool.iterdir()) - before) and not run(['lpstat', '-W', 'not-completed', '-o', 'everyday-test']).stdout.strip(), 90)
    assert any(p.read_bytes().startswith(b'%PDF') for p in set(spool.iterdir()) - before if p.is_file())
    raster = LAB / 'raster-printer'; raster.mkdir()
    start(['ippeveprinter', '-p', '8632', '-f', 'image/pwg-raster', '-d', str(raster), '-k',
           'enzimOS Raster Fixture'], 'raster-printer')
    wait(lambda: ':8632 ' in run(['ss', '-ltn']).stdout)
    run(['lpadmin', '-p', 'everyday-raster', '-E', '-v', 'ipp://localhost:8632/ipp/print', '-m', 'everywhere'])
    run(['lpadmin', '-p', 'everyday-raster', '-o', 'printer-is-shared=false'])
    run(ENV + ['lp', '-d', 'everyday-raster', str(page)])
    wait(lambda: bool(list(raster.iterdir())) and not run(['lpstat', '-W', 'not-completed', '-o', 'everyday-raster']).stdout.strip(), 90)
    assert any(p.read_bytes().startswith(b'RaS2') for p in raster.iterdir() if p.is_file())
    mark('actual-postscript-to-pdf-and-pdf-to-driverless-pwg-raster')
    # Leave the real queue available for the subsequent sandbox/native UI review.
    return printer


def wireguard():
    run(['ip', 'netns', 'add', 'everyday-peer'])
    run(['ip', 'link', 'add', 'lab-wg', 'type', 'veth', 'peer', 'name', 'lab-peer'])
    run(['nmcli', 'device', 'set', 'lab-wg', 'managed', 'no'])
    run(['ip', 'link', 'set', 'lab-peer', 'netns', 'everyday-peer'])
    run(['ip', 'address', 'add', '192.0.2.1/24', 'dev', 'lab-wg'])
    run(['ip', 'link', 'set', 'lab-wg', 'up'])
    run(['ip', 'netns', 'exec', 'everyday-peer', 'ip', 'address', 'add', '192.0.2.2/24', 'dev', 'lab-peer'])
    run(['ip', 'netns', 'exec', 'everyday-peer', 'ip', 'link', 'set', 'lab-peer', 'up'])
    run(['ip', 'netns', 'exec', 'everyday-peer', 'ip', 'link', 'set', 'lo', 'up'])
    keys = []
    for name in ['client', 'peer']:
        private = run(['wg', 'genkey']).stdout.strip()
        public = run(['wg', 'pubkey'], input=private + '\n').stdout.strip()
        path = LAB / (name + '.key')
        path.write_text(private + '\n'); path.chmod(0o600)
        keys.append((private, public, str(path)))
    run(['ip', 'netns', 'exec', 'everyday-peer', 'ip', 'link', 'add', 'wg-peer', 'type', 'wireguard'])
    run(['ip', 'netns', 'exec', 'everyday-peer', 'wg', 'set', 'wg-peer', 'listen-port', '51820',
         'private-key', keys[1][2], 'peer', keys[0][1], 'allowed-ips', '10.42.0.2/32'])
    run(['ip', 'netns', 'exec', 'everyday-peer', 'ip', 'address', 'add', '10.42.0.1/24', 'dev', 'wg-peer'])
    run(['ip', 'netns', 'exec', 'everyday-peer', 'ip', 'link', 'set', 'wg-peer', 'up'])
    profile = LAB / 'lab-wg-vpn.conf'
    profile.write_text(f'''[Interface]
PrivateKey = {keys[0][0]}
Address = 10.42.0.2/24
[Peer]
PublicKey = {keys[1][1]}
AllowedIPs = 10.42.0.1/32
Endpoint = 192.0.2.2:51820
PersistentKeepalive = 1
''')
    profile.chmod(0o600)
    run(['nmcli', 'connection', 'import', 'type', 'wireguard', 'file', str(profile)])
    run(['nmcli', 'connection', 'modify', 'lab-wg-vpn', 'connection.autoconnect', 'no'])
    run(['nmcli', 'connection', 'up', 'lab-wg-vpn'])
    run(['ping', '-c', '2', '-W', '5', '10.42.0.1'])
    assert any(int(row.split()[-1]) > 0 for row in run(['wg', 'show', 'lab-wg-vpn', 'latest-handshakes']).stdout.splitlines())
    run(['nmcli', 'connection', 'down', 'lab-wg-vpn'])
    run(['nmcli', 'connection', 'up', 'lab-wg-vpn'])
    run(['ping', '-c', '1', '-W', '5', '10.42.0.1'])
    run(['nmcli', 'connection', 'delete', 'lab-wg-vpn'])
    run(['ip', 'netns', 'delete', 'everyday-peer'])
    assert run(['ip', 'link', 'show', 'lab-wg'], ok=False).returncode != 0  # netns deletion removes both veth ends
    profile.unlink()
    mark('real-nm-wireguard-import-handshake-reconnect-remove')


def mdns_egress(peer, zone, expected):
    for family in ['4', '6']:
        prefix = LAB / ('mdns-' + zone + '-' + family)
        token = prefix.name
        process = start(peer + ['python', '-B', str(CD / 'mdns_peer.py'), family, str(prefix), token], token)
        wait(lambda: prefix.with_suffix('.ready').exists())
        code = """import socket,sys
family,token,allowed=sys.argv[1:]
s=socket.socket(socket.AF_INET if family=='4' else socket.AF_INET6,socket.SOCK_DGRAM)
if family=='4':
 s.bind(('10.77.0.2',0));s.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_IF,socket.inet_aton('10.77.0.2'))
 address=('224.0.0.251',5353)
else:
 s.bind(('fd77::2',0));index=socket.if_nametoindex('lab-nm')
 s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_IF,index)
 address=('ff02::fb',5353,0,index)
try:s.sendto(token.encode(),address)
except PermissionError:
 if allowed=='yes':raise
 print('Expected kernel rejection of public multicast')
"""
        run(['python', '-c', code, family, token, 'yes' if expected else 'no'])
        process.wait(timeout=5)
        actual = prefix.with_suffix('.result').read_text() == 'yes'
        assert actual == expected, (zone, family, actual, expected)
        mark('actual-ipv' + family + '-mdns-' + zone + ('-allowed' if expected else '-blocked'))


def captive_portal():
    run(['ip', 'netns', 'add', 'everyday-portal'])
    run(['ip', 'link', 'add', 'lab-nm', 'type', 'veth', 'peer', 'name', 'portal-peer'])
    run(['ip', 'link', 'set', 'portal-peer', 'netns', 'everyday-portal'])
    peer = ['ip', 'netns', 'exec', 'everyday-portal']
    run(peer + ['ip', 'address', 'add', '10.77.0.1/24', 'dev', 'portal-peer'])
    run(peer + ['ip', 'address', 'add', 'fd77::1/64', 'dev', 'portal-peer'])
    run(peer + ['ip', 'link', 'set', 'portal-peer', 'up'])
    run(peer + ['ip', 'link', 'set', 'lo', 'up'])
    mode = LAB / 'portal-mode'
    mode.write_text('portal')
    start(peer + ['python', '-B', str(CD / 'portal_server.py'), str(mode)], 'portal')
    wait(lambda: ':80 ' in run(peer + ['ss', '-ltn']).stdout)
    override = Path('/etc/NetworkManager/conf.d/90-everyday-lab.conf')
    override.write_text('[connectivity]\nuri=http://10.77.0.1/probe\nresponse=NetworkManager is online\ninterval=300\ntimeout=5\n')
    run(['nmcli', 'general', 'reload', 'conf'])
    run(['nmcli', 'connection', 'add', 'type', 'ethernet', 'ifname', 'lab-nm',
         'con-name', 'everyday-portal', 'connection.autoconnect', 'no',
         'connection.zone', 'public', 'ipv4.method', 'manual', 'ipv4.addresses', '10.77.0.2/24',
         'ipv4.gateway', '10.77.0.1', 'ipv6.method', 'manual', 'ipv6.addresses', 'fd77::2/64', 'ipv6.never-default', 'yes'])
    run(['nmcli', 'connection', 'up', 'everyday-portal'])
    assert run(['firewall-cmd', '--get-zone-of-interface=lab-nm']).stdout.strip() == 'public'
    assert run(['firewall-cmd', '--zone=public', '--query-service=mdns'], ok=False).returncode != 0
    mdns_egress(peer, 'public', False)
    for value, expected in [('portal', 'portal'), ('online', 'full'), ('offline', 'limited'), ('online', 'full')]:
        mode.write_text(value)
        wait(lambda: run(['nmcli', 'networking', 'connectivity', 'check'], timeout=20, ok=False).stdout.strip() == expected, 20)
    properties = ['busctl', '--system', 'set-property', 'org.freedesktop.NetworkManager',
                  '/org/freedesktop/NetworkManager', 'org.freedesktop.NetworkManager', 'ConnectivityCheckEnabled', 'b']
    run(properties + ['false'])
    time.sleep(1)
    counter = mode.with_suffix('.count')
    before = int(counter.read_text())
    run(['nmcli', 'networking', 'connectivity', 'check'], timeout=20, ok=False)
    assert int(counter.read_text()) == before, 'disabled connectivity check still sent a probe'
    run(properties + ['true'])
    wait(lambda: run(['nmcli', 'networking', 'connectivity', 'check'], timeout=20, ok=False).stdout.strip() == 'full', 20)
    assert int(counter.read_text()) > before
    mark('real-connectivity-privacy-disable-no-probe-and-enable')
    run(['nmcli', 'connection', 'modify', 'everyday-portal', 'connection.zone', 'enzimos-trusted'])
    run(['nmcli', 'device', 'reapply', 'lab-nm'])
    assert run(['firewall-cmd', '--get-zone-of-interface=lab-nm']).stdout.strip() == 'enzimos-trusted'
    assert run(['firewall-cmd', '--zone=enzimos-trusted', '--query-service=mdns']).stdout.strip() == 'yes'
    mdns_egress(peer, 'trusted', True)
    run(['nmcli', 'connection', 'delete', 'everyday-portal'])
    run(['ip', 'link', 'delete', 'lab-nm'], ok=False)
    run(['ip', 'netns', 'delete', 'everyday-portal'])
    override.unlink()
    run(['nmcli', 'general', 'reload', 'conf'])
    mark('real-nm-captive-full-limited-reconnect-trusted-discovery-policy')


def openvpn():
    run(['nmcli', 'connection', 'add', 'type', 'dummy', 'ifname', 'vpn-base', 'con-name', 'everyday-vpn-base',
         'connection.autoconnect', 'no', 'ipv4.method', 'manual', 'ipv4.addresses', '192.0.2.90/32',
         'ipv4.never-default', 'yes', 'ipv6.method', 'disabled'])
    run(['nmcli', 'connection', 'up', 'everyday-vpn-base'])
    directory = LAB / 'vpn'
    directory.mkdir(mode=0o700)
    ca = directory / 'ca.pem'
    cakey = directory / 'ca.key'
    run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
         '-nodes', '-days', '1', '-subj', '/CN=enzimOS-disposable-VPN-CA',
         '-keyout', str(cakey), '-out', str(ca)])
    for index, name in enumerate(['server', 'client'], 1):
        key = directory / (name + '.key')
        request = directory / (name + '.csr')
        cert = directory / (name + '.pem')
        extension = directory / (name + '.ext')
        extension.write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=' +
                             ('serverAuth' if name == 'server' else 'clientAuth') + '\n')
        run(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
             '-nodes', '-subj', '/CN=enzimOS-lab-' + name, '-keyout', str(key), '-out', str(request)])
        run(['openssl', 'x509', '-req', '-in', str(request), '-CA', str(ca), '-CAkey', str(cakey),
             '-set_serial', str(index), '-days', '1', '-extfile', str(extension), '-out', str(cert)])
        key.chmod(0o600)
    cakey.chmod(0o600)
    server = directory / 'server.conf'
    server.write_text(f'''local 127.0.0.1
port 1194
proto udp
dev tun-lab
ca {ca}
cert {directory}/server.pem
key {directory}/server.key
dh none
topology subnet
server 10.89.0.0 255.255.255.0
data-ciphers AES-256-GCM
keepalive 2 10
verb 1
''')
    start(['openvpn', '--config', str(server)], 'openvpn')
    wait(lambda: ':1194 ' in run(['ss', '-lun']).stdout)
    profile = directory / 'lab-openvpn.ovpn'
    profile.write_text('''client
dev tun
proto udp
remote 127.0.0.1 1194
nobind
remote-cert-tls server
route-nopull
data-ciphers AES-256-GCM
''' + ''.join(f'<{name}>\n{(directory / source).read_text()}</{name}>\n'
              for name, source in [('ca', 'ca.pem'), ('cert', 'client.pem'), ('key', 'client.key')]))
    profile.chmod(0o600)
    run(['nmcli', 'connection', 'import', 'type', 'openvpn', 'file', str(profile)])
    run(['nmcli', 'connection', 'modify', 'lab-openvpn', 'connection.autoconnect', 'no',
         'ipv4.never-default', 'yes', 'ipv6.never-default', 'yes'])
    run(['nmcli', 'connection', 'up', 'lab-openvpn', 'ifname', 'vpn-base'], timeout=90)
    run(['ping', '-c', '2', '-W', '5', '10.89.0.1'])
    run(['nmcli', 'connection', 'down', 'lab-openvpn'])
    run(['nmcli', 'connection', 'up', 'lab-openvpn', 'ifname', 'vpn-base'], timeout=90)
    run(['ping', '-c', '1', '-W', '5', '10.89.0.1'])
    run(['nmcli', 'connection', 'delete', 'lab-openvpn'])
    profile.unlink()
    run(['nmcli', 'connection', 'delete', 'everyday-vpn-base'])
    mark('real-nm-openvpn-import-tls-tunnel-reconnect-remove')


def main():
    assert os.geteuid() == 0 and Path('/etc/enzimos').is_dir()
    LAB.mkdir(mode=0o755)
    runtime = LAB / 'user-runtime'
    runtime.mkdir(mode=0o700)
    os.chown(runtime, 1000, 1000)
    fixture_packages()
    foundation()
    failures = []
    for operation in [mount_service, print_queue, wireguard, openvpn, captive_portal]:
        try:
            operation()
        except Exception as error:
            import traceback
            traceback.print_exc()
            failures.append(operation.__name__)
            print('ENZIMOS_EVERYDAY_CHECK_FAILED ' + operation.__name__, flush=True)
    assert not failures, 'failed backend gates: ' + ', '.join(failures)
    print('ENZIMOS_EVERYDAY_BACKENDS_PASS', flush=True)


def cleanup():
    print('ENZIMOS_EVERYDAY_KERNEL_DENIALS\n' + run(['journalctl', '-b', '-k', '--no-pager', '-g', 'apparmor=\"DENIED\"', '-n', '20'], ok=False).stdout, flush=True)
    print('ENZIMOS_EVERYDAY_LISTENERS\n' + run(['ss', '-ltnp'], ok=False).stdout, flush=True)
    for log in LAB.glob('*.log') if LAB.is_dir() else []:
        # Disposable server diagnostics only; private key files are never read.
        print('ENZIMOS_EVERYDAY_SERVER_LOG ' + log.name + '\n' + log.read_text(errors='replace')[-4000:], flush=True)
    for child in reversed(children):
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)
    # Keys/passwords stay in disposable RAM, never in exported acceptance evidence.
    if LAB.is_dir():
        shutil.rmtree(LAB)


if __name__ == '__main__':
    try:
        main()
    finally:
        cleanup()
