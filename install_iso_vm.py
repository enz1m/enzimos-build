#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Install the enzimOS development ISO onto a blank private virtual disk, then boot it.

install: the ISO boots as a CD (UEFI OVMF or BIOS SeaBIOS) with a TEST answer CD
(label ENZIMOS_ANSWERS) and one blank 24 GiB qcow2 target; the unattended installer must
print ENZIMOS_INSTALL_PASS and power off. boot: the installed disk alone boots (UEFI
with the install run's firmware variables, or BIOS), the LUKS prompt is answered with the
public test passphrase on the serial console, and the test first-boot check must print
ENZIMOS_FIRSTBOOT_PASS. boot --vnc SECONDS: a human review boot (e.g. the installer UI
preview) with a VNC display on the private unix socket /work/vnc.sock, held until the time is
up or the guest powers off; its result is REVIEW-ENDED, never a qualification. Default lab limits: 1 vCPU, 2 GiB (explicit multi-session qualification may use 4 GiB), networking disabled by default, KVM when
available, nice19/idle I/O, one at a time. --network adds isolated user-mode Ethernet
with DHCP, no external gateway and no host forwarding. --internet explicitly
allows outbound user-mode NAT for attended boot fixtures (--network and --vnc),
with no inbound forwarding. Never a host block device."""
import argparse
from datetime import datetime, timezone
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import time

from contract import Invalid, digest, load
from signed_bootstrap import FREE_FLOOR, new_output
from target_vm import sandbox, accel, read_log, MAX_LOG
from lab_resources import constrain_job

DISK = 24*1024**3
FIX = Path(__file__).resolve().parent/'fixtures/install-iso'
OVMF = '/usr/share/edk2/x64/OVMF_CODE.4m.fd'


def answers_iso(out, answers, label='ENZIMOS_ANSWERS'):
    # label ENZIMOS_TESTCHECK: only the first-boot check, for a graphical (human-driven) install.
    stage = out/'answers';stage.mkdir()
    if label == 'ENZIMOS_ANSWERS':shutil.copyfile(answers, stage/'answers.env')
    values = dict(line.split('=', 1) for line in answers.read_text().splitlines() if line and not line.startswith('#'))
    encrypt = values.get('ENZIMOS_ENCRYPT', 'yes')
    if encrypt not in ('yes', 'no'):raise Invalid('test encryption expectation must be yes or no')
    (stage/'firstboot-check.sh').write_text((FIX/'firstboot-check.sh').read_text().replace(
        'expected_encrypt=yes #', 'expected_encrypt='+encrypt+' #'))
    args = sandbox(out)+['--', '/usr/bin/xorriso', '-as', 'mkisofs', '-quiet', '-R', '-V', label, '-o', '/work/answers.iso', '/work/answers']
    subprocess.run(args, check=True, timeout=60, stdout=subprocess.DEVNULL)


class Qmp:
    """Minimal QMP client on the VM's private control socket: screenshots and key presses."""
    IO_TIMEOUT = 5.0
    MAX_FRAME = 1024 * 1024

    def __init__(self, path):
        import socket
        deadline = time.monotonic() + 20
        while True:
            self.sock = socket.socket(socket.AF_UNIX)
            self.sock.settimeout(min(2.0, max(.001, deadline - time.monotonic())))
            try:
                self.sock.connect(str(path))
                break
            except OSError:
                self.sock.close()
                if time.monotonic() >= deadline:raise Invalid('QMP socket unavailable')
                time.sleep(.2)
        self.file = self.sock.makefile('rwb')
        self.pending = bytearray()
        try:
            if 'QMP' not in self._receive(time.monotonic() + self.IO_TIMEOUT):
                raise Invalid('invalid QMP greeting')
            self.call('qmp_capabilities')
        except BaseException:
            self.file.close();self.sock.close();raise

    def _receive(self, deadline):
        try:
            while b'\n' not in self.pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:raise Invalid('QMP response deadline reached')
                self.sock.settimeout(remaining)
                data = self.sock.recv(min(65536, self.MAX_FRAME + 1 - len(self.pending)))
                if not data:raise Invalid('QMP disconnected')
                self.pending.extend(data)
                if len(self.pending) > self.MAX_FRAME:raise Invalid('QMP frame limit reached')
            line, _, rest = self.pending.partition(b'\n')
            self.pending = bytearray(rest)
            return json.loads(line)
        except (OSError, ValueError) as error:
            raise Invalid('QMP transport failed') from error

    def call(self, command, **arguments):
        deadline = time.monotonic() + self.IO_TIMEOUT
        self.sock.settimeout(self.IO_TIMEOUT)
        try:self.sock.sendall(json.dumps({'execute':command,'arguments':arguments}).encode()+b'\n')
        except OSError as error:raise Invalid('QMP command send failed') from error
        while True:
            reply = self._receive(deadline)
            if 'return' in reply:return reply['return']
            if 'error' in reply:raise Invalid('QMP '+command+': '+reply['error'].get('desc', ''))

    def type(self, text):
        for char in text:
            if char == '\n':keys = ['ret']
            elif char == '-':keys = ['minus']
            elif char == ' ':keys = ['spc']
            elif char.isupper():keys = ['shift', char.lower()]
            else:keys = [char]
            self.call('send-key', keys=[{'type': 'qcode', 'data': k} for k in keys]);time.sleep(0.08)

    def screenshot(self, out, name):
        self.call('screendump', filename='/work/'+name+'.ppm')
        time.sleep(0.5);png(out/(name+'.ppm'), out/(name+'.png'));(out/(name+'.ppm')).unlink()


def png(source, target):
    import struct, zlib
    data = source.read_bytes();parts = data.split(b'\n', 3)
    if parts[0] != b'P6':raise Invalid('unexpected screendump format')
    width, height = map(int, parts[1].split());pixels = parts[3]
    rows = b''.join(b'\x00'+pixels[y*width*3:(y+1)*width*3] for y in range(height))
    chunk = lambda kind, body: struct.pack('>I', len(body))+kind+body+struct.pack('>I', zlib.crc32(kind+body) & 0xffffffff)
    target.write_bytes(b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))+chunk(b'IDAT', zlib.compress(rows, 6))+chunk(b'IEND', b''))


def vnc_unlock(output, secret):
    """Type the disk passphrase into the graphical unlock prompt; never logged."""
    path = output/'.unlock'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:stream.write(secret)
        subprocess.run([sys.executable, '-I', str(Path(__file__).resolve().parent/'vnc_client.py'), str(output/'vnc.sock'),
                        'typefile:'+str(path), 'wait:0.4', 'key:ret'], check=False, timeout=90,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    finally:
        path.unlink(missing_ok=True)


def fixture_input(name, directory=False):
    """Require an explicitly selected external fixture, never a private scratch path."""
    raw = os.environ.get(name)
    if not raw:
        raise Invalid(f'{name} is required for this fixture')
    path = Path(raw).resolve(strict=True)
    if not (path.is_dir() if directory else path.is_file()):
        raise Invalid(f'{name} has the wrong input type')
    return path


def payload_iso(out, build):
    stage = out/'testpayload'
    if str(build) in ('desktop', 'settings', 'review-ui', 'live-ui-probe', 'existing-os', 'lts', 'boot-console', 'alongside-check', 'delivery-base', 'delivery-enroll', 'media-prepare', 'delivery-secure', 'delivery-tamper', 'delivery-display', 'delivery-display-debug', 'delivery-display-theme', 'mcp-center', 'desktop-refresh-stage', 'desktop-refresh', 'desktop-zen', 'desktop-parity', 'backup-installed', 'backup-adopt'):
        stage.mkdir()
        fixture = {'delivery-enroll': 'delivery-base', 'backup-adopt': 'backup-installed'}.get(str(build), str(build))
        for source in (FIX/fixture).iterdir():
            if source.is_file():shutil.copyfile(source, stage/source.name)
        if str(build) in ('backup-installed', 'backup-adopt'):
            # One payload, two scenarios: create a new repository, or adopt one.
            (stage/'scenario').write_text('adopt' if str(build) == 'backup-adopt' else 'initialize')
        if str(build)=='delivery-display-theme':
            shutil.copyfile(fixture_input('ENZIMOS_VM_THEME_SCRIPT'),stage/'enzimos.script')
        if str(build)=='delivery-enroll':
            (stage/'enroll-firmware').touch()
            shutil.copyfile(fixture_input('ENZIMOS_VM_MEDIA_OWNER_CERTIFICATE'),stage/'media-owner.crt')
        if str(build)=='delivery-secure':
            shutil.copyfile(Path(__file__).resolve().parents[1]/'enzimos-updates/deploy/enzimos-update-server.service',stage/'enzimos-update-server.service')
        if str(build)=='desktop-refresh-stage':
            desktop_stage=fixture_input('ENZIMOS_VM_DESKTOP_STAGE', directory=True)
            subprocess.run(['tar','--sort=name','--owner=0','--group=0','--numeric-owner','-C',str(desktop_stage),'-I','zstd -T1 -3','-cf',str(stage/'desktop-stage.tar.zst'),'.'],check=True,timeout=180)
        if str(build)=='mcp-center':
            shutil.copyfile(fixture_input('ENZIMOS_VM_MCP_BUILD_SUMMARY'),stage/'expected-build.json')
        if str(build) in ('review-ui', 'live-ui-probe'):
            # The review payload carries the current UI independently of the installation ISO.
            ui = Path(__file__).resolve().parents[1]/'enzimos-installer-ui'
            shutil.copyfile(ui/'target/release/enzimos-installer', stage/'enzimos-installer')
            shutil.copytree(ui/'data', stage/'data')
        args = sandbox(out)+['--', '/usr/bin/xorriso', '-as', 'mkisofs', '-quiet', '-R', '-V', 'ENZIMOS_TESTPAYLOAD', '-o', '/work/testpayload.iso', '/work/testpayload']
        subprocess.run(args, check=True, timeout=60, stdout=subprocess.DEVNULL);return {str(build)+'_test': True}
    reports = [load(Path(item)) for item in str(build).split(',')]
    stage.mkdir()
    for name in ('run.sh', 'update.py'):shutil.copyfile(FIX/'update'/name, stage/name)
    packages = []
    for report in reports:
        package = Path(report['package'])
        if not str(report.get('status', '')).startswith('PASS') or digest(package) != report['sha256']:raise Invalid('reviewed update package required')
        shutil.copyfile(package, stage/package.name)
        packages.append({'filename': package.name, 'name': report.get('package_name', 'enzimos-native-policy'), 'release': report['release'], 'sha256': report['sha256']})
    (stage/'update.json').write_text(json.dumps({'packages': packages})+'\n')
    args = sandbox(out)+['--', '/usr/bin/xorriso', '-as', 'mkisofs', '-quiet', '-R', '-V', 'ENZIMOS_TESTPAYLOAD', '-o', '/work/testpayload.iso', '/work/testpayload']
    subprocess.run(args, check=True, timeout=60, stdout=subprocess.DEVNULL)
    return {'packages': packages}


def dialogue(values):
    """Scripted replies for the interactive installer on the serial console, in order."""
    return [('Press Enter to begin the enzimOS installation.', b'\n'),
            ('Disk to ERASE and install enzimOS on', b'\n'), ('Type the disk path again', b'/dev/vda\n'),
            ('Computer name', values['ENZIMOS_HOSTNAME'].encode()+b'\n'), ('Administrator user name', values['ENZIMOS_USER'].encode()+b'\n'),
            ('Full name', values['ENZIMOS_FULLNAME'].encode()+b'\n'), ('Administrator password:', values['ENZIMOS_PASSWORD'].encode()+b'\n'),
            ('Repeat:', values['ENZIMOS_PASSWORD'].encode()+b'\n'), ('Encrypt the disk', b'yes\n'),
            ('Disk encryption passphrase:', values['ENZIMOS_PASSPHRASE'].encode()+b'\n'), ('Repeat:', values['ENZIMOS_PASSPHRASE'].encode()+b'\n'),
            ('Time zone', values['ENZIMOS_TIMEZONE'].encode()+b'\n'), ('press Enter to restart', b'\n')]


def ssh_forward():
    """ENZIMOS_VM_SSH_PORT: forward that port on host loopback only to the guest's SSH,
    for development media with key-only SSH. ENZIMOS_VM_SSH_GUEST_PORT selects the
    development guest listener (22 for historical images, 22222 for current builds).
    No other inbound access."""
    port = os.environ.get('ENZIMOS_VM_SSH_PORT', '')
    if not port:
        return update_forward()
    if not (port.isdigit() and 1024 < int(port) < 65536):raise Invalid('SSH forward port must be 1025..65535')
    guest = os.environ.get('ENZIMOS_VM_SSH_GUEST_PORT', '22')
    if not (guest.isdigit() and 0 < int(guest) < 65536):raise Invalid('Guest SSH port must be 1..65535')
    return f',hostfwd=tcp:127.0.0.1:{port}-:{guest}' + update_forward()

def update_forward():
    """ENZIMOS_VM_UPDATE_PORT: let the guest reach a lab update server on host
    loopback at that port as 10.0.2.100:PORT (QEMU refuses forwarding the host
    address itself). Outbound to that one port only; the guest network stays
    restricted. A guest relays it to its own loopback for the client."""
    port = os.environ.get('ENZIMOS_VM_UPDATE_PORT', '')
    if not port:
        return ''
    if not (port.isdigit() and 1024 < int(port) < 65536):raise Invalid('update server port must be 1025..65535')
    # cmd: opens one host connection per guest connection (a tcp: chardev
    # connects once, at start).
    return f',guestfwd=tcp:10.0.2.100:{port}-cmd:/usr/bin/socat - TCP:127.0.0.1:{port}'


def qemu(out, mode, iso=None, payload=False, answers=True, media='cd', desktop=False, vnc=False, scratch_disk=False, network=False, backup_usb=False, display_size=None, secure_firmware=False, guest_ram_mib=2048, internet=False, unlock_display=False, cpu_seconds=None):
    if type(guest_ram_mib) is not int or guest_ram_mib not in (2048, 4096):raise Invalid("unsupported bounded guest RAM")
    if type(internet) is not bool or (internet and (not network or not vnc)):
        raise Invalid('outbound internet requires explicit network and VNC')
    argv = sandbox(out)
    if internet:
        argv += ['--share-net', '--ro-bind', '/etc/resolv.conf', '/etc/resolv.conf']
    elif network and ssh_forward():
        # The loopback-only SSH listener lives in the host namespace; the guest stays restricted.
        argv += ['--share-net']
    if iso is not None:argv += ['--ro-bind', str(iso), '/inputs/install.iso']
    cpu = cpu_seconds or (3000 if not vnc else 12*3600+600)
    # A scratch disk is a 64 GiB image the guest may fill (backup tests).
    fsize = max(DISK, 64*1024**3+1024**3) if scratch_disk else DISK
    # Each QEMU I/O worker thread would get its own 64 MiB malloc arena; under the 6 GiB
    # address-space cap that exhausts thread creation (EAGAIN) on the larger live medium.
    argv += ['--setenv', 'MALLOC_ARENA_MAX', '2']
    # OVMF stalls with virtio-vga and -display none. Keep a private Unix VNC
    # backend even unattended; no viewer, TCP listener or extra QMP owner is needed.
    argv += ['--', '/usr/bin/prlimit', f'--cpu={cpu}:{cpu}', '--as=6442450944:6442450944', f'--fsize={fsize}:{fsize}', '--',
             '/usr/bin/qemu-system-x86_64', '-no-user-config', '-nodefaults', '-machine', 'q35', *accel(), '-cpu', 'max', '-smp', str(min(4, len(os.sched_getaffinity(0)))), '-m', f'{guest_ram_mib}M',
             '-nic', (('user,model=virtio-net-pci' if internet else 'user,model=virtio-net-pci,restrict=on') + ssh_forward()) if network else 'none', '-display', 'vnc=unix:/work/vnc.sock', '-device', ('virtio-vga'+(',xres='+display_size.split('x')[0]+',yres='+display_size.split('x')[1] if display_size else '')) if desktop else 'virtio-vga', '-monitor', 'none', '-serial', 'stdio', '-no-reboot',
             # Keep an input device for both attended and automated disk unlocks.
             '-device', 'qemu-xhci', '-device', 'usb-kbd',
             *(['-qmp', 'unix:/work/qmp.sock,server=on,wait=off', '-device', 'usb-tablet'] if desktop else []),
             '-drive', 'if=none,id=target,format=qcow2,file=/work/target.qcow2,aio=threads', '-device', 'virtio-blk-pci,drive=target,serial=enzimos-target,bootindex=1']
    if iso is not None:
        # media='disk': the ISO image as a raw disk, as after writing it to a USB stick.
        # ENZIMOS_VM_MEDIA_MBPS: cap install-medium reads (MB/s) to time a USB stick.
        mbps = os.environ.get('ENZIMOS_VM_MEDIA_MBPS', '')
        if mbps and not (mbps.isdigit() and 1 <= int(mbps) <= 10000):raise Invalid('media throttle must be 1..10000 MB/s')
        throttle = f',throttling.bps-read={int(mbps) * 1000000}' if mbps else ''
        argv += (['-drive', f'if=none,id=install,media=cdrom,readonly=on,format=raw,file=/inputs/install.iso{throttle}', '-device', 'ide-cd,drive=install,bus=ide.0,bootindex=0'] if media == 'cd' else
                 ['-drive', f'if=none,id=install,readonly=on,format=raw,file=/inputs/install.iso{throttle}', '-device', 'virtio-blk-pci,drive=install,serial=enzimos-usb,bootindex=0'])
        argv += [
                 *(['-drive', 'if=none,id=answers,media=cdrom,readonly=on,format=raw,file=/work/answers.iso', '-device', 'ide-cd,drive=answers,bus=ide.1'] if answers else [])]
    if scratch_disk:
        argv += ['-drive','if=none,id=scratch,format=qcow2,file=/work/scratch.qcow2,aio=threads','-device','virtio-blk-pci,drive=scratch,serial=enzimos-fixture']
    if backup_usb:
        argv += ['-drive','if=none,id=rescueusb,format=qcow2,file=/work/backup.qcow2,aio=threads','-device','usb-storage,drive=rescueusb,serial=enzimos-rescue']
    if payload:
        argv += ['-drive', 'if=none,id=payload,media=cdrom,readonly=on,format=raw,file=/work/testpayload.iso', '-device', 'ide-cd,drive=payload,bus=ide.0']
    if secure_firmware:
        if mode!='uefi':raise Invalid('Secure Boot firmware requires UEFI')
        argv += ['-machine','smm=on','-global','driver=cfi.pflash01,property=secure,value=on']
    if mode == 'uefi':argv += ['-drive', f'if=pflash,unit=0,format=raw,readonly=on,file={"/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd" if secure_firmware else OVMF}', '-drive', 'if=pflash,unit=1,format=raw,file=/work/vars.fd']
    else:argv += ['-bios', '/usr/share/qemu/bios-256k.bin']
    return argv


def clone_boot_source(previous, mode, output, review_only=False):
    """Copy a boot source; an explicit continued review never inherits qualification."""
    previous = Path(previous).resolve(strict=True)
    prior = load(previous)
    source = previous.parent
    image = source/'target.qcow2'
    if prior.get('mode') != mode:
        raise Invalid('earlier phase of the same firmware mode required')
    if review_only:
        if prior.get('status') != 'REVIEW-ENDED' or prior.get('qualification') is not False or prior.get('review_display') is not True:
            raise Invalid('attended review source required')
        info = image.lstat()
        if image.is_symlink() or not image.is_file() or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise Invalid('owned regular private review disk required')
        if mode == 'uefi':
            variables = source/'vars.fd';info = variables.lstat()
            if variables.is_symlink() or not variables.is_file() or info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise Invalid('owned regular private review firmware required')
    elif prior.get('status') != 'PASS-install-iso-phase':
        raise Invalid('successful earlier phase of the same firmware mode required')
    elif digest(image) != prior['disk_sha256']:
        raise Invalid('installed disk changed')
    subprocess.run(['cp', '--reflink=auto', str(image), str(output/'target.qcow2')], check=True)
    if mode == 'uefi':
        shutil.copyfile(source/'vars.fd', output/'vars.fd')
    return prior, previous


def run(phase, mode, output, iso=None, answers=None, previous=None, payload=None, expect=None, interactive=False, media='cd', vnc=None, hold=False, disk_gib=24, existing=None, scratch_disk=False, review_reboots=False, network=False, backup_usb=False, display_size=None, secure_firmware=False, rescue_iso=None, corrupt_live=False, guest_ram_mib=2048, internet=False, boot_seconds=None, resume_review=False):
    if type(resume_review) is not bool or (resume_review and (phase != 'boot' or not vnc or expect or payload or rescue_iso or hold or not previous)):
        raise Invalid('continued review requires an attended boot without qualification payloads or markers')
    if type(internet) is not bool or (internet and (not network or not vnc or phase != 'boot')):
        raise Invalid('outbound internet requires an attended boot with explicit network and VNC')
    if type(guest_ram_mib) is not int or guest_ram_mib not in (2048, 4096):raise Invalid('unsupported bounded guest RAM')
    if guest_ram_mib == 4096:
        memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        if int(memory['MemAvailable'].split()[0]) < 8*1024*1024:raise Invalid('4 GiB guest requires at least 8 GiB host available memory')
    if display_size not in (None, '800x600', '1024x768', '1280x800', '1920x1080'):raise Invalid('unsupported display size')
    if display_size and not vnc:raise Invalid('display size requires VNC')
    if os.geteuid() == 0:raise Invalid('run unprivileged')
    if backup_usb and not vnc:raise Invalid("backup USB requires the graphical test controller (--vnc)")
    if rescue_iso and (phase!='boot' or payload or not vnc or hold or interactive):raise Invalid('media rescue requires a VNC boot of a successful private disk without payload')
    if corrupt_live and (not rescue_iso or expect):raise Invalid('live corruption is an explicit negative media review, never a successful install qualification')
    # A longer unattended boot bound for payloads that do real work (whole-system backups).
    if boot_seconds is not None and (type(boot_seconds) is not int or phase != 'boot' or vnc or not 900 <= boot_seconds <= 4*3600):
        raise Invalid('boot_seconds is an unattended boot bound of 900 s to 4 h')
    resources = constrain_job()
    if mode not in ('uefi', 'bios') or phase not in ('install', 'boot'):raise Invalid('unknown phase/mode')
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR+3*1024**3:raise Invalid('insufficient headroom for a bounded install disk')
    output = new_output(output)
    result = {'status': 'FAIL', 'phase': phase, 'mode': mode, 'release_authorized': False, 'networking': ('explicit-outbound-user-nat-no-inbound-forwarding' if internet else 'isolated-user-ethernet') if network else False, 'guest_ram_mib': guest_ram_mib, 'vcpus': min(4, len(os.sched_getaffinity(0)))}
    process = None;started = time.monotonic()
    try:
        answers = Path(answers or FIX/'answers.env').resolve(strict=True)
        values = dict(line.split('=', 1) for line in answers.read_text().splitlines() if line and not line.startswith('#'))
        if phase == 'install':
            iso = Path(iso).resolve(strict=True);built = load(iso.parent/'build.json')
            if built['status'] != 'PASS-install-iso-built' or digest(iso) != built['iso_sha256']:raise Invalid('ISO does not match its build report')
            # hold: a human review install with no test volume; the VM runs until the guest restarts.
            if not interactive and not hold:answers_iso(output, answers, 'ENZIMOS_TESTCHECK' if vnc else 'ENZIMOS_ANSWERS')
            if disk_gib not in (24,64):raise Invalid('review disk must be 24 or 64 GiB')
            if existing:
                old=Path(existing).resolve(strict=True);prior=load(old)
                if prior.get('status')!='PASS-install-iso-phase' or digest(old.parent/'target.qcow2')!=prior.get('disk_sha256'):raise Invalid('review source disk identity mismatch')
                subprocess.run(['cp','--reflink=auto',str(old.parent/'target.qcow2'),str(output/'target.qcow2')],check=True)
                subprocess.run(sandbox(output)+['--','/usr/bin/qemu-img','resize','-q','/work/target.qcow2',str(disk_gib*1024**3)],check=True,timeout=30)
                # Expanding this PRIVATE fixture disk needs its backup GPT moved to
                # the new end. Operate on a regular raw file inside the lab sandbox;
                # never attach a host block device. Original partition bytes stay put.
                subprocess.run(sandbox(output)+['--','/usr/bin/qemu-img','convert','-f','qcow2','-O','raw','/work/target.qcow2','/work/expanded.raw'],check=True,timeout=180)
                before=json.loads(subprocess.check_output(sandbox(output)+['--','/usr/bin/sfdisk','--json','/work/expanded.raw']))['partitiontable']['partitions']
                subprocess.run(sandbox(output)+['--','/usr/bin/sfdisk','--relocate','gpt-bak-std','/work/expanded.raw'],check=True,timeout=30,stdout=subprocess.DEVNULL)
                after=json.loads(subprocess.check_output(sandbox(output)+['--','/usr/bin/sfdisk','--json','/work/expanded.raw']))['partitiontable']['partitions']
                if before!=after:raise Invalid('fixture expansion changed original partitions')
                subprocess.run(sandbox(output)+['--','/usr/bin/qemu-img','convert','-f','raw','-O','qcow2','/work/expanded.raw','/work/expanded.qcow2'],check=True,timeout=180)
                (output/'expanded.raw').unlink();os.replace(output/'expanded.qcow2',output/'target.qcow2')
                result['fixture_expanded_gpt']=True
                result['preserved_fixture_partitions']=before
                result['existing_result_sha256']=digest(old)
            else:
                subprocess.run(sandbox(output)+['--', '/usr/bin/qemu-img', 'create', '-q', '-f', 'qcow2', '/work/target.qcow2', str(disk_gib*1024**3)], check=True, timeout=30)
            result['disk_gib']=disk_gib
            if mode == 'uefi':shutil.copyfile('/usr/share/edk2/x64/OVMF_VARS.4m.fd', output/'vars.fd')
            result.update(iso_sha256=built['iso_sha256'], iso_manifest=built['manifest'], answers_sha256=digest(answers))
        else:
            prior, previous = clone_boot_source(previous, mode, output, resume_review)
            secure_firmware=secure_firmware or prior.get('secure_firmware',False)
            result.update(previous_result_sha256=digest(previous), iso_sha256=prior['iso_sha256'])
            if resume_review:result['continued_review'] = True
            if payload:result['update_package'] = payload_iso(output, payload)
        if rescue_iso:
            iso=Path(rescue_iso).resolve(strict=True);built=load(iso.parent/'build.json')
            if built['status']!='PASS-install-iso-built' or digest(iso)!=built['iso_sha256']:raise Invalid('rescue ISO identity changed')
            result['rescue_media_sha256']=built['iso_sha256']
            if corrupt_live:
                # Validate the original first. Mutate only a private copy, retaining
                # its signed boot image and signed expected squashfs digest.
                layout=subprocess.check_output(['xorriso','-indev',str(iso),'-find','/enzimos/live.sfs','-exec','report_lba','--'],text=True,stderr=subprocess.DEVNULL,timeout=60)
                matches=re.findall(r"File data lba:\s+0\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*'/enzimos/live.sfs'",layout)
                if len(matches)!=1:raise Invalid('exact single squashfs extent required for fault test')
                lba,blocks,size=map(int,matches[0]);offset=lba*2048+size//2
                if not (size>4096 and blocks*2048>=size and offset<iso.stat().st_size):raise Invalid('invalid squashfs fault extent')
                private=output/'fault-live.iso';shutil.copyfile(iso,private)
                with private.open('r+b') as stream:
                    stream.seek(offset);original=stream.read(1)
                    stream.seek(offset);stream.write(bytes([original[0]^1]));stream.flush();os.fsync(stream.fileno())
                result['negative_fault']={'kind':'live-squashfs-byte','offset':offset,'source_sha256':built['iso_sha256'],'mutated_sha256':digest(private),'qualification':False}
                iso=private
        if vnc and not 60 <= vnc <= 12*3600:raise Invalid('a VNC display is held for 1 min to 12 h')
        if vnc and phase == 'install' and interactive:raise Invalid('a graphical install is not the text dialogue')
        desktop = str(payload) in ('desktop', 'review-ui', 'live-ui-probe') or bool(vnc)
        if hold and not (vnc and phase == 'install'):raise Invalid('--hold is for a graphical install with --vnc')
        if scratch_disk:subprocess.run(sandbox(output)+['--','/usr/bin/qemu-img','create','-q','-f','qcow2','/work/scratch.qcow2',str(64*1024**3)],check=True,timeout=30)
        if backup_usb:
            if phase=='boot' and (previous.parent/'backup.qcow2').exists():
                rescue=previous.parent/'backup.qcow2'
                if not prior.get('backup_disk_sha256') or digest(rescue)!=prior['backup_disk_sha256']:raise Invalid('backup fixture disk identity mismatch')
                subprocess.run(['cp','--reflink=auto',str(rescue),str(output/'backup.qcow2')],check=True)
            else:subprocess.run(sandbox(output)+['--','/usr/bin/qemu-img','create','-q','-f','qcow2','/work/backup.qcow2',str(8*1024**3)],check=True,timeout=30)

        if display_size:result['display_size']=display_size
        # enzimOS's Plymouth theme takes the disk passphrase on screen only; an
        # unattended encrypted boot types it through a private VNC display.
        unlock_display = phase == 'boot' and not vnc and values.get('ENZIMOS_ENCRYPT') == 'yes'
        argv = qemu(output, mode, iso if phase == 'install' or rescue_iso else None, bool(payload), not interactive and not hold and not rescue_iso, media, desktop, bool(vnc), scratch_disk, network, backup_usb, display_size, secure_firmware, guest_ram_mib, internet, unlock_display,
                    # A long unattended boot (backup tests) keeps all vCPUs busy for hours;
                    # QEMU's CPU-time cap must follow the wall-clock bound.
                    cpu_seconds=boot_seconds*4+600 if boot_seconds else None)
        if review_reboots:
            if not vnc or phase!='boot':raise Invalid('review reboots require a VNC boot')
            argv.remove('-no-reboot')
        result['media'] = media
        script = dialogue(values) if interactive else [];position = 0;replies = 0
        result['interactive'] = interactive
        (output/'command.json').write_text(json.dumps(argv, indent=2)+'\n')
        passphrase = (values.get('ENZIMOS_PASSPHRASE', '')+'\n').encode();sent = False;recovery_prompts=0;unlock_at = None;unlock_typed = 0
        with (output/'serial.log').open('wb') as log, (output/'stderr.log').open('wb') as errors:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=log, stderr=errors, env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
            qmp = Qmp(output/'qmp.sock') if desktop else None;shots = []
            deadline = time.monotonic()+(vnc or (2400 if phase == 'install' else boot_seconds or 900))
            review_log_start = 0; hold_reboot_count = 0
            while True:
                if process.poll() is not None:
                    # Human review: a reboot before completing installation boots the same
                    # private disk and medium again. Shutdown must remain a shutdown.
                    recent = read_log(output/'serial.log')[review_log_start:]
                    if hold and process.returncode == 0 and time.monotonic() < deadline and 'reboot: Restarting system' in recent and 'ENZIMOS_INSTALL_PASS' not in recent:
                        if qmp is not None:
                            qmp.file.close();qmp.sock.close()
                        review_log_start = len(read_log(output/'serial.log'))
                        hold_reboot_count += 1
                        result['review_reboots'] = hold_reboot_count
                        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=log, stderr=errors, env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
                        qmp = Qmp(output/'qmp.sock') if desktop else None
                        continue
                    break
                if vnc and time.monotonic() > deadline:break
                if vnc and phase == 'install' and not hold and 'ENZIMOS_INSTALL_PASS' in read_log(output/'serial.log'):
                    # The graphical installer has finished (disk synced and unmounted); stop here.
                    time.sleep(5);process.terminate();process.wait(timeout=30);break
                if time.monotonic() > deadline or (output/'serial.log').stat().st_size > MAX_LOG:raise Invalid('VM time/log bound reached')
                if shutil.disk_usage(output).free < FREE_FLOOR:raise Invalid('free-space floor reached; stopping VM')
                if replies < len(script):
                    text = read_log(output/'serial.log');pattern, reply = script[replies]
                    found = text.find(pattern, position)
                    if found >= 0:
                        time.sleep(0.7)
                        for index, part in enumerate(reply.split(b'\x00')):
                            if index:time.sleep(0.5)
                            process.stdin.write(part);process.stdin.flush()
                        position = found+len(pattern);replies += 1
                if qmp is not None:
                    text = read_log(output/'serial.log')
                    if 'ENZIMOS_REVIEW_UI_UP' in text and 'review' not in shots:
                        time.sleep(10);qmp.screenshot(output, 'review');shots.append('review')
                    if 'ENZIMOS_DESKTOP_GREETER_UP' in text and 'greeter' not in shots:
                        time.sleep(12);qmp.screenshot(output, 'greeter');shots.append('greeter')
                        qmp.call('send-key', keys=[{'type': 'qcode', 'data': 'shift'}]);time.sleep(2);qmp.screenshot(output, 'greeter-field')
                        qmp.type(values['ENZIMOS_PASSWORD']+'\n');result['greeter_login_typed'] = True
                    if 'ENZIMOS_DESKTOP_SESSION_UP' in text and 'desktop' not in shots:
                        time.sleep(20);qmp.screenshot(output, 'desktop');shots.append('desktop')
                        time.sleep(15);qmp.screenshot(output, 'desktop-later')
                    if 'ENZIMOS_DESKTOP_APP_UP' in text and 'app' not in shots:
                        time.sleep(8);qmp.screenshot(output, 'app');shots.append('app')
                    if 'ENZIMOS_DESKTOP_TIMEOUT' in text and 'timeout' not in shots:
                        qmp.screenshot(output, 'timeout');shots.append('timeout')
                count=read_log(output/'serial.log').count('ENZIMOS recovery passphrase:')
                if review_reboots and expect and values.get('ENZIMOS_ENCRYPT')=='yes' and count>recovery_prompts:
                    process.stdin.write(passphrase);process.stdin.flush();recovery_prompts=count
                if phase == 'boot' and (not vnc or expect) and not sent and values.get('ENZIMOS_ENCRYPT') == 'yes' and 'Please enter passphrase for disk' in read_log(output/'serial.log'):
                    time.sleep(1);process.stdin.write(passphrase);process.stdin.flush();sent = True
                if unlock_display and not sent:
                    text = read_log(output/'serial.log')
                    # SeaBIOS has no BdsDxe serial handoff marker. Its private
                    # graphical unlock uses the same bounded boot-time delay.
                    firmware_started = mode == 'bios' or 'BdsDxe: starting' in text
                    if firmware_started and unlock_typed < 3 and 'ENZIMOS_FIRSTBOOT' not in text:
                        now = time.monotonic()
                        if unlock_at is None:unlock_at = now + 60
                        elif now >= unlock_at:
                            vnc_unlock(output, values['ENZIMOS_PASSPHRASE']);unlock_typed += 1;unlock_at = now + 120
                    if 'ENZIMOS_FIRSTBOOT' in text and unlock_typed:sent = True
                time.sleep(0.5)
        result['process_returncode'] = process.returncode
        text = read_log(output/'serial.log')
        if hold:text = text[review_log_start:]
        if vnc and phase == 'install':
            if 'ENZIMOS_INSTALL_FAILURE' in text or 'ENZIMOS_INSTALL_PASS' not in text:raise Invalid('graphical installation did not report success')
            line = next(l.strip() for l in text.splitlines() if l.strip().startswith('ENZIMOS_INSTALL_PASS'))
            result.update(status='PASS-install-iso-phase', graphical_install=True, secure_firmware=secure_firmware, marker_line=line, install_line=line, passphrase_sent=False,
                          disk_sha256=digest(output/'target.qcow2'), serial_sha256=digest(output/'serial.log'), checked_at=datetime.now(timezone.utc).isoformat(), host_resource_policy=resources)
            return result
        if vnc and not expect:
            result.update(status='REVIEW-ENDED', review_display=True, qualification=False, passphrase_sent=sent,
                          review_ui_up='ENZIMOS_REVIEW_UI_UP' in text, checked_at=datetime.now(timezone.utc).isoformat())
            return result
        for bad in ('ENZIMOS_INSTALL_FAILURE', 'Kernel panic - not syncing', 'ENZIMOS_FIRSTBOOT_FAIL', 'ENZIMOS_FIRSTBOOT_INCOMPLETE', 'ENZIMOS_UPDATE_FAILURE', 'ENZIMOS_NETWORK_FAIL', 'Traceback (most recent call last)'):
            if bad in text:raise Invalid('guest reported failure: '+bad)
        marker = expect or ('ENZIMOS_INSTALL_PASS' if phase == 'install' else 'ENZIMOS_FIRSTBOOT_PASS')
        # Terminal capability replies can precede a service's first output on
        # the same line. Remove only complete ANSI controls, retaining every
        # printable byte and requiring the full firmware marker below.
        plain = re.sub(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|[P\]][^\x1b\x07]*(?:\x1b\\|\x07)|[78])', '', text)
        lines = [l.strip() for l in plain.splitlines()]
        if process.returncode != 0 or not any(l.startswith(marker) for l in lines) or not ('reboot: Power down' in text or 'reboot: Restarting system' in text):raise Invalid('required marker/clean poweroff or reboot missing')
        result['marker_line'] = next(l for l in lines if l.startswith(marker))
        if phase == 'boot' and not rescue_iso:
            if values.get('ENZIMOS_ENCRYPT') == 'yes' and not sent and not vnc:raise Invalid('LUKS passphrase interaction not observed')
            if f'ENZIMOS_FIRSTBOOT_FIRMWARE {mode}' not in lines:raise Invalid('installed system booted in the wrong firmware mode')
            result['checks'] = sorted(l.split(' ', 1)[1] for l in lines if l.startswith('ENZIMOS_FIRSTBOOT_OK '))
        else:
            result['install_line'] = next(l for l in lines if l.startswith(marker))
            if interactive and replies != len(script):raise Invalid('interactive dialogue incomplete: %d/%d replies' % (replies, len(script)))
            result['dialogue_replies'] = replies
        result.update(status='PASS-install-iso-phase', secure_firmware=secure_firmware, passphrase_sent=sent, disk_sha256=digest(output/'target.qcow2'), serial_sha256=digest(output/'serial.log'),
                      checked_at=datetime.now(timezone.utc).isoformat(), host_resource_policy=resources)
        return result
    except BaseException as exc:
        result['failure'] = str(exc) if isinstance(exc, Invalid) else type(exc).__name__;raise
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        if backup_usb and (output/'backup.qcow2').exists():result['backup_disk_sha256']=digest(output/'backup.qcow2')
        result['elapsed_seconds'] = round(time.monotonic()-started, 1)
        (output/'result.json').write_text(json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('phase', choices=('install', 'boot'));p.add_argument('--mode', choices=('uefi', 'bios'), required=True)
    p.add_argument('--rescue-iso',type=Path,help='attach verified installer ISO to a successful private boot disk for attended independent RAM rescue');p.add_argument('--secure-firmware',action='store_true',help='private VM only: use OVMF Secure Boot-capable firmware');p.add_argument('--output', type=Path, required=True);p.add_argument('--iso', type=Path);p.add_argument('--answers', type=Path);p.add_argument('--previous', type=Path);p.add_argument('--payload', type=Path);p.add_argument('--expect');p.add_argument('--interactive', action='store_true');p.add_argument('--media', choices=('cd', 'disk'), default='cd')
    p.add_argument('--review-reboots',action='store_true',help='allow an attended VNC boot to restart within the same bounded review')
    p.add_argument('--resume-review',action='store_true',help='continue the current private disk from REVIEW-ENDED; attended only, never qualification')
    p.add_argument('--corrupt-live',action='store_true',help='negative test only: alter one squashfs byte in a private copy of --rescue-iso')
    p.add_argument('--backup-usb',action='store_true',help='attach a private 8 GiB USB file-rescue test disk; requires --vnc')
    p.add_argument('--scratch-disk',action='store_true',help='attach a blank private 64 GiB partition-test disk')
    p.add_argument('--boot-seconds',type=int,help='unattended boot bound for long payloads (900 s to 4 h; default 900 s)')
    p.add_argument('--disk-gib',type=int,choices=(24,64),default=24);p.add_argument('--existing',type=Path,help='clone a successful private install disk for alongside testing')
    p.add_argument('--hold', action='store_true', help='graphical install for human review: no test volume, run until the guest restarts')
    p.add_argument('--network', action='store_true', help='isolated virtual Ethernet with DHCP; no external network or host forwarding')
    p.add_argument('--internet', action='store_true', help='explicit outbound user-mode NAT for attended boot fixtures; requires --network and --vnc, no inbound forwarding')
    p.add_argument('--vnc', type=int, metavar='SECONDS', help='hold a VNC display on /work/vnc.sock (boot: review; install: graphical installer)')
    p.add_argument('--display-size', choices=('800x600','1024x768','1280x800','1920x1080'), help='preferred virtual monitor resolution for VNC')
    a = p.parse_args()
    try:print(json.dumps(run(a.phase, a.mode, a.output, a.iso, a.answers, a.previous, a.payload, a.expect, a.interactive, a.media, a.vnc, a.hold, a.disk_gib, a.existing, a.scratch_disk, a.review_reboots, a.network, a.backup_usb, a.display_size, a.secure_firmware, a.rescue_iso, a.corrupt_live, internet=a.internet, boot_seconds=a.boot_seconds, resume_review=a.resume_review), indent=2))
    except (Invalid, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc)}), file=sys.stderr);raise SystemExit(2)
