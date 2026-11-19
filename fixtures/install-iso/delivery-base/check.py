# SPDX-License-Identifier: MIT
"""Guest-only actual installed gaming/owner-UKI qualification."""
import json,os,subprocess,sys
from pathlib import Path
sys.path.insert(0,'/usr/lib/enzimos')
if Path('/run/enzimos-testpayload/secure_boot.py').exists():
    sys.path.insert(0,'/run/enzimos-testpayload')
    print('ENZIMOS_PRIVATE_RAM_FIRMWARE_API_OVERLAY',flush=True)
import native,secure_boot,root_ownership as birth,generation_registry as registry

def run(*args):return subprocess.check_output([str(x) for x in args],text=True,stderr=subprocess.STDOUT,timeout=180)
failures=[]
def checked(name,value):
    if not value:failures.append(name)
    print(('ENZIMOS_DELIVERY_BASE_OK ' if value else 'ENZIMOS_DELIVERY_BASE_FAIL ')+name,flush=True)

print('ENZIMOS_ZRAM_DIAGNOSTIC '+run('swapon','--show'),flush=True)
print(run('systemctl','cat','dev-zram0.swap'),flush=True)
print(Path('/usr/lib/systemd/zram-generator.conf.d/20-enzimos.conf').read_text(),flush=True)
checked('zram-active',run('swapon','--show=NAME,PRIO','--raw','--noheadings').find('/dev/zram0')>=0)
checked('zram-priority',any(line.split()==['/dev/zram0','100'] for line in run('swapon','--show=NAME,PRIO','--raw','--noheadings').splitlines()))
checked('zram-compression','[zstd]' in Path('/sys/block/zram0/comp_algorithm').read_text())
checked('zswap-off',Path('/sys/module/zswap/parameters/enabled').read_text().strip()=='N')
checked('swappiness',Path('/proc/sys/vm/swappiness').read_text().strip()=='150')
checked('swap-page-cluster',Path('/proc/sys/vm/page-cluster').read_text().strip()=='0')
memory=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:')))*1024
checked('zram-size',abs(int(Path('/sys/block/zram0/disksize').read_text())-min(memory,8*2**30))<2**20)
checked('tmp-tmpfs',run('findmnt','-n','-o','FSTYPE','/tmp').strip()=='tmpfs')
checked('dirty-bytes',Path('/proc/sys/vm/dirty_bytes').read_text().strip()=='268435456' and Path('/proc/sys/vm/dirty_background_bytes').read_text().strip()=='67108864')
checked('stop-timeout',run('systemctl','show','-P','DefaultTimeoutStopUSec').strip()=='45s')
checked('login-editor',run('su','-','admin','-c','printf %s "$EDITOR"').strip()=='nano')
for command in ('less','man','unzip','zip','7z','htop','lsof','tree','wget','hostname'):
    checked('command-'+command,subprocess.run(['sh','-c','command -v '+command],stdout=subprocess.DEVNULL).returncode==0)
checked('bash-completion',Path('/usr/share/bash-completion/bash_completion').is_file())
for name in ('lib32-mesa','lib32-vulkan-intel','lib32-vulkan-radeon','lib32-vulkan-nouveau','lib32-pipewire','lib32-alsa-plugins','lib32-gamemode','gamemode','ttf-liberation','enzimos-update-client'):
    checked('installed-'+name,any(line.startswith(name+' ') for line in run('pacman','-Q',name).splitlines()))
for path in ('/usr/lib32/libvulkan_intel.so','/usr/lib32/libvulkan_radeon.so','/usr/lib32/libgamemode.so.0'):
    checked('elf32-'+Path(path).name,'ELF 32-bit' in run('file','-L',path))
for path in ('/usr/lib32/libvulkan_intel.so','/usr/lib32/libvulkan_radeon.so','/usr/lib32/libgamemode.so.0'):
    dependencies=run('/usr/lib/ld-linux.so.2','--list',path)
    checked('resolved32-'+Path(path).name,'not found' not in dependencies)
pressure=Path('/run/enzimos-zram-pressure.py')
pressure.write_text("from pathlib import Path\nimport time\nx=bytearray(200*1024**2)\nfor p in range(0,len(x),4096):x[p]=123\ntime.sleep(1)\nPath('/run/enzimos-zram-pressure.result').write_text(Path('/sys/block/zram0/mm_stat').read_text())\n")
run('systemd-run','--quiet','--wait','--pipe','--unit=enzimos-zram-pressure','-p','MemoryMax=128M','-p','MemorySwapMax=256M','python',pressure)
checked('zram-real-pressure',int(Path('/run/enzimos-zram-pressure.result').read_text().split()[0])>0)
checked('multilib-enabled','[multilib]\nInclude = /etc/pacman.d/mirrorlist' in Path('/etc/pacman.conf').read_text())
checked('ntsync-device',Path('/dev/ntsync').is_char_device())
checked('gamemode-member','gamemode' in run('id','-nG','admin').split())
checked('esync-limit',int(run('su','-','admin','-c','ulimit -n').strip())>=524288)
checked('game-memory-mappings',int(Path('/proc/sys/vm/max_map_count').read_text())>=1048576)
checked('no-game-launchers',not any(subprocess.run(['pacman','-Q',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0 for name in ('steam','lutris','wine','heroic-games-launcher')))
checked('refresh-not-enabled',subprocess.run(['systemctl','is-enabled','--quiet','enzimos-update-refresh.timer']).returncode!=0)
checked('firmware-off',secure_boot.firmware()['uefi'] and not secure_boot.firmware()['enabled'])
# Stop maintenance timers so the explicit key/UKI stage has exclusive admission.
for unit in ('enzimos-home-history.timer','enzimos-scrub.timer','enzimos-trim.timer','enzimos-deferred.timer','snapper-cleanup.timer'):
    subprocess.run(['systemctl','stop',unit],check=True)
# Enabling on an existing managed generation must retain its verified bindings.
with native.operation_lock():
    created=birth.create_fallback('signed-before-enable')
    native.publish_boot('/boot','signed-before-enable',native.installed_kernels(),native.root_options(Path('/proc/cmdline').read_text().strip(),created['subvolume']))
secure_boot.create_key();secure_boot.enable()
with registry.catalog_transaction() as (_,_,catalog):
    for record in catalog['generations'].values():checked('catalog-'+record['generation'],registry.entry_fingerprints(record)==record['entry_fingerprints'])
for entry in Path('/boot/loader/entries').glob('*.conf'):
    fields=native.entry_fields(entry.read_text(),None);secure_boot.verify_entry(fields)
    checked('signed-'+entry.name,'uki' in fields and not any(line.startswith(('linux ','initrd ')) for line in entry.read_text().splitlines()))
if Path('/run/enzimos-testpayload/enroll-firmware').exists():
    state=secure_boot.firmware();assert state['capable'] and state['setup_mode'] and not state['enabled']
    esl=Path('/run/enzimos-lab-owner.esl')
    subprocess.run(['cert-to-efi-sig-list','-g','26a5e497-2929-4ac1-a6b9-f7c4938697c4',str(secure_boot.DIRECTORY/'owner.crt'),str(esl)],check=True)
    # Explicit disposable VM keys only, never a user machine's firmware.
    subprocess.run(['mount','-o','remount,rw','/sys/firmware/efi/efivars'],check=True)
    try:
        media_esl=Path('/run/enzimos-lab-media.esl')
        subprocess.run(['cert-to-efi-sig-list','/run/enzimos-testpayload/media-owner.crt',str(media_esl)],check=True)
        subprocess.run(['efi-updatevar','-e','-f',str(media_esl),'db'],check=True)
        print(secure_boot.enroll_db(),flush=True)
        assert secure_boot.db_contains((secure_boot.EFI/('db-'+secure_boot.DB_GUID)).read_bytes(),(secure_boot.DIRECTORY/'owner.cer').read_bytes())
        subprocess.run(['efi-updatevar','-e','-f',str(esl),'KEK'],check=True)
        auth=Path('/run/enzimos-lab-platform.auth')
        subprocess.run(['sign-efi-sig-list','-k',str(secure_boot.DIRECTORY/'owner.key'),'-c',str(secure_boot.DIRECTORY/'owner.crt'),'PK',str(esl),str(auth)],check=True)
        subprocess.run(['efi-updatevar','-f',str(auth),'PK'],check=True)
    finally:subprocess.run(['mount','-o','remount,ro','/sys/firmware/efi/efivars'],check=True)
    checked('owner-firmware-enrollment',True)
Path('/etc/systemd/system/enzimos-firstboot-check.service').unlink(missing_ok=True)
subprocess.run(['systemctl','disable','enzimos-firstboot-check.service'],check=True)
driver=Path('/usr/lib/enzimos-test/lab-payload.sh')
driver.write_text('''#!/usr/bin/bash
set -eu
payload=$(blkid -L ENZIMOS_TESTPAYLOAD 2>/dev/null || true)
[[ -n $payload ]] || exit 0
mkdir -p /run/enzimos-testpayload
mount -o ro "$payload" /run/enzimos-testpayload
printf '\\nENZIMOS_FIRSTBOOT_FIRMWARE uefi\\n'
exec /usr/bin/bash /run/enzimos-testpayload/run.sh
''');driver.chmod(0o755)
unit=Path('/etc/systemd/system/enzimos-lab-payload.service')
unit.write_text('[Unit]\nDescription=Private VM qualification payload\nAfter=multi-user.target enzimos-recovery-session-state.service\n[Service]\nType=simple\nExecStart=/usr/lib/enzimos-test/lab-payload.sh\nStandardOutput=tty\nTTYPath=/dev/ttyS0\n[Install]\nWantedBy=multi-user.target\n')
subprocess.run(['systemctl','enable','enzimos-lab-payload.service'],check=True)
assert not failures,failures
print('ENZIMOS_DELIVERY_BASE_PASS',flush=True)
