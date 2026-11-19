# SPDX-License-Identifier: MIT
"""Disposable VM only: retain a qualified root, then break its init executable."""
import os,subprocess,sys
from pathlib import Path
sys.path.insert(0,'/usr/lib/enzimos')
import native,root_ownership as birth,generation_registry as registry,secure_boot
# Optional private USB fixture for the media's authenticated file-copy terminal.
usb=subprocess.check_output(['lsblk','-dn','-o','NAME,SERIAL,SIZE','--bytes'],text=True).splitlines()
devices=[line.split()[0] for line in usb if len(line.split())==3 and line.split()[1:] == ['enzimos-rescue',str(8*1024**3)]]
if devices:
    assert len(devices)==1 and devices[0].startswith('sd')
    subprocess.run(['mkfs.ext4','-F','-L','ENZIMOS_RESCUE_USB','/dev/'+devices[0]],check=True)
    print('ENZIMOS_MEDIA_PRIVATE_USB_READY',flush=True)
for unit in ('enzimos-home-history.timer','enzimos-backup.timer','enzimos-scrub.timer','enzimos-trim.timer','enzimos-deferred.timer','snapper-cleanup.timer','snapper-timeline.timer'):
    subprocess.run(['systemctl','stop',unit],check=True)
Path('/etc/enzimos-media-marker').write_text('SNAPSHOT BEFORE DAMAGE\n')
# The verifier is in the retained snapshot; it runs only after automatic adoption.
Path('/usr/local/bin/enzimos-media-verify.py').write_text('''import json,sys,subprocess
from pathlib import Path
sys.path.insert(0,'/usr/lib/enzimos')
import recovery_activation,media_rescue,generation_registry as registry
markers=[x.split('=',1)[1] for x in Path('/proc/cmdline').read_text().split() if x.startswith('enzimos.staged=')]
assert len(markers)==1
identifier=markers[0]
assert recovery_activation.records()[identifier]['phase']=='adopted'
assert json.loads((registry.CONTROL/'media-restores'/(identifier+'.json')).read_text())['phase']=='complete'
assert Path('/etc/enzimos-media-marker').read_text()=='SNAPSHOT BEFORE DAMAGE\\n'
assert Path('/home/admin/media-preservation.txt').read_text()=='PERSONAL FILE AFTER SNAPSHOT\\n'
assert (registry.CONTROL/'updates/post-snapshot-marker').read_text()=='TUF CONTROL MUST SURVIVE\\n'
assert (registry.CONTROL/'updates/metadata/timestamp.json').is_file()
assert not Path('/run/enzimos-recovery-needed').exists()
print('ENZIMOS_FIRSTBOOT_FIRMWARE '+('uefi' if Path('/sys/firmware/efi').is_dir() else 'bios'),flush=True)
print('ENZIMOS_MEDIA_ADOPTED_PASS '+identifier,flush=True)
subprocess.run(['systemctl','--no-block','poweroff'],check=True)
''')
unit=Path('/etc/systemd/system/enzimos-media-verify.service')
unit.write_text('[Unit]\nDescription=Private media restore verification\nAfter=enzimos-recovery-session-state.service\nBefore=greetd.service\nConditionKernelCommandLine=enzimos.staged\n[Service]\nType=oneshot\nExecStart=/usr/bin/python /usr/local/bin/enzimos-media-verify.py\nStandardOutput=tty\nTTYPath=/dev/ttyS0\n[Install]\nWantedBy=multi-user.target\n')
subprocess.run(['systemctl','enable','enzimos-media-verify.service'],check=True)
with native.operation_lock():
    created=birth.create_fallback('media-before-damage')
    native.publish_boot('/boot','media-before-damage',native.installed_kernels(),native.root_options(Path('/proc/cmdline').read_text().strip(),created['subvolume']))
Path('/home/admin/media-preservation.txt').write_text('PERSONAL FILE AFTER SNAPSHOT\n')
(registry.CONTROL/'updates/post-snapshot-marker').write_text('TUF CONTROL MUST SURVIVE\n')
Path('/etc/enzimos-media-marker').write_text('BROKEN CURRENT SYSTEM\n')
# Only this VM's normal installed root is damaged. Original ELF remains in snapshot.
damaged=Path('/usr/lib/systemd/systemd.private-damaged')
damaged.write_bytes(b'This private VM init executable was intentionally damaged.\n');damaged.chmod(0o755)
os.replace(damaged,'/usr/lib/systemd/systemd')
os.sync()
print('ENZIMOS_FIRSTBOOT_FIRMWARE '+('uefi' if Path('/sys/firmware/efi').is_dir() else 'bios'),flush=True)
print('ENZIMOS_MEDIA_PREPARE_PASS',flush=True)
