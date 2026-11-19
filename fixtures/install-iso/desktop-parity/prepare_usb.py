# SPDX-License-Identifier: MIT
"""TEST ONLY: format the harness's fresh private 8GiB USB before account login."""
import json
from pathlib import Path
import subprocess
import time

def command(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=30).stdout

disks = json.loads(command(['lsblk', '-J', '--tree', '-b', '-o', 'PATH,SERIAL,SIZE,TRAN,FSTYPE,MOUNTPOINTS']))['blockdevices']
usb = [d for d in disks if d.get('serial') == 'enzimos-rescue']
assert len(usb) == 1 and usb[0]['size'] == 8 * 1024**3 and usb[0]['tran'] == 'usb'
assert usb[0].get('fstype') is None and not any(usb[0].get('mountpoints') or []) and not usb[0].get('children')
disk = usb[0]['path']
subprocess.run(['sfdisk', '--quiet', '--wipe', 'always', disk],
               input='label: gpt\nstart=2048, type=L\n', text=True, check=True, timeout=30)
command(['udevadm', 'settle', '--timeout=15'])
for _ in range(20):
    layout = json.loads(command(['lsblk', '-J', '--tree', '-o', 'PATH,TYPE,PKNAME', disk]))['blockdevices']
    parts = layout[0].get('children', [])
    if len(parts) == 1 and Path(parts[0]['path']).is_block_device():
        break
    time.sleep(.5)
else:
    raise AssertionError('private fixture USB partition not ready')
assert parts[0]['type'] == 'part' and parts[0]['pkname'] in (disk, Path(disk).name)
filesystem = parts[0]['path']
command(['mkfs.ext4', '-q', '-L', 'enzimos-testusb', filesystem])
command(['udevadm', 'settle', '--timeout=15'])
state = {'disk': disk, 'filesystem': filesystem, 'label': 'enzimos-testusb',
         'fixture_only': True, 'previously_empty': True}
Path('/run/enzimos-parity-usb.json').write_text(json.dumps(state))
Path('/run/enzimos-parity-usb-device').write_text(filesystem)
Path('/run/enzimos-parity-usb-device').chmod(0o644)
print('ENZIMOS_PARITY_PRIVATE_USB_PREPARED', flush=True)
