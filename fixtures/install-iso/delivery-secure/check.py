# SPDX-License-Identifier: MIT
"""Actual later firmware boot verifies enabled state, signed payloads, module loaders."""
import json,subprocess,sys,shutil,tempfile
from pathlib import Path
sys.path.insert(0,'/usr/lib/enzimos')
import secure_boot,native,generation_registry as registry
subprocess.run(['systemd-analyze','verify','--man=no','--generators=no','/run/enzimos-testpayload/enzimos-update-server.service'],check=True)
state=secure_boot.firmware();assert state['enabled'] and not state['setup_mode'],state
assert secure_boot.configured()
layout=native.output(['sfdisk','--dump','/dev/vda'])
with tempfile.TemporaryDirectory(prefix='installer-preflight-',dir='/run') as temp:
    credentials=Path(temp)/'owner';credentials.mkdir(mode=0o700)
    for name in ('owner.key','owner.crt','owner.cer'):
        shutil.copyfile(secure_boot.DIRECTORY/name,credentials/name)
        (credentials/name).chmod(0o600 if name=='owner.key' else 0o644)
    assert secure_boot.installer_preflight(True,credentials)
    for encrypted,directory in ((False,credentials),(True,Path(temp)/'missing')):
        try:secure_boot.installer_preflight(encrypted,directory)
        except native.Failure:pass
        else:raise AssertionError('unsafe installer preflight accepted')
    original=secure_boot.DIRECTORY
    try:
        secure_boot.DIRECTORY=Path(temp)/'unenrolled';secure_boot.create_key()
        try:secure_boot.installer_preflight(True,secure_boot.DIRECTORY)
        except native.Failure:pass
        else:raise AssertionError('unenrolled owner certificate accepted')
    finally:secure_boot.DIRECTORY=original
assert native.output(['sfdisk','--dump','/dev/vda'])==layout
print('ENZIMOS_DELIVERY_INSTALLER_PREFLIGHT_PASS',flush=True)
for entry in Path('/boot/loader/entries').glob('*.conf'):secure_boot.verify_entry(native.entry_fields(entry.read_text(),None))
with registry.catalog_transaction() as (_,_,catalog):
    for record in catalog['generations'].values():assert registry.entry_fingerprints(record)==record['entry_fingerprints']
# A repair publication reuses trusted loader receipts rather than unsigned bootctl.
secure_boot.refresh_loaders()
assert Path('/etc/systemd/system/systemd-boot-update.service').is_symlink()
assert subprocess.run(['systemctl','is-enabled','systemd-boot-update.service'],capture_output=True,text=True).stdout.strip()=='masked'
print('ENZIMOS_DELIVERY_SECURE_STATE '+json.dumps(state),flush=True)
print('ENZIMOS_DELIVERY_LOCKDOWN '+Path('/sys/kernel/security/lockdown').read_text().strip(),flush=True)
print('ENZIMOS_FIRSTBOOT_FIRMWARE uefi',flush=True)
print('ENZIMOS_DELIVERY_SECURE_PASS',flush=True)
