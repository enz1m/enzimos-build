# SPDX-License-Identifier: MIT
"""Disposable VM only: flip a signed UKI payload byte, retaining the trusted loader."""
import os,struct,subprocess,sys
from pathlib import Path
sys.path.insert(0,'/usr/lib/enzimos')
import secure_boot,native
assert secure_boot.firmware()['enabled']
filename=next(line.split()[1] for line in Path('/boot/loader/loader.conf').read_text().splitlines() if line.startswith('default '))
assert '/' not in filename and '*' not in filename
fields=native.entry_fields((Path('/boot/loader/entries')/filename).read_text(),None);secure_boot.verify_entry(fields)
p=secure_boot.source_path(fields['uki']);body=bytearray(p.read_bytes());header=struct.unpack_from('<I',body,60)[0];count=struct.unpack_from('<H',body,header+6)[0];optional=struct.unpack_from('<H',body,header+20)[0]
for number in range(count):
    pos=header+24+optional+number*40
    if body[pos:pos+8].rstrip(b'\0')==b'.cmdline':
        offset=struct.unpack_from('<I',body,pos+20)[0];body[offset]^=1;break
else:raise AssertionError('missing signed command line')
p.write_bytes(body)
result=subprocess.run(['sbverify','--cert',str(secure_boot.DIRECTORY/'owner.crt'),str(p)],capture_output=True)
assert result.returncode!=0,'altered signature accepted'
print('ENZIMOS_TAMPERED_IMAGE '+fields['uki'],flush=True);os.sync()
print('ENZIMOS_FIRSTBOOT_FIRMWARE uefi',flush=True)
print('ENZIMOS_TAMPER_PREPARE_PASS',flush=True)
