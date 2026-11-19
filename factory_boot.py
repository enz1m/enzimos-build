#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline admission of signed factory-chain candidates, never release authorization.

Public certificates/policy are explicit operator inputs. This does not enroll keys,
invoke a signer, install loaders, trust Microsoft certificates automatically, or
turn preparation evidence into firmware/OS qualification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

from contract import Invalid, digest

ROLES = ('shim', 'loader', 'installer', 'normal', 'lts', 'recovery')
UKIS = frozenset(ROLES[2:])
MAX_PE = 256 * 1024**2
SHIM_SOURCE_SHA256 = '46319cd228d8f2c06c744241c0f342412329a7c630436fce7f82cf6936b1d603'
TARGETS = {'shim':'EFI/BOOT/BOOTX64.EFI', 'loader':'EFI/BOOT/enzimosx64.efi',
           **{r:f'EFI/Linux/enzimos-{r}.efi' for r in UKIS}}


def require(ok, message):
    if not ok: raise Invalid(message)


def read(path, limit):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink input refused')
    require(path.is_file() and 0 < path.stat().st_size <= limit, 'input size/type bound')
    require(not path.stat().st_mode & 0o022, 'writable by other users')
    with path.open('rb') as f:
        body = f.read(limit + 1)
    require(0 < len(body) <= limit, 'input changed beyond bound')
    return body


def pe(body):
    """Strict x86-64 EFI PE32+ parser; certificate table uses file offsets."""
    require(len(body) >= 64 and body[:2] == b'MZ', 'invalid DOS header')
    offset = struct.unpack_from('<I', body, 60)[0]
    require(64 <= offset and offset + 24 <= len(body) and body[offset:offset+4] == b'PE\0\0', 'invalid PE header')
    machine, count = struct.unpack_from('<HH', body, offset+4)
    optional = struct.unpack_from('<H', body, offset+20)[0]
    start = offset+24
    require(machine == 0x8664 and 0 < count <= 64 and optional >= 152 and start+optional+40*count <= len(body), 'unsupported PE architecture/headers')
    require(struct.unpack_from('<H', body, start)[0] == 0x20b, 'PE32+ required')
    subsystem, flags = struct.unpack_from('<HH', body, start+68)
    require(subsystem == 10 and flags & 0x100, 'EFI application with NX compatibility required')
    directories = struct.unpack_from('<I', body, start+108)[0]
    require(5 <= directories <= (optional-112)//8, 'PE directory bound')
    certificate, size = struct.unpack_from('<II', body, start+112+4*8)
    require(certificate > 0 and certificate % 8 == 0 and size >= 8 and certificate+size == len(body), 'bounded terminal Authenticode table required')
    position = certificate
    while position < certificate+size:
        require(position+8 <= certificate+size, 'truncated certificate header')
        length, revision, kind = struct.unpack_from('<IHH', body, position)
        require(length >= 8 and position+length <= certificate+size and revision == 0x200 and kind == 2, 'invalid Authenticode certificate')
        position += (length+7)&~7
    require(position == certificate+size, 'certificate alignment bound')
    parts = {}; ranges = []
    for i in range(count):
        p = start+optional+i*40
        try: name = body[p:p+8].rstrip(b'\0').decode('ascii')
        except UnicodeError: raise Invalid('non-ASCII section')
        virtual, _, size, raw = struct.unpack_from('<IIII', body, p+8)
        require(name and name not in parts and raw+size <= certificate, 'section name/range bound')
        if size:
            require(raw >= start+optional+count*40 and all(raw+size <= a or raw >= b for a,b in ranges), 'overlapping PE sections')
            ranges.append((raw,raw+size))
        require(name not in ('.sbat','.linux','.initrd','.cmdline') or 0 < virtual <= size, 'truncated authenticated section')
        parts[name] = body[raw:raw+min(virtual,size)]
    return parts


def sbat(body):
    require(0 < len(body) <= 65536, 'SBAT size bound')
    try: text = body.rstrip(b'\0').decode('ascii')
    except UnicodeError: raise Invalid('invalid SBAT encoding')
    require(text.endswith('\n') and '\0' not in text, 'SBAT newline/NUL policy')
    rows = {}
    for line in text.splitlines():
        fields = line.split(',')
        require(len(fields) == 6 and all(fields) and all(32 <= ord(c) < 127 for c in line), 'invalid SBAT row')
        name, generation = fields[:2]
        require(re.fullmatch(r'[A-Za-z0-9_.-]+',name) and name not in rows and re.fullmatch(r'[1-9][0-9]{0,8}',generation), 'invalid/duplicate SBAT identity')
        rows[name] = int(generation)
    require(rows.get('sbat') == 1 and len(rows) >= 3, 'upstream and vendor SBAT required')
    return rows


def policy(value):
    require(type(value) is dict and set(value) == {'schema','purpose','certificates','sbat_minimum','artifacts'}, 'invalid policy fields')
    require(value['schema'] == 1 and value['purpose'] in ('lab','submission-preparation'), 'preparation policy only')
    require(type(value['certificates']) is dict and set(value['certificates']) == {'firmware','vendor'}, 'two distinct public trust domains required')
    for cert in value['certificates'].values():
        require(type(cert) is dict and set(cert) == {'file','sha256'}, 'certificate fields')
        require(re.fullmatch(r'[A-Za-z0-9_.-]+', cert['file']) and re.fullmatch('[0-9a-f]{64}', cert['sha256']), 'invalid certificate binding')
    require(value['certificates']['firmware']['sha256'] != value['certificates']['vendor']['sha256'], 'firmware/vendor trust must differ')
    floors = value['sbat_minimum']
    require(type(floors) is dict and 1 <= len(floors) <= 128, 'revocation floor bounds')
    for name, floor in floors.items():
        require(re.fullmatch(r'[A-Za-z0-9_.-]+',name) and type(floor) is int and 1 <= floor <= 999999999, 'invalid SBAT floor')
    artifacts = value['artifacts']
    require(type(artifacts) is dict and set(artifacts) == set(ROLES), 'complete boot role set required')
    files = set()
    for role, row in artifacts.items():
        require(type(row) is dict and set(row) == {'file','sha256','vendor_sbat'}, 'artifact fields')
        require(re.fullmatch(r'[A-Za-z0-9_.-]+\.efi', row['file']) and row['file'] not in files, 'distinct safe PE filenames required')
        files.add(row['file'])
        require(re.fullmatch('[0-9a-f]{64}',row['sha256']) and row['vendor_sbat'] == f'{role}.enzimos', 'artifact digest/vendor SBAT binding')
        require(row['vendor_sbat'] in floors, 'vendor SBAT floor missing')
    return value


def check_transition(previous, current):
    """Rotation/rollback preparation cannot lower or drop known revocation floors.

    Both policies must arrive through the operator's separate authenticated trust.
    This helper is not a persistent client antirollback store.
    """
    previous=policy(previous); current=policy(current)
    require(previous['purpose']==current['purpose'],'cannot relabel lab trust as submission')
    for name,floor in previous['sbat_minimum'].items():
        require(current['sbat_minimum'].get(name,0)>=floor,'revocation floor cannot drop or decrease')
    return {'status':'PASS-monotonic-policy-preparation','previous_policy_sha256':hashlib.sha256(json.dumps(previous,sort_keys=True,separators=(',',':')).encode()).hexdigest()}


def verify_signature(image, certificate, verifier):
    """No network/environment/host home; explicit verifier is recorded in receipt."""
    verifier = Path(verifier).absolute()
    read(verifier, 8*1024**2)
    require(os.access(verifier, os.X_OK), 'verifier executable required')
    argv = ['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
            '--ro-bind','/usr','/usr','--symlink','usr/lib','/lib','--symlink','usr/lib','/lib64',
            '--proc','/proc','--dev','/dev','--tmpfs','/tmp',
            '--ro-bind',str(verifier),'/tmp/sbverify','--ro-bind',str(image),'/tmp/image.efi',
            '--ro-bind',str(certificate),'/tmp/certificate.pem','--','/tmp/sbverify',
            '--cert','/tmp/certificate.pem','/tmp/image.efi']
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    require(result.returncode == 0 and len(result.stdout)+len(result.stderr) <= 65536, 'Authenticode verification failed')


def inspect(directory, policy_path, verifier, previous_policy=None):
    directory = Path(directory).absolute()
    encoded = read(policy_path, 65536)
    try: value = policy(json.loads(encoded))
    except (ValueError,TypeError,RecursionError): raise Invalid('invalid policy JSON')
    transition=None
    if previous_policy is not None:
        try: transition=check_transition(json.loads(read(previous_policy,65536)),value)
        except (ValueError,TypeError,RecursionError): raise Invalid('invalid retained policy JSON')
    certificates = {}
    for role, record in value['certificates'].items():
        path = directory/record['file']; body = read(path, 16384)
        require(hashlib.sha256(body).hexdigest() == record['sha256'], 'certificate differs from operator pin')
        require(b'PRIVATE KEY' not in body and body.startswith(b'-----BEGIN CERTIFICATE-----'), 'public PEM certificate required')
        certificates[role] = body
    records = {}
    for role, record in value['artifacts'].items():
        image = directory/record['file']; body = read(image, MAX_PE)
        require(hashlib.sha256(body).hexdigest() == record['sha256'], 'artifact digest mismatch')
        parts = pe(body); require('.sbat' in parts, 'SBAT section required')
        rows = sbat(parts['.sbat'])
        require(record['vendor_sbat'] in rows, 'vendor-specific SBAT absent')
        for name, generation in rows.items():
            require(generation >= value['sbat_minimum'].get(name,1), 'revoked SBAT generation')
        require(('shim' if role == 'shim' else 'systemd') in rows, 'upstream SBAT identity missing')
        if role in UKIS:
            require(all(parts.get(k) for k in ('.linux','.initrd','.cmdline')), 'complete authenticated UKI required')
            try: command = parts['.cmdline'].rstrip(b'\0\n').decode('ascii')
            except UnicodeError: raise Invalid('invalid command line')
            tokens = command.split()
            require(0 < len(command) <= 4096 and all(32 <= ord(c) < 127 for c in command), 'command line bound')
            require(tokens.count('lockdown=integrity') == 1 and not any(t.startswith('lockdown=') and t != 'lockdown=integrity' for t in tokens), 'embedded integrity lockdown required')
            require(not any(t.startswith(('initrd=','init=','rdinit=','efi=disable','module.sig_enforce=0')) for t in tokens), 'unauthenticated boot override refused')
        # Freeze exactly the parsed/hashed bytes before invoking the verifier.
        with tempfile.TemporaryDirectory(prefix='enzimos-factory-verify-') as temporary:
            image_copy=Path(temporary)/'image.efi'; image_copy.write_bytes(body)
            cert_copy=Path(temporary)/'public.pem'; cert_copy.write_bytes(certificates['firmware' if role == 'shim' else 'vendor'])
            verify_signature(image_copy,cert_copy,verifier)
        records[role] = {'file':record['file'],'sha256':record['sha256'],'bytes':len(body),'sbat':rows,
                         'sections':{k:hashlib.sha256(parts[k]).hexdigest() for k in ('.linux','.initrd','.cmdline') if k in parts}}
    return {'schema':1,'status':'PASS-preparation-artifacts','purpose':value['purpose'],
            'release_authorized':False,'factory_firmware_qualified':False,'policy_sha256':hashlib.sha256(encoded).hexdigest(),
            'verifier_sha256':digest(Path(verifier)),'transition':transition,'certificates':value['certificates'],'artifacts':records,
            'remaining_gates':['external-shim-review-and-signing','factory-CA-and-dbx-matrix',
                'generic-initrd-root-and-recovery-discovery','runtime-lockdown-and-module-rejection',
                'both-kernels-recovery-and-update-interruptions','hardware-Windows-and-NVIDIA']}


def prepare(directory, policy_path, verifier, output, previous_policy=None):
    """Validate everything before creating a new bundle. No firmware/ESP access."""
    receipt = inspect(directory,policy_path,verifier,previous_policy)
    output = Path(output).absolute()
    require(not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)), 'new nonsymlink output required')
    require(not output.is_relative_to(Path(directory).absolute()), 'output must not overlap input')
    output.mkdir(mode=0o700)
    try:
        for role, record in receipt['artifacts'].items():
            dest = output/TARGETS[role]; dest.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
            body = read(Path(directory)/record['file'],MAX_PE)
            require(hashlib.sha256(body).hexdigest() == record['sha256'], 'artifact changed during copy')
            with dest.open('xb') as f: f.write(body);f.flush();os.fsync(f.fileno())
            dest.chmod(0o644)
        for record in receipt['certificates'].values():
            body=read(Path(directory)/record['file'],16384)
            require(hashlib.sha256(body).hexdigest()==record['sha256'],'certificate changed during copy')
            (output/record['file']).write_bytes(body)
        (output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        return receipt
    except BaseException:
        # Keep incomplete evidence; never present it as an admitted bundle.
        (output/'INCOMPLETE').write_text('Preparation failed; discard or review, never install.\n')
        raise


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('inspect','prepare'))
    p.add_argument('--inputs',type=Path,required=True);p.add_argument('--policy',type=Path,required=True)
    p.add_argument('--previous-policy',type=Path,help='independently authenticated retained policy for monotonic rotation check')
    p.add_argument('--verifier',type=Path,default=Path('/usr/bin/sbverify'));p.add_argument('--output',type=Path)
    a=p.parse_args()
    try:
        if a.action=='prepare':
            require(a.output is not None,'output required'); result=prepare(a.inputs,a.policy,a.verifier,a.output,a.previous_policy)
        else: result=inspect(a.inputs,a.policy,a.verifier,a.previous_policy)
        print(json.dumps(result,indent=2))
    except (Invalid,OSError,ValueError,TypeError,subprocess.SubprocessError) as e:p.exit(1,str(e)+'\n')

if __name__=='__main__':main()
