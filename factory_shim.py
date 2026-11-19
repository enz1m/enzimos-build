#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit unsigned shim preparation from reviewed upstream source/public cert.

No network, signing keys, firmware access or Microsoft submission. This recipe
records the actual local toolchain; release review still needs a frozen rebuild
container/toolroot and independent reproduction.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
from contract import Invalid, digest
from factory_boot import SHIM_SOURCE_SHA256, read, require
from signed_bootstrap import new_output


def build(source, certificate, output, epoch=1790899200):
    source=Path(source).absolute();certificate=Path(certificate).absolute()
    body=read(source,16*1024**2)
    require(hashlib.sha256(body).hexdigest()==SHIM_SOURCE_SHA256,'reviewed shim16.1 source SHA required')
    cert=read(certificate,16384)
    require(cert[:1]==b'\x30' and b'PRIVATE KEY' not in cert,'public DER vendor certificate required')
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    try: parsed=x509.load_der_x509_certificate(cert)
    except ValueError: raise Invalid('invalid vendor X509 certificate')
    require(parsed.public_bytes(serialization.Encoding.DER)==cert,'canonical DER required')
    require(type(epoch) is int and 0 <= epoch < 2**32,'source epoch bound')
    out=new_output(output)
    with tarfile.open(source) as archive:
        members=archive.getmembers()
        require(len(members)<=20000 and sum(m.size for m in members)<=128*1024**2,'shim source extraction bound')
        require(all(m.name.startswith('shim-16.1/') or m.name=='shim-16.1' for m in members),'source root contract')
        archive.extractall(out,filter='data')
    (out/'vendor.der').write_bytes(cert)
    (out/'vendor-sbat.csv').write_text((out/'shim-16.1/data/sbat.csv').read_text()+'shim.enzimos,1,enzimOS,shim,16.1,https://github.com/rhboot/shim\n')
    argv=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
          '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
          '--symlink','usr/lib','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--dir','/etc',
          '--bind',str(out),'/work','--chdir','/work/shim-16.1','--setenv','PATH','/usr/bin',
          '--setenv','LANG','C.UTF-8','--setenv','SOURCE_DATE_EPOCH',str(epoch),'--']
    args=['make','-j2','DASHJ=-j2','POST_PROCESS_PE_FLAGS=-n -x','FORMAT=-O efi-app-x86_64','VENDOR_CERT_FILE=/work/vendor.der',
          'DEFAULT_LOADER=\\\\enzimosx64.efi','SBATPATH=/work/vendor-sbat.csv','shimx64.efi','mmx64.efi']
    result=subprocess.run(argv+args,stdin=subprocess.DEVNULL,capture_output=True,timeout=900)
    require(len(result.stdout)+len(result.stderr)<=8*1024**2,'build log size bound')
    (out/'build.stdout').write_bytes(result.stdout);(out/'build.stderr').write_bytes(result.stderr)
    require(result.returncode==0,'shim preparation failed; logs retained')
    artifacts={}
    for name in ('shimx64.efi','mmx64.efi'):
        shutil.copyfile(out/'shim-16.1'/name,out/name);artifacts[name]=digest(out/name)
    receipt={'schema':1,'status':'PASS-unsigned-shim-preparation','release_authorized':False,
             'source_sha256':SHIM_SOURCE_SHA256,'vendor_der_sha256':hashlib.sha256(cert).hexdigest(),
             'epoch':epoch,'arguments':args,'source_patches':[],
             'toolchain_sha256':{name:digest(Path('/usr/bin')/name) for name in ('gcc','ld','objcopy','make','openssl')},
             'artifacts':artifacts,'next_stage':'\\enzimosx64.efi',
             'note':'FORMAT selects output only: current binutils --target also selects the ELF input format; no source or verification patch.'}
    (out/'build.json').write_text(json.dumps(receipt,indent=2)+'\n');return receipt


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True)
    p.add_argument('--vendor-certificate',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    from lab_resources import constrain_job
    try:
        constrain_job(8);print(json.dumps(build(a.source,a.vendor_certificate,a.output),indent=2))
    except (Invalid,OSError,subprocess.SubprocessError) as e:p.exit(1,str(e)+'\n')

if __name__=='__main__':main()
