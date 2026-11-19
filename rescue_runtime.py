#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the actual built rescue RAM userspace in an isolated local namespace."""
import argparse,json,subprocess,sys
from pathlib import Path
from contract import digest
from lab_resources import constrain_job
from signed_bootstrap import new_output

def check(image,output,constrain=True):
    if constrain:constrain_job(cpu_limit=8)
    image=Path(image).resolve(strict=True);output=new_output(output)
    root=output/'root';root.mkdir()
    extraction=['bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
                '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
                '--symlink','usr/lib','/lib64','--dir','/etc','--proc','/proc','--dev','/dev',
                '--tmpfs','/tmp','--ro-bind',str(image),'/tmp/image','--bind',str(root),'/out',
                '--chdir','/out','--setenv','PATH','/usr/bin','--','/usr/bin/lsinitcpio','--cpio','-x','/tmp/image']
    subprocess.run(extraction,check=True,capture_output=True,timeout=120)
    prefix=['bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
            '--ro-bind',str(root),'/','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--tmpfs','/run',
            '--setenv','PATH','/usr/bin','--setenv','LANG','C.UTF-8','--']
    code='import json,sys,pefile,_cffi_backend; from cryptography import x509; from cryptography.hazmat.primitives.asymmetric import rsa; rsa.generate_private_key(public_exponent=65537,key_size=2048); print(json.dumps({"python":sys.version,"crypto_and_pe_imports":True,"rsa_key_generation":True}))'
    imported=subprocess.run(prefix+['/usr/bin/python','-I','-c',code],capture_output=True,text=True,timeout=60)
    (output/'stderr.log').write_text(imported.stderr)
    imported.check_returncode()
    ukify=subprocess.run(prefix+['/usr/lib/systemd/ukify','--help'],capture_output=True,text=True,timeout=60)
    (output/'stderr.log').write_text(imported.stderr+ukify.stderr)
    ukify.check_returncode()
    result={'status':'PASS-rescue-runtime','image_sha256':digest(image),'runtime':json.loads(imported.stdout),'ukify_help':ukify.returncode==0,'network':'isolated','host_services_changed':False}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    (output/'stderr.log').write_text(imported.stderr+ukify.stderr)
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('image',type=Path);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(check(a.image,a.output),indent=2))
