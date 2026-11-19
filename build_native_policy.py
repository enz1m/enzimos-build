#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build only our original copy-only policy recipe in a network-disabled sandbox."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from contract import Invalid,digest
from signed_bootstrap import new_output,FREE_FLOOR
from lab_resources import constrain_job
from native_package_audit import EPOCH, audit, bounded_bytes, source_snapshot


def build(source,license_path,output,release=1,package_name='enzimos-native-policy'):
    if os.geteuid()==0 or type(release) is not int or release<1:raise Invalid('unprivileged positive release required')
    if package_name not in ('enzimos-native-policy','enzimos-system-backend','enzimos-update-client'):raise Invalid('unreviewed authored package name')
    resources=constrain_job(cpu_limit=8)
    source=Path(source).resolve(strict=True);tree=source/'root'
    entries=source_snapshot(tree)
    license_body=bounded_bytes(license_path)
    install_body=bounded_bytes(source/'native-policy.install')
    recipe_template=bounded_bytes(source/'PKGBUILD.in').decode('utf-8')
    if '\npkgname='+package_name+'\n' not in '\n'+recipe_template:raise Invalid('recipe package identity mismatch')
    if shutil.disk_usage(Path(output).absolute().parent).free<FREE_FLOOR+16*1024**2:raise Invalid('space floor')
    output=new_output(output);manifest={}
    with tarfile.open(output/'policy.tar','w',format=tarfile.USTAR_FORMAT) as ar:
        for name,value in sorted(entries.items()):
            body=value['body'];info=tarfile.TarInfo('policy/'+name)
            info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=EPOCH;info.mode=value['mode']
            info.type=tarfile.DIRTYPE if body is None else tarfile.REGTYPE
            if body is not None:
                info.size=len(body);manifest[name]=hashlib.sha256(body).hexdigest()
            ar.addfile(info,None if body is None else io.BytesIO(body))
    (output/'LICENSE').write_bytes(license_body)
    recipe=recipe_template.replace('@POLICY_SHA256@',digest(output/'policy.tar')).replace('@LICENSE_SHA256@',digest(output/'LICENSE')).replace('pkgrel=1',f'pkgrel={release}')
    (output/'PKGBUILD').write_text(recipe);(output/'native-policy.install').write_bytes(install_body)
    for name in ('artifacts','build','sources','logs'):(output/name).mkdir()
    (output/'makepkg.conf').write_text('CARCH="x86_64"\nCHOST="x86_64-pc-linux-gnu"\nBUILDENV=(!distcc !color !ccache check !sign)\nOPTIONS=(!strip docs !libtool !staticlibs emptydirs !zipman !purge !debug !lto)\nINTEGRITY_CHECK=(sha256)\nPKGEXT=".pkg.tar.zst"\nSRCEXT=".src.tar.gz"\nCOMPRESSZST=(zstd -c -T1 -q -)\nBUILDDIR=/work/build\nPKGDEST=/work/artifacts\nSRCDEST=/work/sources\nLOGDEST=/work/logs\nPACKAGER="enzimOS unsigned lab policy build"\n')
    (output/'pacman.conf').write_text('[options]\nArchitecture = x86_64\nDBPath = /var/lib/pacman\n')
    args=['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib','/lib64','--ro-bind','/var/lib/pacman','/var/lib/pacman','--dir','/etc','--ro-bind',str(output/'pacman.conf'),'/etc/pacman.conf','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--bind',str(output),'/work','--chdir','/work','--setenv','PATH','/usr/bin','--setenv','HOME','/tmp','--setenv','LANG','C.UTF-8','--setenv','TZ','UTC','--setenv','SOURCE_DATE_EPOCH',str(EPOCH),'--','/usr/bin/prlimit','--cpu=60:60','--as=1073741824:1073741824','--fsize=67108864:67108864','--','/usr/bin/makepkg','--config','/work/makepkg.conf','--nodeps','--noconfirm']
    (output/'command.json').write_text(json.dumps(args,indent=2)+'\n')
    result=subprocess.run(args,capture_output=True,text=True,timeout=90,env={'PATH':'/usr/bin','LANG':'C.UTF-8'})
    (output/'build.stdout').write_text(result.stdout);(output/'build.stderr').write_text(result.stderr)
    if result.returncode:raise Invalid('copy-only policy package build failed')
    packages=list((output/'artifacts').glob('*.pkg.tar.zst'))
    if len(packages)!=1:raise Invalid('unexpected output count')
    checked=audit(packages[0],entries,license_body,install_body,release,package_name=package_name, recipe=recipe)
    report={'status':'PASS-unsigned-policy-package-built','package':str(packages[0]),'sha256':digest(packages[0]),'sources':manifest,'release':release,'package_name':package_name,'host_resource_policy':resources,'release_authorized':False,'host_installed':False,'makepkg_nodeps_scope':'copy-only authored recipe; guest pacman must still validate runtime dependencies/signature',
            'source_date_epoch':EPOCH,'payload_audit':checked,'clean_arch_toolchain':False,
            'toolchain_scope':'read-only host /usr and package inventory, private network-disabled build; not a clean Arch release builder',
            'build_inputs':{name:digest(output/name) for name in ('policy.tar','PKGBUILD','native-policy.install','LICENSE','makepkg.conf','pacman.conf')},
            'source_modes':{name:value['mode'] for name,value in entries.items()},
            'builder_sources':{name:digest(Path(__file__).parent/name) for name in ('build_native_policy.py','native_package_audit.py','lab_resources.py')}}
    (output/'build.json').write_text(json.dumps(report,indent=2)+'\n');return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('source','license','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--release',type=int,default=1);a=p.parse_args()
    try:print(json.dumps(build(a.source,a.license,a.output,a.release),indent=2))
    except (Invalid,OSError,ValueError,subprocess.SubprocessError) as e:
        print(json.dumps({'status':'FAIL','error':str(e)}),file=sys.stderr);raise SystemExit(2)
