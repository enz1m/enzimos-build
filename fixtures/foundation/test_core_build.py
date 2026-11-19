#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Actual core recipes in fresh guest Arch roots; bounded exact artifact export."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import native

BASE=Path('/var/lib/enzimos-core-builder')


def qualify(check,payload):
    payload=Path(payload);plan=json.loads((payload/'core-build-plan.json').read_text())
    expected={r['name']:r['version'] for r in plan['packages']}
    check(len(expected)==256 and not BASE.exists(),'fresh full core build root required')
    before=native.output(['pacman','-Q']);authority=native.authority_identity()
    native.run(['btrfs','subvolume','create',BASE])
    for name in ('var/lib/pacman','dev','proc','sys','run','tmp','work'):(BASE/name).mkdir(parents=True,exist_ok=True)
    conf=Path('/run/core-pacman.conf');conf.write_text('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n')
    keys=Path('/run/core-public-keys');keys.mkdir(mode=0o700)
    for name in ('pubring.gpg','trustdb.gpg','gpg.conf'):shutil.copyfile(payload/'core-public-keys'/name,keys/name)
    packages=[]
    for row in plan['packages']:
        p=payload/'core-packages'/row['url'].rsplit('/',1)[-1]
        check(native.sha(p)==row['sha256_from_metadata'],'core dependency bytes changed');packages.append(p)
    for source,target,options in (('/dev','dev',None),('proc','proc',None),('sysfs','sys','ro'),('tmpfs','run','mode=0755')):
        if source=='/dev':native.run(['mount','--rbind',source,BASE/target]);native.run(['mount','--make-rslave',BASE/target])
        else:native.run(['mount','-t',source,*(['-o',options] if options else []),source,BASE/target])
    try:
        native.run(['pacman','--root',BASE,'--config',conf,'--gpgdir',keys,'--noconfirm','-U',*packages])
        installed=native.output(['pacman','--root',BASE,'--config',conf,'-Q'])
        check(dict(line.split(' ',1) for line in installed.splitlines())==expected,'core builder inventory differs')
        native.run(['chroot',BASE,'useradd','-m','-u','1000','-s','/bin/bash','builder']);(BASE/'tmp').chmod(0o1777)
        artifacts={}
        for label in ('native','backend'):
            work=BASE/'work';work.chmod(0o755);os.chown(work,1000,1000)
            source=payload/('core-source-'+label)
            for p in source.iterdir():
                if p.is_file():shutil.copyfile(p,work/p.name);os.chown(work/p.name,1000,1000)
            for name in ('artifacts','build','sources','logs'):(work/name).mkdir();os.chown(work/name,1000,1000)
            native.run(['chroot','--userspec=1000:1000',BASE,'/usr/bin/env','-i','PATH=/usr/bin','HOME=/home/builder','LANG=C.UTF-8','TZ=UTC',
                'SOURCE_DATE_EPOCH=1789516800','MAKEFLAGS=-j1','/usr/bin/bash','-c','cd /work && makepkg --config /work/makepkg.conf --noconfirm'])
            built=list((work/'artifacts').glob('*.pkg.tar.zst'));check(len(built)==1,'exactly one core package required')
            package=built[0];check(package.stat().st_size<256*1024,'bounded core artifact')
            destination=BASE/(label+'.pkg.tar.zst');shutil.copyfile(package,destination)
            artifacts[label]={'sha256':native.sha(package),'bytes':package.stat().st_size}
            if label=='native':
                # Only this freshly built original package is signed by a new
                # ephemeral guest-RAM LAB key; no production or host key is used.
                signing=Path('/run/core-lab-signing');signing.mkdir(mode=0o700)
                native.run(['gpg','--homedir',signing,'--batch','--pinentry-mode','loopback','--passphrase','','--quick-generate-key',
                            'enzimOS DISPOSABLE clean core dependency','ed25519','sign','1d'])
                native.run(['gpg','--homedir',signing,'--batch','--detach-sign','--output',str(destination)+'.sig',destination])
                public=subprocess.check_output(['gpg','--homedir',str(signing),'--export'])
                subprocess.run(['gpg','--homedir',str(keys),'--batch','--no-autostart','--import'],input=public,check=True)
                fp=next(x.split(':')[9] for x in native.output(['gpg','--homedir',signing,'--with-colons','--list-keys']).splitlines() if x.startswith('fpr:'))
                native.run(['gpg','--homedir',keys,'--batch','--no-autostart','--import-ownertrust'],input=fp+':5:\n')
                native.run(['pacman','--root',BASE,'--config',conf,'--gpgdir',keys,'--noconfirm','-U',destination])
            work.rename(BASE/('evidence-'+label));work.mkdir()
        check(native.output(['pacman','-Q'])==before and native.authority_identity()==authority,'outside builder inventory/authority changed')
        for label in ('native','backend'):
            body=(BASE/(label+'.pkg.tar.zst')).read_bytes()
            print('ENZIMOS_CORE_ARTIFACT='+json.dumps({'label':label,**artifacts[label],'base64':base64.b64encode(body).decode()}),flush=True)
        return {'clean_packages':256,'normal_dependency_checks':True,'actual_core_recipes':True,
                'artifacts':artifacts,'outside_inventory_authority_preserved':True,'host_toolchain_used':False,
                'cross_host_reproducibility':False,'release_authorized':False}
    finally:
        for name in ('run','sys','proc','dev'):native.run(['umount','-R',BASE/name])
