# SPDX-License-Identifier: MIT
"""Optional owner-signed installer profile. Private keys stay outside the ISO.

A factory firmware needs a vendor-trusted bootstrap, not an arbitrary owner key.
This profile is for firmware explicitly trusting the supplied owner certificate.
"""
import os,shutil,subprocess
from pathlib import Path
from contract import Invalid,digest
from build_initrd_lab import builder_argv,run_command

def prepare(root,stage,out,kernel,live_initrd,rescue_initrd,key,certificate):
    root,stage,out=map(Path,(root,stage,out));key=Path(key).resolve(strict=True);certificate=Path(certificate).resolve(strict=True)
    for path in (key,certificate):
        if not path.is_file() or path.stat().st_uid!=os.getuid() or path.stat().st_mode&0o022:raise Invalid('owned signing input required')
    if key.stat().st_mode&0o077:raise Invalid('private signing key permissions required')
    artifacts=out/'signed-media';artifacts.mkdir()
    expected=root/'usr/lib/enzimos-live/live.sha256';expected.write_text(digest(stage/'enzimos/live.sfs')+'\n')
    script=root/'usr/lib/enzimos-live/live-root.sh'
    text=script.read_text();needle='mount -t squashfs '
    check='''if [[ -f /usr/lib/enzimos-live/live.sha256 ]]; then
    expected=$(< /usr/lib/enzimos-live/live.sha256)
    actual=$(sha256sum "$base/media/enzimos/live.sfs"); actual=${actual%% *}
    [[ $expected == "$actual" ]] || { echo 'enzimOS: signed live-system digest mismatch' >&2; exit 1; }
fi
'''
    if needle not in text:raise Invalid('live root mount contract changed')
    script.write_text(text.replace(needle,check+needle,1))
    config=root/'etc/mkinitcpio-live-signed.conf'
    config.write_text((root/'etc/mkinitcpio-live.conf').read_text().replace('BINARIES=(', 'BINARIES=(/usr/bin/sha256sum ').replace('FILES=(', 'FILES=(/usr/lib/enzimos-live/live.sha256 '))
    modules=[p for p in (root/'usr/lib/modules').iterdir() if (p/'pkgbase').is_file() and (p/'pkgbase').read_text().strip()=='linux']
    if len(modules)!=1:raise Invalid('exact signed media kernel required')
    run_command(builder_argv(root,artifacts,['mkinitcpio','-k',modules[0].name,'-c','/etc/mkinitcpio-live-signed.conf','-g','/tmp/artifacts/live.img']),out,'signed-live-initrd',600)
    base='rd.systemd.gpt_auto=no quiet splash plymouth.ignore-serial-consoles loglevel=2 rd.systemd.show_status=false systemd.show_status=false rd.systemd.wants=enzimos-live-root.service systemd.firstboot=no console=tty0 console=ttyS0,115200 systemd.log_color=no panic=10'
    images=[('install','Install enzimOS',artifacts/'live.img',base),('text','Install enzimOS (text)',artifacts/'live.img',base+' enzimos.text'),('rescue','Rescue an existing enzimOS installation',Path(rescue_initrd),'enzimos.installer-rescue=1 rdinit=/usr/lib/enzimos-native/enzimos-media-rescue-init loglevel=2 console=tty0 console=ttyS0,115200 panic=10')]
    def signed_command(args,label):
        argv=builder_argv(root,artifacts,args);position=argv.index('--')
        argv[position:position]=['--ro-bind',str(key),'/run/owner.key','--ro-bind',str(certificate),'/run/owner.crt']
        run_command(argv,out,label,600)
    shutil.copyfile(kernel,artifacts/'kernel');shutil.copyfile(rescue_initrd,artifacts/'rescue.img')
    for name,title,initrd,options in images:
        (artifacts/(name+'.cmdline')).write_text(options+'\n')
        signed_command(['/usr/lib/systemd/ukify','build','--linux','/tmp/artifacts/kernel','--initrd','/tmp/artifacts/'+('rescue.img' if name=='rescue' else 'live.img'),'--cmdline','@/tmp/artifacts/'+name+'.cmdline','--os-release','@/etc/os-release','--secureboot-private-key','/run/owner.key','--secureboot-certificate','/run/owner.crt','--output','/tmp/artifacts/'+name+'.efi'],'signed-media-'+name)
        signed_command(['sbverify','--cert','/run/owner.crt','/tmp/artifacts/'+name+'.efi'],'verify-signed-media-'+name)
    signed_command(['sbsign','--key','/run/owner.key','--cert','/run/owner.crt','--output','/tmp/artifacts/BOOTX64.EFI','/usr/lib/systemd/boot/efi/systemd-bootx64.efi'],'sign-media-loader')
    signed_command(['sbverify','--cert','/run/owner.crt','/tmp/artifacts/BOOTX64.EFI'],'verify-media-loader')
    tree=artifacts/'efi-tree';(tree/'EFI/BOOT').mkdir(parents=True);(tree/'enzimos/media').mkdir(parents=True);(tree/'loader/entries').mkdir(parents=True)
    shutil.copyfile(artifacts/'BOOTX64.EFI',tree/'EFI/BOOT/BOOTX64.EFI')
    (tree/'loader/loader.conf').write_text('default install.conf\ntimeout 5\neditor no\nauto-entries no\nauto-firmware no\n')
    for name,title,_,_ in images:
        shutil.copyfile(artifacts/(name+'.efi'),tree/'enzimos/media'/(name+'.efi'))
        (tree/'loader/entries'/(name+'.conf')).write_text('title '+title+'\nuki /enzimos/media/'+name+'.efi\n')
    image=stage/'boot/limine/limine-uefi-cd.bin'
    image.unlink();
    with image.open('xb') as f:f.truncate(512*1024**2)
    subprocess.run(['mformat','-i',str(image),'-F','::'],check=True,timeout=60)
    subprocess.run(['mcopy','-s','-i',str(image),str(tree/'EFI'),str(tree/'loader'),str(tree/'enzimos'),'::/'],check=True,timeout=180)
    shutil.copyfile(artifacts/'BOOTX64.EFI',stage/'EFI/BOOT/BOOTX64.EFI')
    shutil.copytree(tree/'enzimos/media',stage/'enzimos/media');shutil.copytree(tree/'loader',stage/'loader')
    shutil.copyfile(certificate,stage/'enzimos/owner-certificate.pem')
    return {'mode':'owner-signed-uki','certificate_sha256':digest(certificate),'live_system_sha256':digest(stage/'enzimos/live.sfs'),'factory_firmware_trusted':False,'private_key_included':False,'images':{name:digest(artifacts/(name+'.efi')) for name,_,_,_ in images}}
