"""Check the preserved system only on the explicitly identified alongside fixture."""
import hashlib,json,subprocess
from pathlib import Path
if not Path('/dev/vda5').exists():raise SystemExit(0)
def run(*args,**kw):
 p=subprocess.run(args,capture_output=True,text=True,**kw)
 if p.returncode:raise RuntimeError(str(args)+': '+p.stderr)
 return p
assert '/dev/vda5' in run('cryptsetup','status','enzimos-crypt').stdout
folder=Path('/mnt/other-verify');folder.mkdir();esp=folder/'esp';home=folder/'home';esp.mkdir();home.mkdir()
run('cryptsetup','open','--readonly','--key-file','-','/dev/vda3','other-fixture',input='ENZIMOS-PUBLIC-TEST-DISK')
try:
 run('mount','-t','btrfs','-o','ro,rescue=nologreplay,subvol=enzimos-home','/dev/mapper/other-fixture',str(home))
 run('mount','-o','ro','/dev/vda2',str(esp))
 try:
  manifest=json.loads((home/'admin/original-boot-files.json').read_text())
  for name,wanted in manifest.items():assert hashlib.sha256((esp/name).read_bytes()).hexdigest()==wanted,name
  assert (home/'admin/alongside-preservation.txt').read_text()=='Original system and personal data must survive alongside installation.\n'
  print('ENZIMOS_ALONGSIDE_PRESERVATION_PASS all-original-boot-files-and-personal-data',flush=True)
 finally:run('umount',str(esp));run('umount',str(home))
finally:run('cryptsetup','close','other-fixture')
