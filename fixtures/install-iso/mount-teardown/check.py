# SPDX-License-Identifier: MIT
"""Explicit disposable-guest mount-holder controls in an independent mount namespace."""
import contextlib,importlib.util,io,json,os,subprocess,sys,time
from pathlib import Path
if os.geteuid()!=0 or os.environ.get('ENZIMOS_DISPOSABLE_TEST')!='1' or os.readlink('/proc/self/ns/mnt')==os.readlink('/proc/1/ns/mnt'):
 raise SystemExit('explicit disposable Root guest and private mount namespace required')
spec=importlib.util.spec_from_file_location('drain',Path(__file__).with_name('mount_teardown.py'))
drain=importlib.util.module_from_spec(spec);spec.loader.exec_module(drain)
target=Path(drain.TARGET)
assert subprocess.run(['mountpoint','-q',str(target)],check=False).returncode!=0,'fixture target already mounted'
target.mkdir(parents=True,exist_ok=True)
rows=[]
for transient in (True,False):
 subprocess.run(['mount','-t','tmpfs','-o','size=1m','tmpfs',str(target)],check=True)
 code="import os,sys,time;fd=os.open('/mnt/enzimos',os.O_RDONLY|os.O_DIRECTORY);print('READY',flush=True);"+('time.sleep(2)' if transient else 'sys.stdin.read(1)')+';os.close(fd)'
 child=subprocess.Popen([sys.executable,'-I','-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
 assert child.stdout.readline().strip()=='READY'
 captured=io.StringIO();started=time.monotonic();refused=False
 try:
  with contextlib.redirect_stdout(captured):
   try:drain.finish_unmount()
   except RuntimeError:refused=True
  elapsed=time.monotonic()-started
  assert refused is not transient,(transient,refused)
  assert 1<=elapsed<=18,elapsed
  diagnostic=captured.getvalue()
  assert 'ENZIMOS_TARGET_UNMOUNT_WAIT holders=' in diagnostic
  assert any(x['pid']==child.pid for x in json.loads(diagnostic.split('holders=',1)[1].splitlines()[0])),diagnostic
  if transient:assert 'ENZIMOS_TARGET_UNMOUNT_PASS' in diagnostic
  else:
   assert 'ENZIMOS_TARGET_UNMOUNT_PASS' not in diagnostic
   subprocess.run(['mountpoint','-q',str(target)],check=True)
  rows.append({'transient':transient,'refused':refused,'elapsed_seconds':round(elapsed,3),'holder_pid':child.pid})
 finally:
  if child.poll() is None:child.stdin.write('x');child.stdin.flush()
  child.wait(timeout=5)
  child.stdin.close();child.stdout.close()
  if not transient:subprocess.run(['/usr/bin/umount','--recursive','--',str(target)],check=True)
print('ENZIMOS_NATIVE_MOUNT_DRAIN_PASS '+json.dumps(rows),flush=True)
