# SPDX-License-Identifier: MIT
"""Optional local lab scheduling; ordinary builds keep operator-managed limits."""
import fcntl
import os
from pathlib import Path
import subprocess

_LOCK=None


BUILD_CPUS = 8
VM_CPUS = 4


def constrain_job(cpu_limit=VM_CPUS):
    """Apply local lab scheduling only when ENZIMOS_LAB_LIMITS=1."""
    if type(cpu_limit) is not int or not 1 <= cpu_limit <= 12:
        raise ValueError('lab jobs may use between 1 and 12 eligible logical CPUs')
    if os.environ.get('ENZIMOS_LAB_LIMITS') != '1':
        return {'scheduling': 'operator-managed'}
    global _LOCK
    if _LOCK is None:
        cache=Path(os.environ.get('XDG_CACHE_HOME',Path.home()/'.cache'))
        state=Path(os.environ.get('ENZIMOS_LAB_STATE_DIR',cache/'enzimos-build'))
        state.mkdir(mode=0o700,parents=True,exist_ok=True)
        lock=state/'lab-job.lock'
        _LOCK=lock.open('a')
        try:fcntl.flock(_LOCK,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BaseException:
            _LOCK.close();_LOCK=None
            raise
    allowed=os.sched_getaffinity(0)
    if not allowed:
        raise RuntimeError('no eligible logical CPU')
    cpus=set(sorted(allowed)[-cpu_limit:])
    os.sched_setaffinity(0,cpus)
    # Lower than interactive work, but not idle: an idle I/O class starves the
    # job whenever other host work is busy.
    os.setpriority(os.PRIO_PROCESS,0,max(10,os.getpriority(os.PRIO_PROCESS,0)))
    subprocess.run(['/usr/bin/ionice','-c','2','-n','7','-p',str(os.getpid())],check=True,
                   capture_output=True,timeout=5)
    return {'cpu_affinity':sorted(os.sched_getaffinity(0)),
            'nice':os.getpriority(os.PRIO_PROCESS,0),'io_priority':'best-effort-7',
            'cpu_scope':f'up to {cpu_limit} eligible logical CPUs for job and children; kernel background work is not covered',
            'heavy_job_lock':'exclusive nonblocking local lab lock',
            'parallel_vm_jobs':1}
