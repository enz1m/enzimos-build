# SPDX-License-Identifier: MIT
"""TEST payload: installed-system local backup without Settings, as root in the guest.

Scenarios (argument):
  initialize  format the scratch disk, enroll it through the supported root
              setup route (--provision-plan/--provision-apply, "Create a new
              repository"), leave it attached but unmounted, then run the
              System1 backup-create sequence (--system-backup-create), the
              standalone --backup-create, manual retention, and verify the
              snapshots with the stored password on a read-only mount.
  adopt       format the scratch disk, create a repository with plain restic,
              adopt it through the same root route ("Use an existing
              repository", right password), back up into it through the System1
              sequence and verify the snapshots.

Markers: ENZIMOS_PAYLOAD_OK/FAIL <step>. Exit status 0 only when every step passed.
"""
import fcntl
import json
import os
import pwd
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BACKEND = '/usr/lib/enzimos-backend/enzimos-system-backend'
POLICY = '/usr/lib/enzimos-native/enzimos-policy'
DISK = Path('/dev/disk/by-id/virtio-enzimos-fixture')
CONTROL = Path('/var/lib/enzimos-control')
# Synthetic fixture credential for a disposable VM disk only.
PASSWORD = b'enzimos-vm-backup-fixture-2026'
SNAPSHOT = re.compile(r'[0-9a-f]{64}')
failed = []


def mark(ok, name, detail=''):
    text = f"ENZIMOS_PAYLOAD_{'OK' if ok else 'FAIL'} {name}"
    print(text + (f' {detail}' if detail else ''), flush=True)
    if not ok:
        failed.append(name)
    return ok


def journal(since):
    """Backup lines of the failed step only: backend, worker and policy
    identifiers plus the transient worker units, since the step started."""
    base = ['journalctl', '-b', '--no-pager', '-o', 'short-monotonic', '--since', f'@{since:.0f}', '-n', '80']
    for name, matches in (('identifiers', ['-t', 'enzimos-system-backend', '-t', 'enzimos-backup-worker', '-t', 'enzimos-policy']),
                          ('worker-units', ['-u', 'enzimos-backup-local-*'])):
        lines = subprocess.run(base + matches, capture_output=True, text=True, timeout=60).stdout.splitlines()
        for line in lines:
            if line.startswith('-- '):
                continue
            print(f'ENZIMOS_PAYLOAD_JOURNAL {name} {line[:400]}', flush=True)


def last_journal_line(since):
    """Newest backup journal line since `since` (identifiers or worker units)."""
    newest = ''
    for matches in (['-t', 'enzimos-system-backend', '-t', 'enzimos-backup-worker', '-t', 'enzimos-policy'],
                    ['-u', 'enzimos-backup-local-*']):
        lines = [line for line in subprocess.run(
            ['journalctl', '-b', '--no-pager', '-o', 'short-unix', '--since', f'@{since:.0f}', '-n', '1', *matches],
            capture_output=True, text=True, timeout=60).stdout.splitlines() if line and not line.startswith('-- ')]
        if lines and lines[-1] > newest:
            newest = lines[-1]
    return newest


def progress(name, started, since, stderr):
    """One status line for a long step: elapsed, worker units, last lines."""
    units = subprocess.run(['systemctl', 'list-units', '--all', '--plain', '--no-legend', 'enzimos-backup-local-*'],
                           capture_output=True, text=True, timeout=60).stdout.split('\n')
    units = ';'.join(' '.join(u.split()[:4]) for u in units if u.strip()) or 'none'
    stderr.flush()
    try:
        own = Path(stderr.name).read_text(errors='replace').splitlines()[-1:]
    except OSError:
        own = []
    print(f'ENZIMOS_PAYLOAD_PROGRESS {name} elapsed={time.monotonic() - started:.0f}s units={units[:300]} '
          f'stderr={(own[0] if own else "")[:200]} journal={last_journal_line(since)[:300]}', flush=True)


def command(name, args, timeout, pass_fds=(), codes=(0,)):
    """Run one root command; return its last JSON stdout line, or None after marking the failure.
    Long steps print ENZIMOS_PAYLOAD_PROGRESS every 60 s so a stall is visible."""
    started = time.monotonic()
    since = time.time() - 1
    with tempfile.NamedTemporaryFile('w+', prefix='payload-out-', dir='/run') as out, \
            tempfile.NamedTemporaryFile('w+', prefix='payload-err-', dir='/run') as err:
        process = subprocess.Popen(args, stdout=out, stderr=err, text=True, pass_fds=pass_fds)
        reported = started
        while process.poll() is None:
            now = time.monotonic()
            if now - started > timeout:
                process.kill()
                process.wait()
                mark(False, name, f'timeout after {timeout} s')
                journal(since)
                return None
            if now - reported >= 60:
                progress(name, started, since, err)
                reported = now
            time.sleep(1)
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(), err.read()
    elapsed = round(time.monotonic() - started, 1)
    print(f'ENZIMOS_PAYLOAD_STEP {name} exit={process.returncode} seconds={elapsed}', flush=True)
    for line in stderr.splitlines()[-20:]:
        print(f'ENZIMOS_PAYLOAD_STDERR {name} {line[:400]}', flush=True)
    lines = [line for line in stdout.splitlines() if line.strip()]
    value = None
    if lines:
        try:
            value = json.loads(lines[-1])
        except ValueError:
            value = None
    if process.returncode not in codes or value is None:
        mark(False, name, f'exit {process.returncode}')
        journal(since)
        return None
    print(f'ENZIMOS_PAYLOAD_RESULT {name} {json.dumps(value, sort_keys=True)[:2000]}', flush=True)
    return value


def plain(args, timeout=300, env=None):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)


def unmounted(name):
    """The configured drive is left attached but unmounted; the stub is bare."""
    rows = plain(['findmnt', '-rn', '-o', 'TARGET']).stdout.split()
    return mark(not any(t == '/backup-repository' or t.startswith('/backup-repository/') for t in rows), name)


def sealed_input(uid, gid, secret):
    """A sealed anonymous memfd owned by the ordinary owner, as Settings sends it."""
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    pid = os.fork()
    if pid == 0:
        try:
            parent.close()
            os.setgroups([])
            os.setresgid(gid, gid, gid)
            os.setresuid(uid, uid, uid)
            fd = os.memfd_create('enzimos-backup-input', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
            os.write(fd, secret)
            os.fchmod(fd, 0o600)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            socket.send_fds(child, [b'x'], [fd])
            os._exit(0)
        except BaseException:
            os._exit(1)
    child.close()
    _, fds, _, _ = socket.recv_fds(parent, 1, 1)
    _, status = os.waitpid(pid, 0)
    parent.close()
    if status != 0 or len(fds) != 1:
        raise RuntimeError('sealed input helper failed')
    return fds[0]


def restic(args, password_file, timeout=900):
    env = {'PATH': '/usr/bin', 'HOME': '/root', 'LANG': 'C.UTF-8', 'RESTIC_PASSWORD_FILE': str(password_file)}
    return plain(['restic', '--no-cache', *args], timeout, env)


def snapshots(uuid, password_file):
    """Snapshot IDs read with the given password from a read-only mount."""
    target = Path('/run/enzimos-fixture-verify')
    target.mkdir(mode=0o700, exist_ok=True)
    mounted = plain(['mount', '-t', 'btrfs', '-o', 'ro,nodev,nosuid,noexec', f'/dev/disk/by-uuid/{uuid}', str(target)])
    if mounted.returncode != 0:
        print(f'ENZIMOS_PAYLOAD_STDERR verify-mount {mounted.stderr.strip()[:400]}', flush=True)
        return None
    try:
        listed = restic(['--no-lock', '-r', str(target/'restic'), 'snapshots', '--json'], password_file)
        if listed.returncode != 0:
            print(f'ENZIMOS_PAYLOAD_STDERR verify-snapshots {listed.stderr.strip()[-400:]}', flush=True)
            return None
        return [row['id'] for row in json.loads(listed.stdout)]
    finally:
        plain(['umount', str(target)])
        plain(['udevadm', 'settle', '--timeout=30'])


def prepare_disk(scenario):
    for _ in range(60):
        if DISK.exists():
            break
        time.sleep(1)
    if not mark(DISK.exists(), 'scratch-disk'):
        return None
    device = str(DISK.resolve())
    made = plain(['mkfs.btrfs', '-f', '-q', '-L', 'enzimos-fixture', device])
    plain(['udevadm', 'settle', '--timeout=30'])
    uuid = plain(['blkid', '-p', '-s', 'UUID', '-o', 'value', device]).stdout.strip()
    if not mark(made.returncode == 0 and re.fullmatch(r'[0-9a-f-]{36}', uuid) is not None, 'format-btrfs', uuid):
        return None
    if scenario == 'adopt':
        # An existing repository made outside enzimOS, with one snapshot.
        target = Path('/run/enzimos-fixture-existing')
        target.mkdir(mode=0o700, exist_ok=True)
        secret = Path('/run/enzimos-fixture-password')
        secret.write_bytes(PASSWORD)
        secret.chmod(0o600)
        ok = plain(['mount', '-t', 'btrfs', '-o', 'nodev,nosuid,noexec', device, str(target)]).returncode == 0
        ok = ok and restic(['-r', str(target/'restic'), 'init'], secret).returncode == 0
        ok = ok and restic(['-r', str(target/'restic'), 'backup', '--host', 'enzimos-fixture', '/etc/os-release'], secret).returncode == 0
        plain(['umount', str(target)])
        plain(['udevadm', 'settle', '--timeout=30'])
        if not mark(ok, 'existing-repository'):
            return None
    return uuid


def enroll(uuid, mode):
    inventory = command('candidates', [BACKEND, '--backup-candidates'], 120)
    if inventory is None:
        return False
    tokens = [row.get('selection_id') for row in inventory.get('candidates', []) if row.get('filesystem_uuid_hint') == uuid]
    if not mark(len(tokens) == 1 and isinstance(tokens[0], str), 'candidate', json.dumps(inventory.get('candidates'))[:600]):
        return False
    owner = pwd.getpwnam('admin')
    request = f'vm-{mode}-1'
    args = [request, tokens[0], mode, str(owner.pw_uid)]
    plan = command(f'{mode}-plan', [BACKEND, '--provision-plan', *args], 600)
    if plan is None or not mark(SNAPSHOT.fullmatch(str(plan.get('plan_sha256', ''))) is not None, f'{mode}-plan-digest'):
        return False
    fd = sealed_input(owner.pw_uid, owner.pw_gid, PASSWORD)
    try:
        result = command(f'{mode}-apply', [BACKEND, '--provision-apply', *args, plan['plan_sha256'], str(fd)], 1800, pass_fds=(fd,))
    finally:
        os.close(fd)
    if result is None:
        return False
    mark(True, f'{mode}-enrolled', json.dumps(result, sort_keys=True)[:400])
    pinned = (CONTROL/'backup-destination.json').exists() and Path('/etc/enzimos/backup.json').exists()
    unmounted(f'{mode}-left-unmounted')
    return mark(pinned, f'{mode}-pinned')


def system1_backup(name):
    started = time.time()
    value = command(name, [BACKEND, '--system-backup-create'], 3600)
    snapshot = ((value or {}).get('result') or {}).get('snapshot_id')
    ok = mark(isinstance(snapshot, str) and SNAPSHOT.fullmatch(snapshot) is not None, f'{name}-snapshot', str(snapshot))
    unmounted(f'{name}-left-unmounted')
    system1_queries(name, snapshot if ok else None, started)
    return snapshot if ok else None


def system1_queries(name, snapshot, started):
    """What Settings reads after Back up now: the cleanup outcome from
    `backups` and the recovery points from `backup-points`, which attaches the
    unmounted drive for the read only."""
    status = command(f'{name}-backups-query', [BACKEND, '--system-query', 'backups'], 300)
    local = (((status or {}).get('retention') or {}).get('last_cleanup') or {}).get('local') or {}
    mark(local.get('status') in ('removed', 'nothing-to-remove', 'automatic-cleanup-off')
         and isinstance(local.get('removed'), int) and local.get('at_unix', 0) >= int(started),
         f'{name}-cleanup-reported', json.dumps(local))
    points = command(f'{name}-points-query', [BACKEND, '--system-query', 'backup-points'], 600)
    ids = [row.get('id') for row in points] if isinstance(points, list) else []
    mark(snapshot is not None and snapshot in ids, f'{name}-points-listed', json.dumps(ids)[:600])
    unmounted(f'{name}-points-left-unmounted')


HISTORY = Path('/var/lib/enzimos-history')


def seed_home():
    """Content for the skip rules: a Node project, a person's exclusion and a
    file to remove later. Rules are written where the history service keeps them."""
    owner = pwd.getpwnam('admin')
    home = Path(owner.pw_dir)
    for rel, body in (('proj/package.json', b'{}'), ('proj/node_modules/pkg/blob', os.urandom(4096)),
                      ('proj/src/app.js', b'main'), ('Private/secret.txt', b'skip me'),
                      ('remove-me.txt', b'remove from backups')):
        path = home/rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    plain(['chown', '-R', f'{owner.pw_uid}:{owner.pw_gid}', str(home/'proj'), str(home/'Private'), str(home/'remove-me.txt')])
    (HISTORY/'users').mkdir(parents=True, exist_ok=True, mode=0o700)
    (HISTORY/'users'/f'{owner.pw_uid}.json').write_text(json.dumps({'automatic': True, 'excluded': ['Private']}))
    return owner, home


def listing(uuid, snapshot, path):
    """`restic ls` of one snapshot below `path` from a read-only mount."""
    target = Path('/run/enzimos-fixture-verify')
    target.mkdir(mode=0o700, exist_ok=True)
    if plain(['mount', '-t', 'btrfs', '-o', 'ro,nodev,nosuid,noexec', f'/dev/disk/by-uuid/{uuid}', str(target)]).returncode:
        return None
    try:
        out = restic(['--no-lock', '-r', str(target/'restic'), 'ls', snapshot, path], Path('/etc/enzimos/backup.password'))
        return out.stdout.splitlines() if out.returncode == 0 else None
    finally:
        plain(['umount', str(target)])
        plain(['udevadm', 'settle', '--timeout=30'])


def all_snapshots(uuid):
    """Full snapshot rows (tags included)."""
    target = Path('/run/enzimos-fixture-verify')
    target.mkdir(mode=0o700, exist_ok=True)
    if plain(['mount', '-t', 'btrfs', '-o', 'ro,nodev,nosuid,noexec', f'/dev/disk/by-uuid/{uuid}', str(target)]).returncode:
        return None
    try:
        out = restic(['--no-lock', '-r', str(target/'restic'), 'snapshots', '--json'], Path('/etc/enzimos/backup.password'))
        return json.loads(out.stdout) if out.returncode == 0 else None
    finally:
        plain(['umount', str(target)])
        plain(['udevadm', 'settle', '--timeout=30'])


def skip_and_space(uuid, first, owner, home):
    """2026-11-05 backup review: skipped folders, removal, space limit, an
    unplugged drive and reconnecting it."""
    base = f'/backup-source/home/{home.name}'
    rows = listing(uuid, first, base) or []
    mark(any(r.endswith('/proj/src/app.js') for r in rows) and not any('/node_modules' in r for r in rows),
         'skip-build-output', f'{len(rows)} entries')
    mark(not any('/Private' in r for r in rows), 'skip-excluded-folder')
    skipped = listing(uuid, first, '/backup-source/inventory') or []
    mark(any(r.endswith('/skipped.txt') for r in rows + skipped), 'skipped-list-recorded')
    # Remove from backups: the person deleted the file and asked; the next
    # backup's cleanup rewrites every point without it.
    (home/'remove-me.txt').unlink()
    HISTORY.joinpath('removals.json').write_text(json.dumps([{'uid': owner.pw_uid, 'path': f'{home.name}/remove-me.txt', 'requested': int(time.time())}]))
    value = command('removal-backup', [BACKEND, '--backup-create'], 3600)
    removals = ((value or {}).get('cleanup') or {}).get('removals') or {}
    mark(removals.get('applied') == 1 and removals.get('pending') == 0, 'removal-applied', json.dumps(removals))
    points = all_snapshots(uuid) or []
    left = [p['id'] for p in points if any(r.endswith('/remove-me.txt') for r in (listing(uuid, p['id'], base) or []))]
    mark(points and not left, 'removed-from-every-point', json.dumps(left))
    mark(points and all(p.get('tags') == ['enzimos-whole-linux'] and p.get('hostname') == 'enzimos' for p in points),
         'rewritten-points-still-managed', json.dumps([p.get('tags') for p in points]))
    status = command('used-space-query', [BACKEND, '--system-query', 'backups'], 300) or {}
    mark(isinstance(status.get('repository_bytes_measured'), int) and status['repository_bytes_measured'] > 0
         and status.get('pending_removals') == 0, 'used-space-reported', str(status.get('repository_bytes_measured')))
    # Space limit far below one whole-system backup: the oldest go, never the newest.
    policy = json.loads(Path('/etc/enzimos/backup-retention.json').read_text())
    policy['budget_bytes'] = 1 << 30
    Path('/etc/enzimos/backup-retention.json').write_text(json.dumps(policy))
    value = command('budget-backup', [BACKEND, '--backup-create'], 3600)
    newest = (value or {}).get('snapshot_id')
    budget = ((value or {}).get('cleanup') or {}).get('budget') or {}
    after = [p['id'] for p in (all_snapshots(uuid) or [])]
    mark(after == [newest] and budget.get('over') is True, 'budget-keeps-only-newest', json.dumps({'after': after, 'budget': budget}))
    del policy['budget_bytes']
    Path('/etc/enzimos/backup-retention.json').write_text(json.dumps(policy))
    # The drive is unplugged: recorded as waiting, not a silent failure.
    device = DISK.resolve().name
    sysdev = Path(f'/sys/block/{device}/device').resolve()
    bus_id = sysdev.name
    driver = Path('/sys/bus/virtio/drivers/virtio_blk')
    (driver/'unbind').write_text(bus_id)
    plain(['udevadm', 'settle', '--timeout=30'])
    absent = plain([BACKEND, '--backup-create'], 600)
    print(f'ENZIMOS_PAYLOAD_STEP absent-backup exit={absent.returncode} {absent.stderr.strip()[-200:]}', flush=True)
    run = json.loads((CONTROL/'backup-run-status.json').read_text()) if (CONTROL/'backup-run-status.json').exists() else {}
    mark(run.get('state') == 'waiting-for-drive', 'absent-drive-is-waiting', json.dumps(run))
    # Connected again: udev marks it no-automount and asks for the owed backup.
    marker = CONTROL/'backup.enabled'
    fake_marker = not marker.exists()
    if fake_marker:
        marker.write_text('lab')
    since = time.time()
    (driver/'bind').write_text(bus_id)
    plain(['udevadm', 'settle', '--timeout=30'])
    time.sleep(3)
    info = plain(['udevadm', 'info', '--query=property', f'/dev/disk/by-uuid/{uuid}']).stdout
    mark('UDISKS_AUTO=0' in info, 'backup-drive-not-automounted')
    log = plain(['journalctl', '-b', '--no-pager', '--since', f'@{since:.0f}', '-o', 'cat']).stdout
    mark('starting the owed backup' in log, 'reconnect-starts-owed-backup', log[-400:].replace('\n', ' | '))
    plain(['systemctl', 'stop', 'enzimos-backup.service'])
    if fake_marker:
        marker.unlink()


def main(scenario):
    if scenario not in ('initialize', 'adopt'):
        raise SystemExit('unknown scenario')
    uuid = prepare_disk(scenario)
    if uuid is None or not enroll(uuid, scenario):
        return 1
    created = []
    owner, home = seed_home() if scenario == 'initialize' else (None, None)
    snapshot = system1_backup('system1-backup-create')
    if snapshot:
        created.append(snapshot)
    if scenario == 'initialize':
        value = command('cli-backup-create', [BACKEND, '--backup-create'], 3600)
        snapshot = (value or {}).get('snapshot_id')
        if mark(isinstance(snapshot, str) and SNAPSHOT.fullmatch(snapshot) is not None, 'cli-backup-create-snapshot', str(snapshot)):
            created.append(snapshot)
        cleanup = (value or {}).get('cleanup') or {}
        mark(cleanup.get('status') in ('removed', 'nothing-to-remove', 'automatic-cleanup-off'), 'cli-cleanup-after-backup', json.dumps(cleanup))
        unmounted('cli-backup-create-left-unmounted')
        retained = command('retention', [POLICY, 'backup', 'retain'], 1800)
        mark((retained or {}).get('status') in ('removed', 'nothing-to-remove'), 'retention-status', json.dumps(retained))
        unmounted('retention-left-unmounted')
    stored = Path('/etc/enzimos/backup.password')
    listed = snapshots(uuid, stored)
    mark(listed is not None and all(s in listed for s in created) and len(created) == (2 if scenario == 'initialize' else 1),
         'snapshots-verified', json.dumps(listed))
    if scenario == 'adopt':
        mark(listed is not None and len(listed) >= 2, 'adopted-history-kept', json.dumps(listed))
    if scenario == 'initialize' and created:
        skip_and_space(uuid, created[0], owner, home)
    unmounted('final-left-unmounted')
    print(f'ENZIMOS_PAYLOAD_SUMMARY {scenario} failed={",".join(failed) or "none"}', flush=True)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else 'initialize'))
