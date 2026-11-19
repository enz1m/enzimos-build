#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""TEST payload: stage 1 serves the next native-policy release from a guest-local repository
signed with a disposable key made in this guest, and runs native.run_update (fallback of the
installed root + new generation, selected). Stage 2 (next boot) must run and confirm it."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.path.insert(0, '/usr/lib/enzimos')
import native
import generation_registry as registry

PAYLOAD = Path('/run/enzimos-testpayload');STATE = Path('/var/lib/enzimos-test/update.json')
REPO = Path('/var/lib/enzimos-test/repo');CONFIG = Path('/etc/pacman-enzimos-test.conf');GENERATION = 'upd-installed'


def run(*args, **kw):return subprocess.run([str(a) for a in args], check=True, **kw)


def stage1():
    for unit in ('enzimos-home-history.timer', 'enzimos-scrub.timer', 'enzimos-trim.timer', 'enzimos-deferred.timer', 'snapper-cleanup.timer', 'snapper-timeline.timer'):
        subprocess.run(['systemctl', 'stop', unit])
    key = Path('/run/enzimos-test-signing');key.mkdir(mode=0o700)
    env = dict(os.environ, GNUPGHOME=str(key))
    run('gpg', '--batch', '--quiet', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key', 'enzimOS DISPOSABLE installed-update test', 'ed25519', 'sign', '1d', env=env)
    fingerprint = next(l.split(':')[9] for l in subprocess.check_output(['gpg', '--with-colons', '--list-keys'], env=env, text=True).splitlines() if l.startswith('fpr:'))
    public = Path('/run/enzimos-test-signing.gpg');public.write_bytes(subprocess.check_output(['gpg', '--batch', '--export'], env=env))
    run('gpg', '--homedir', '/etc/pacman.d/gnupg', '--batch', '--no-autostart', '--import', public)
    run('gpg', '--homedir', '/etc/pacman.d/gnupg', '--batch', '--no-autostart', '--import-ownertrust', input=(fingerprint+':5:\n').encode())
    REPO.mkdir(parents=True);summary = json.loads((PAYLOAD/'update.json').read_text())
    targets = []
    for item in summary['packages']:
        target = REPO/item['filename'];shutil.copyfile(PAYLOAD/item['filename'], target)
        run('gpg', '--batch', '--detach-sign', '--output', str(target)+'.sig', target, env=env);targets.append(target)
    run('repo-add', '-q', REPO/'enzimos-test.db.tar.gz', *targets)
    CONFIG.write_text('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly DatabaseOptional\nLocalFileSigLevel = Required TrustedOnly\n'
                      'CacheDir = /var/cache/pacman/pkg/\nLogFile = /var/log/pacman-enzimos-test.log\n\n[enzimos-test]\nServer = file://'+str(REPO)+'\n')
    names = [item['name'] for item in summary['packages']]
    before = native.output(['pacman', '-Q', *names])
    assert native.upgrade_candidates(CONFIG), 'no upgrade offered'
    options = ' '.join(w for w in Path('/proc/cmdline').read_text().split() if not w.startswith(('enzimos.', 'BOOT_IMAGE=', 'initrd=')))
    native.run_update(CONFIG, GENERATION, native.installed_kernels(), options)
    after = native.output(['pacman', '-Q', *names])
    assert after == '\n'.join(f"{item['name']} 0.1.0-{item['release']}" for item in summary['packages']), after
    catalog = registry.status()['catalog']['generations']
    assert catalog[GENERATION]['state'] == 'ready' and catalog['old-'+GENERATION]['state'] == 'ready', catalog
    assert native.generation_selected(GENERATION), 'new generation not selected'
    STATE.parent.mkdir(exist_ok=True);native.atomic_json(STATE, {'boot_id': native.boot_id(), 'before': before, 'after': after, 'inventory': native.output(['pacman', '-Q'])})
    os.sync();Path('/run/enzimos-test-reboot').touch()
    print('\nENZIMOS_UPDATE_STAGED %s -> %s generation=%s' % (before.replace('\n', ', '), after.replace('\n', ', '), GENERATION), flush=True)


def stage2():
    saved = json.loads(STATE.read_text());assert saved['boot_id'] != native.boot_id(), 'later boot required'
    assert registry.current_marker() == GENERATION, 'did not boot the new generation: %r' % registry.current_marker()
    confirmed = registry.confirm_current();assert confirmed['generation'] == GENERATION, confirmed
    assert native.output(['pacman', '-Q']) == saved['inventory'], 'inventory differs from the transaction result'
    print('\nENZIMOS_UPDATE_CONFIRMED generation=%s %s' % (GENERATION, saved['after'].replace('\n', ', ')), flush=True)


if __name__ == '__main__':
    stage2() if STATE.exists() else stage1()
