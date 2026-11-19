#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Guest-only clean Arch tool installation and ordinary dependency-checked C build."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import native

BASE = Path('/var/lib/enzimos-clean-builder')
SOURCE = b'#include <stdio.h>\nint main(void) { puts("ENZIMOS-CLEAN-BUILDER-OK"); return 0; }\n'
LICENSE = b'SPDX-License-Identifier: MIT\nOriginal enzimOS disposable compiler probe.\n'


def qualify(check, payload):
    payload = Path(payload)
    plan = json.loads((payload/'clean-builder-plan.json').read_text())
    expected = {row['name']: row['version'] for row in plan['packages']}
    check({'base-devel', 'devtools', 'gcc', 'make', 'fakeroot', 'dbus-broker-units'} <= set(expected), 'incomplete clean builder closure')
    check(not BASE.exists(), 'fresh clean build root required')
    host_inventory = native.output(['pacman', '-Q']);authority = native.authority_identity()
    native.run(['btrfs', 'subvolume', 'create', BASE])
    for name in ('var/lib/pacman', 'var/cache/pacman/pkg', 'dev', 'proc', 'sys', 'run', 'tmp', 'build'):(BASE/name).mkdir(parents=True, exist_ok=True)
    config = Path('/run/clean-builder-pacman.conf')
    config.write_text('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n')
    # A new public-only admission cache is compiled from this exact verified
    # builder closure; never broaden or roll back the guest's current authority.
    keys = Path('/run/clean-builder-public-keys');keys.mkdir(mode=0o700)
    for name in ('pubring.gpg', 'trustdb.gpg', 'gpg.conf'):shutil.copyfile(payload/'builder-public-keys'/name, keys/name)
    packages = []
    for row in plan['packages']:
        file = payload/'builder-packages'/row['url'].rsplit('/', 1)[-1]
        check(file.is_file() and native.sha(file) == row['sha256_from_metadata'], 'builder package bytes changed')
        packages.append(str(file))
    native.run(['mount', '--rbind', '/dev', BASE/'dev']);native.run(['mount', '--make-rslave', BASE/'dev'])
    native.run(['mount', '-t', 'proc', 'proc', BASE/'proc'])
    native.run(['mount', '-t', 'sysfs', '-o', 'ro', 'sysfs', BASE/'sys'])
    native.run(['mount', '-t', 'tmpfs', '-o', 'mode=0755', 'tmpfs', BASE/'run'])
    try:
        native.run(['pacman', '--root', BASE, '--config', config, '--gpgdir', keys, '--noconfirm', '-U', *packages])
        actual = native.output(['pacman', '--root', BASE, '--config', config, '-Q'])
        check(dict(line.split(' ', 1) for line in actual.splitlines()) == expected, 'clean installed dependency set mismatch')
        native.run(['chroot', BASE, '/usr/bin/useradd', '-m', '-u', '1000', '-s', '/bin/bash', 'builder'])
        native.run(['chmod', '1777', BASE/'tmp'])
        artifacts = []
        for iteration in range(2):
            work = BASE/'build';work.chmod(0o755);os.chown(work, 1000, 1000)
            (work/'hello.c').write_bytes(SOURCE);(work/'LICENSE').write_bytes(LICENSE)
            recipe = '''pkgname=enzimos-compiler-probe
pkgver=0.0.1
pkgrel=1
pkgdesc='Disposable original clean compiler probe'
arch=('x86_64')
license=('MIT')
depends=('glibc')
makedepends=('gcc')
source=('hello.c' 'LICENSE')
sha256sums=('%s' '%s')
build() { gcc -O2 -Wall -Wextra -Werror -o hello hello.c; }
check() { test "$(./hello)" = ENZIMOS-CLEAN-BUILDER-OK; }
package() {
 install -Dm755 hello "$pkgdir/usr/bin/enzimos-compiler-probe"
 install -Dm644 LICENSE "$pkgdir/usr/share/licenses/enzimos-compiler-probe/LICENSE"
}
''' % (hashlib.sha256(SOURCE).hexdigest(), hashlib.sha256(LICENSE).hexdigest())
            (work/'PKGBUILD').write_text(recipe)
            for path in work.iterdir():os.chown(path, 1000, 1000)
            native.run(['chroot', '--userspec=1000:1000', BASE, '/usr/bin/env', '-i', 'PATH=/usr/bin', 'HOME=/home/builder',
                        'LANG=C.UTF-8', 'TZ=UTC', 'SOURCE_DATE_EPOCH=1789516800', 'MAKEFLAGS=-j1',
                        '/usr/bin/bash', '-c', 'cd /build && makepkg --noconfirm'])
            built = list(work.glob('*.pkg.tar.zst'))
            check(len(built) >= 1, 'clean build produced no package')
            package = next(path for path in built if path.name.startswith('enzimos-compiler-probe-0'))
            with tarfile.open(package, 'r|zst') as archive:
                metadata = None;binary = False
                for member in archive:
                    if member.name == '.BUILDINFO':metadata = archive.extractfile(member).read().decode()
                    if member.name == 'usr/bin/enzimos-compiler-probe':binary = member.isfile() and member.uid == member.gid == 0
                check(binary and metadata and 'installed = gcc-'+expected['gcc']+'-x86_64' in metadata, 'build metadata/compiler missing')
            artifacts.append({'sha256': native.sha(package), 'bytes': package.stat().st_size})
            work.rename(BASE/('build-evidence-'+str(iteration)));work.mkdir()
        check(artifacts[0] == artifacts[1], 'fresh clean compiler outputs differ')
        check(native.output(['pacman', '-Q']) == host_inventory and native.authority_identity() == authority, 'guest source system/authority changed')
        result = {'clean_installed_packages': len(expected), 'real_gcc_compile_and_check': True,
                  'dependency_checks_enabled': True, 'two_same_environment_archives_equal': True,
                  'artifacts': artifacts, 'guest_system_inventory_authority_preserved': True,
                  'native_policy_clean_build_qualified': False, 'cross_host_reproducibility': False,
                  'host_toolchain_used_for_package': False, 'shipping_compiler_probe': False}
        (Path('/var/lib/enzimos-control')/'clean-builder-result.json').write_text(json.dumps(result, indent=2)+'\n')
        return result
    finally:
        for name in ('run', 'sys', 'proc', 'dev'):native.run(['umount', '-R', BASE/name])
