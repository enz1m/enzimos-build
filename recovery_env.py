#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the on-disk recovery environment (D-031): a kernel, a small initramfs,
base.sfs and usr.sfs. It boots from the ESP into a RAM root, independent of
the installed root, and runs the recovery screen with its own copies of the
recovery tools, restic, networking, storage and crypto."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

from build_initrd_lab import builder_argv, run_command
from contract import Invalid
from signed_bootstrap import FREE_FLOOR, new_output

RECOVERY_UI = Path(__file__).resolve().parents[1]/'enzimos-recovery-ui'
# What the environment needs; their dependencies come along.
ROOTS = [
    'base', 'linux', 'mkinitcpio', 'plymouth', 'greetd', 'sudo', 'pam', 'shadow',
    'networkmanager', 'iproute2', 'iputils', 'openssh', 'cifs-utils',
    'cryptsetup', 'btrfs-progs', 'dosfstools', 'exfatprogs', 'ntfs-3g', 'e2fsprogs',
    'restic', 'mesa', 'vulkan-icd-loader', 'noto-fonts', 'ttf-dejavu',
    'linux-firmware-intel', 'linux-firmware-amdgpu', 'linux-firmware-radeon',
    'linux-firmware-realtek', 'linux-firmware-atheros', 'linux-firmware-mediatek',
    'linux-firmware-broadcom', 'linux-firmware-other', 'intel-ucode', 'amd-ucode',
    'enzimos-native-policy', 'enzimos-rust-packages', 'enzimos-rust-recovery-ui',
]
# The private recovery compositor's runtime (enzimos-recovery-ui
# package/compositor/PKGBUILD.in), plus libraries it links without declaring.
COMPOSITOR = re.compile(r"^depends=\((.*)\)$", re.M)
EXTRA_COMPOSITOR = ['tomlplusplus', 'libheif', 'libjxl', 'gdk-pixbuf2', 'libei', 'xcb-util-errors', 'xcb-util-wm']
# Never in the environment: it has no desktop, apps, Flatpak or AI.
EXCLUDE = re.compile(r'^(nvidia.*|linux-lts.*|linux-firmware-nvidia|flatpak.*|lib32-.*)$')
# Recovery screen files the desktop stage carries (tools/stage_boot_recovery.py).
STAGED = ['usr/bin/enzimos-recovery', 'usr/bin/enzimos-recovery-session',
          'usr/lib/enzimos-recovery-compositor', 'usr/share/enzimos-recovery',
          'usr/lib/enzimos-recovery/terminalrc', 'usr/lib/sysusers.d/enzimos-recovery.conf',
          'usr/lib/tmpfiles.d/enzimos-recovery.conf', 'etc/sudoers.d/enzimos-recovery-tools',
          'etc/sudoers.d/enzimos-recovery-power', 'usr/share/plymouth/themes/enzimos',
          'etc/plymouth/plymouthd.conf', 'usr/share/enzimos/os-release']
ENV_FILES = {
    'recovery-env-root.sh': ('usr/lib/enzimos-recovery-env/recovery-env-root.sh', 0o755),
    'enzimos-recovery-env-root.service': ('usr/lib/systemd/system/enzimos-recovery-env-root.service', 0o644),
    'mkinitcpio-recovery-env.conf': ('etc/mkinitcpio-recovery-env.conf', 0o644),
    'recovery-env-prepare': ('usr/lib/enzimos-recovery-env/recovery-env-prepare', 0o755),
    'enzimos-recovery-env-prepare.service': ('usr/lib/systemd/system/enzimos-recovery-env-prepare.service', 0o644),
    'greetd.toml': ('etc/greetd/config.toml', 0o644),
}
PKGINFO = re.compile(r'^(pkgname|pkgver|depend|provides) = (.+)$', re.M)


def bare(relation):
    """A dependency or provision without its version constraint."""
    return re.split(r'[<>=]', relation, maxsplit=1)[0]


def index(folders):
    """name -> (archive, depends); provided names map to the providing package.
    A later folder's package replaces an earlier one of the same name (the
    enzimOS builds of greetd and the portal replace Arch's)."""
    packages, provided = {}, {}
    for folder in folders:
        for archive in sorted(Path(folder).glob('*.pkg.tar.zst')):
            with tarfile.open(archive, 'r|zst') as t:
                for member in t:
                    if member.name == '.PKGINFO':
                        info = t.extractfile(member).read().decode()
                        break
                else:
                    raise Invalid(f'{archive.name} has no .PKGINFO')
            fields = PKGINFO.findall(info)
            name = next(v for k, v in fields if k == 'pkgname')
            packages[name] = (archive, [bare(v) for k, v in fields if k == 'depend'])
            for k, v in fields:
                if k == 'provides':
                    provided.setdefault(bare(v), name)
    return packages, provided


def closure(packages, provided, roots):
    chosen, queue = set(), list(roots)
    while queue:
        wanted = queue.pop()
        name = wanted if wanted in packages else provided.get(wanted)
        if name is None:
            raise Invalid(f'nothing provides {wanted}')
        if name in chosen or EXCLUDE.match(name):
            continue
        chosen.add(name)
        queue.extend(packages[name][1])
    return sorted(chosen)


def sha(path):
    with open(path, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


ENTRY = """title   enzimOS Recovery
linux   /enzimos/recovery-env/vmlinuz
initrd  /enzimos/recovery-env/initrd.img
options rd.systemd.wants=enzimos-recovery-env-root.service rd.systemd.gpt_auto=no systemd.firstboot=no quiet loglevel=3
"""


PUBLISH_UNIT = """[Unit]
Description=Put the enzimOS recovery environment on the ESP
ConditionPathExists=/usr/lib/enzimos/recovery-env/usr.sfs
RequiresMountsFor=/boot
[Service]
Type=oneshot
ExecStart=/usr/lib/enzimos/recovery-env-publish
[Install]
WantedBy=multi-user.target
"""
PUBLISH_HOOK = """[Trigger]
Type = Package
Operation = Install
Operation = Upgrade
Target = enzimos-recovery-env
[Action]
Description = Putting the recovery environment on the ESP...
When = PostTransaction
# A no-op until systemd-boot is installed (the installer's own transaction).
Exec = /usr/lib/enzimos/recovery-env-publish
"""


def package(output, artifacts):
    """enzimos-recovery-env: the environment under /usr/lib/enzimos/recovery-env
    and the service that puts it on the ESP with its boot entry (the installer
    requires an empty ESP until it installs the boot loader). The boot menu's
    Graphical recovery selects that entry."""
    work = output/'package'
    work.mkdir()
    for name in ('vmlinuz', 'initrd.img', 'base.sfs', 'usr.sfs'):
        os.link(artifacts/name, work/name)
    (work/'enzimos-recovery-env.conf').write_text(ENTRY)
    (work/'enzimos-recovery-env-publish.service').write_text(PUBLISH_UNIT)
    (work/'enzimos-recovery-env.hook').write_text(PUBLISH_HOOK)
    shutil.copyfile(RECOVERY_UI/'env/recovery-env-publish', work/'recovery-env-publish')
    lib = '"$pkgdir/usr/lib/enzimos/recovery-env'
    installs = ''.join(f'  install -Dm644 "$startdir/{n}" {lib}/{n}"\n' for n in ('vmlinuz', 'initrd.img', 'base.sfs', 'usr.sfs', 'enzimos-recovery-env.conf'))
    (work/'PKGBUILD').write_text(f"""pkgname=enzimos-recovery-env
pkgver=0.1.0
pkgrel=1
pkgdesc='enzimOS on-disk recovery environment (RAM root from the ESP)'
arch=('x86_64')
license=('custom')
options=('!strip' '!debug' '!lto')
package() {{
{installs}  install -Dm755 "$startdir/recovery-env-publish" "$pkgdir/usr/lib/enzimos/recovery-env-publish"
  install -Dm644 "$startdir/enzimos-recovery-env-publish.service" "$pkgdir/usr/lib/systemd/system/enzimos-recovery-env-publish.service"
  install -d "$pkgdir/usr/lib/systemd/system/multi-user.target.wants"
  ln -s ../enzimos-recovery-env-publish.service "$pkgdir/usr/lib/systemd/system/multi-user.target.wants/enzimos-recovery-env-publish.service"
  install -Dm644 "$startdir/enzimos-recovery-env.hook" "$pkgdir/usr/share/libalpm/hooks/90-enzimos-recovery-env.hook"
}}
""")
    (work/'makepkg.conf').write_text('CARCH="x86_64"\nCHOST="x86_64-pc-linux-gnu"\nBUILDENV=(!distcc !color !ccache !check !sign)\n'
                                     'OPTIONS=(!strip !docs !libtool !staticlibs emptydirs !zipman !purge !debug !lto)\n'
                                     'PKGEXT=".pkg.tar.zst"\nSRCEXT=".src.tar.gz"\nCOMPRESSZST=(zstd -1 -T2 -c -q -)\nPACKAGER="enzimOS <dev@enzimos.invalid>"\n')
    env = {'PATH': '/usr/bin', 'LANG': 'C.UTF-8', 'HOME': str(work), 'SOURCE_DATE_EPOCH': '1789344000',
           'BUILDDIR': str(work/'build'), 'PKGDEST': str(work), 'SRCDEST': str(work)}
    run = subprocess.run(['makepkg', '--config', str(work/'makepkg.conf'), '--nodeps', '--noconfirm', '--holdver'],
                         cwd=work, env=env, capture_output=True, text=True, timeout=1800)
    (output/'package.log').write_text(run.stdout + run.stderr)
    if run.returncode:
        raise Invalid('recovery environment package failed; see package.log')
    built, = work.glob('enzimos-recovery-env-*.pkg.tar.zst')
    return built


def build(package_folders, desktop, output, fast=False, recovery_build=None):
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR + 6 * 1024**3:
        raise Invalid('insufficient scratch headroom')
    output = new_output(output)
    packages, provided = index(package_folders)
    declared = COMPOSITOR.search((RECOVERY_UI/'package/compositor/PKGBUILD.in').read_text())
    compositor = [bare(d.strip("'")) for d in declared.group(1).split()] if declared else []
    names = closure(packages, provided, ROOTS + compositor + EXTRA_COMPOSITOR)
    work = output/'env'
    work.mkdir()
    (work/'packages.txt').write_text(''.join(str(packages[n][0]) + '\n' for n in names))
    root = work/'root'
    script = r'''
set -euo pipefail
mkdir -m 0755 /work/root
while read -r archive; do
    bsdtar -xpf "$archive" -C /work/root --numeric-owner --exclude .PKGINFO --exclude .BUILDINFO --exclude .MTREE --exclude .INSTALL --exclude .CHANGELOG
done < /work/packages.txt
'''
    binds = []
    for folder in package_folders:
        binds += ['--ro-bind', str(Path(folder).resolve()), str(Path(folder).resolve())]
    sandbox = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib', '/lib64', '--proc', '/proc', '--dev', '/dev', '--dir', '/etc',
            '--tmpfs', '/tmp', '--bind', str(work), '/work', *binds, '--setenv', 'PATH', '/usr/bin',
            '--setenv', 'FAKEROOTDONTTRYCHOWN', '1', '--setenv', 'LANG', 'C.UTF-8', '--']
    fake = sandbox + ['/usr/bin/fakeroot', '-s', '/work/fakeroot.state', '--', '/usr/bin/bash', '-c']
    run_command(fake + [script], output, 'env-root', 1800)
    stage = Path(desktop).resolve(strict=True)
    for rel in STAGED:
        source, dest = stage/rel, root/rel
        if not source.exists():
            if dest.exists() or dest.is_symlink():
                continue  # a package already supplies it
            raise Invalid(f'neither the desktop stage nor a package has {rel}')
        dest.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, dest, symlinks=True, dirs_exist_ok=True)
        else:
            shutil.copy2(source, dest, follow_symlinks=False)
    for name, (rel, mode) in ENV_FILES.items():
        dest = root/rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(RECOVERY_UI/'env'/name, dest)
        dest.chmod(mode)
    shutil.copyfile(RECOVERY_UI/'data/hyprland.lua', root/'usr/share/enzimos-recovery/hyprland.lua')
    if recovery_build:
        # A newer recovery screen and backup tool than the desktop stage's.
        built = Path(recovery_build).resolve(strict=True)
        for name, rel in (('enzimos-recovery', 'usr/bin/enzimos-recovery'),
                          ('enzimos-recovery-backup', 'usr/lib/enzimos-recovery/enzimos-recovery-backup')):
            if (built/name).is_file():
                shutil.copyfile(built/name, root/rel)
                (root/rel).chmod(0o755)
    # Restoring a backup is authorized by the backup's own password, so the
    # kiosk may run the backup tool; only in this environment.
    rule = root/'etc/sudoers.d/enzimos-recovery-backup'
    rule.write_text('enzimos-recovery ALL=(root) NOPASSWD: /usr/lib/enzimos-recovery/enzimos-recovery-backup\n')
    rule.chmod(0o440)
    etc = root/'etc'
    (etc/'enzimos-recovery-env').write_text('enzimOS recovery environment\n')
    (etc/'hostname').write_text('enzimos-recovery\n')
    (etc/'locale.conf').write_text('LANG=C.UTF-8\n')
    shutil.copyfile(root/'usr/share/enzimos/os-release', etc/'os-release')
    units = etc/'systemd/system'
    (units/'graphical.target.wants').mkdir(parents=True, exist_ok=True)
    (units/'multi-user.target.wants').mkdir(parents=True, exist_ok=True)
    for link, target in [('default.target', '/usr/lib/systemd/system/graphical.target'),
                         ('display-manager.service', '/usr/lib/systemd/system/greetd.service'),
                         ('graphical.target.wants/enzimos-recovery-env-prepare.service', '/usr/lib/systemd/system/enzimos-recovery-env-prepare.service'),
                         ('multi-user.target.wants/NetworkManager.service', '/usr/lib/systemd/system/NetworkManager.service'),
                         ('multi-user.target.wants/systemd-resolved.service', '/usr/lib/systemd/system/systemd-resolved.service')]:
        os.symlink(target, units/link)
    # A RAM environment runs no installed-system maintenance or first-boot setup.
    # The wall password agent stops the console agent once boot reaches
    # multi-user, which would take the unlock prompt away from the keyboard.
    for unit in ['systemd-firstboot.service', 'getty@tty1.service', 'autovt@tty1.service',
                 'systemd-ask-password-wall.service', 'systemd-ask-password-wall.path',
                 'snapper-cleanup.timer', 'snapper-timeline.timer', 'fstrim.timer', 'man-db.timer',
                 'archlinux-keyring-wkd-sync.timer', 'systemd-tmpfiles-clean.timer'] + [
                 f'enzimos-{job}.{kind}' for job in ('backup', 'scrub', 'deferred', 'home-history', 'trim', 'generation-retention')
                 for kind in ('timer', 'service')]:
        os.symlink('/dev/null', units/unit)
    os.symlink('/run/systemd/resolve/stub-resolv.conf', etc/'resolv.conf.new')
    os.replace(etc/'resolv.conf.new', etc/'resolv.conf')
    artifacts = work/'artifacts'
    artifacts.mkdir()
    modules = [d for d in (root/'usr/lib/modules').iterdir() if (d/'pkgbase').is_file() and (d/'pkgbase').read_text().strip() == 'linux']
    if len(modules) != 1:
        raise Invalid('exactly one recovery kernel expected')
    kver = modules[0].name
    run_command(builder_argv(root, artifacts, ['/usr/bin/systemd-sysusers']), output, 'env-sysusers', 60)
    run_command(builder_argv(root, artifacts, ['/usr/bin/systemd-hwdb', 'update', '--usr']), output, 'env-hwdb', 120)
    run_command(builder_argv(root, artifacts, ['/usr/bin/depmod', '-a', kver]), output, 'env-depmod', 300)
    run_command(builder_argv(root, artifacts, ['/usr/bin/mkinitcpio', '-k', kver, '-c', '/etc/mkinitcpio-recovery-env.conf', '-g', '/tmp/artifacts/initrd.img']), output, 'env-initrd', 900)
    shutil.copyfile(modules[0]/'vmlinuz', artifacts/'vmlinuz')
    level, processors = ('3', '8') if fast else ('15', '2')
    squash = (f'cd /work && find root -xdev -uid {os.getuid()} -exec chown -h 0:0 {{}} + && '
              f'mksquashfs root/usr artifacts/usr.sfs -noappend -comp zstd -Xcompression-level {level} -b 1M -processors {processors} -mem 256M -no-progress -quiet && '
              f'mksquashfs root artifacts/base.sfs -noappend -e usr -comp zstd -Xcompression-level {level} -b 1M -processors {processors} -mem 256M -no-progress -quiet')
    run_command(sandbox + ['/usr/bin/fakeroot', '-i', '/work/fakeroot.state', '-s', '/work/fakeroot.state', '--', '/usr/bin/bash', '-c', squash], output, 'env-squashfs', 3600)
    files = {name: {'bytes': (artifacts/name).stat().st_size, 'sha256': sha(artifacts/name)}
             for name in ('vmlinuz', 'initrd.img', 'base.sfs', 'usr.sfs')}
    result = {'schema': 1, 'status': 'PASS-recovery-env-built', 'package': str(package(output, artifacts)), 'kernel': kver, 'packages': names,
              'files': files, 'bytes': sum(f['bytes'] for f in files.values()), 'release_authorized': False}
    (output/'result.json').write_text(json.dumps(result, indent=2) + '\n')
    shutil.rmtree(root, ignore_errors=True)
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--packages', type=Path, action='append', required=True, help='folder of verified packages (repeatable)')
    p.add_argument('--desktop', type=Path, required=True, help='desktop stage with the recovery screen files')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--fast', action='store_true', help='quick compression for iteration')
    p.add_argument('--recovery-build', type=Path, help='folder with newer enzimos-recovery and enzimos-recovery-backup binaries')
    a = p.parse_args()
    r = build(a.packages, a.desktop, a.output, a.fast, a.recovery_build)
    print(json.dumps({k: r[k] for k in ('status', 'kernel', 'bytes')} | {'packages': len(r['packages'])}))
