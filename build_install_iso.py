#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the enzimOS development install ISO (hybrid BIOS/UEFI, Limine) from verified inputs.

Contents: the reviewed quorum-verified package cohort with detached signatures, the approved
public-key cache, the native-policy package (signed on the target machine at install time
with a key generated there; no enzimOS signing key exists yet), a live installer initramfs
built with the verified toolroot's mkinitcpio, and Limine BIOS/UEFI boot files. Unprivileged,
sandboxed, no network, no host package or key changes. A development artifact: NOT a release.
"""
import argparse
from datetime import datetime, timezone
import json
import os
import re
from pathlib import Path
import shutil
from stat import S_IMODE
import subprocess
import sys

from contract import Invalid, digest, load
from build_initrd_lab import builder_argv, run_command
from package_trust import verify_plan
import dev_access
from prepare_target_lab import public_cache, GPG_CONFIG
from signed_bootstrap import FREE_FLOOR, new_output
from lab_resources import constrain_job
from headless_plan import DESKTOP_INTEGRATION, LOGIN_PERSONALIZATION

RUNTIME_REPOS = Path(__file__).resolve().parent.parent
INSTALLER = RUNTIME_REPOS/'enzimos-installer/live'
VOLUME = 'ENZIMOS_INSTALL'
OFFICIAL_FLATPAK_MEDIA = 'PASS-official-flatpak-media'
ENZIMOS_DESCRIPTOR_SHA256 = 'd9628aee0aaca7826c9410719b1d72daefe9d55ffc9a813c831b7ff7979c89ff'
# Keep assembly bounded while carrying offline accessibility voices and Unicode
# data. Accessibility added~47MiB; the reviewed native Store and existing
# CPU/Vulkan/speech runtime archives add~73MiB. Keep a finite development bound.
# The 761-package reviewed desktop/device closure also carries its offline bytes
# on the media, plus the five Rust runtime packages. The base AI models
# (LFM3-VL-2B, MiniCPM5 and Whisper, ~1.8 GB), offline streaming speech
# (~120 MB) and the on-disk recovery environment (~1.2 GB) add about 3 GB.
# Keep a fixed ceiling; do not infer a release payload from size.
MAX_ISO = 12*1024**3
# Installer files placed in the live root (source name -> path in the root).
LIVE_FILES = {'enzimos-install.sh': 'usr/lib/enzimos-installer/enzimos-install.sh',
              'live-select.sh': 'usr/lib/enzimos-installer/live-select.sh',
              'installer-session.sh': 'usr/lib/enzimos-installer-ui/installer-session',
              'installer-hyprland.lua': 'usr/share/enzimos-installer-ui/hyprland.lua',
              'enzimos-live.sysusers': 'usr/lib/sysusers.d/enzimos-live.conf',
              'enzimos-live.tmpfiles': 'usr/lib/tmpfiles.d/enzimos-live.conf',
              'enzimos-live.sudoers': 'etc/sudoers.d/enzimos-live',
              'live-root.sh': 'usr/lib/enzimos-live/live-root.sh',
              'mkinitcpio-live.conf': 'etc/mkinitcpio-live.conf',
              'enzimos-live-root.service': 'usr/lib/systemd/system/enzimos-live-root.service',
              'enzimos-live-select.service': 'usr/lib/systemd/system/enzimos-live-select.service',
              'enzimos-installer.service': 'usr/lib/systemd/system/enzimos-installer.service',
              'enzimos-installer-serial.service': 'usr/lib/systemd/system/enzimos-installer-serial.service',
              'enzimos-installer-ui.service': 'usr/lib/systemd/system/enzimos-installer-ui.service'}
# Packages the live system itself never needs (they stay on the medium for the target).
LIVE_EXCLUDE = {'nvidia-open', 'nvidia-open-lts', 'nvidia-utils', 'linux-lts', 'linux-firmware-nvidia',
                'restic', 'flatpak', 'gnome-keyring', 'oo7'}
LIVE_SCRIPT = r"""
set -euo pipefail
cd /work
mkdir -m 0755 root
while read -r pkg; do
    bsdtar -xpf "/packages/$pkg" -C root --numeric-owner --exclude .PKGINFO --exclude .BUILDINFO --exclude .MTREE --exclude .INSTALL --exclude .CHANGELOG
done < live-packages.txt
cp -a /desktop/. root/
# The reviewed native packages take precedence over inherited desktop helpers.
bsdtar -xpf /policy.pkg.tar.zst -C root --numeric-owner --exclude .PKGINFO --exclude .BUILDINFO --exclude .MTREE --exclude .INSTALL --exclude .CHANGELOG
bsdtar -xpf /policy-native.pkg.tar.zst -C root --numeric-owner --exclude .PKGINFO --exclude .BUILDINFO --exclude .MTREE --exclude .INSTALL --exclude .CHANGELOG
bsdtar -xpf /installer-native.pkg.tar.zst -C root --numeric-owner --exclude .PKGINFO --exclude .BUILDINFO --exclude .MTREE --exclude .INSTALL --exclude .CHANGELOG
while read -r source dest; do install -D -m "$( [[ $source == *.sh ]] && echo 0755 || echo 0644 )" "/installer/$source" "root/$dest"; done < live-files.txt
compositor=usr/lib/enzui/compositor/hyprland-current-build
compositor_bin=$compositor/enz-hyprland
compositor_ctl=$compositor/hyprctl/enz-hyprctl
if [[ ! -x root/$compositor_bin && ! -x root/$compositor_ctl ]]; then
    compositor_bin=usr/bin/Hyprland
    compositor_ctl=usr/bin/hyprctl
fi
for executable in usr/lib/enzimos-installer-ui/installer-session "$compositor_bin" "$compositor_ctl" usr/bin/enzimos-installer; do
    [[ -x root/$executable ]] || { echo "Missing executable in graphical installer: /$executable" >&2; exit 1; }
done
install -m 0644 VERSION root/usr/lib/enzimos-installer/VERSION
chmod 0440 root/etc/sudoers.d/enzimos-live
ln -sf /usr/lib/systemd/system/graphical.target root/etc/systemd/system/default.target
mkdir -p root/etc/systemd/system/graphical.target.wants
ln -sf /usr/lib/systemd/system/enzimos-live-select.service root/etc/systemd/system/graphical.target.wants/
# Native package staging and signing stay in RAM on /run itself (the installer
# requires that), and the recovery environment and AI models need more of it
# than systemd's default 20%: systemd-remount-fs applies this to /run.
echo 'tmpfs /run tmpfs nosuid,nodev,mode=0755,size=70% 0 0' >> root/etc/fstab
ln -sf /usr/lib/systemd/system/NetworkManager.service root/etc/systemd/system/graphical.target.wants/
ln -sf /usr/lib/systemd/system/systemd-resolved.service root/etc/systemd/system/graphical.target.wants/
ln -sf /run/systemd/resolve/stub-resolv.conf root/etc/resolv.conf
ln -sf /dev/null root/etc/systemd/system/serial-getty@ttyS0.service
# tty1 always belongs to an installer (graphical or text); a login prompt there would hang it up.
ln -sf /dev/null root/etc/systemd/system/getty@tty1.service
ln -sf /dev/null root/etc/systemd/system/autovt@tty1.service
ln -sf /dev/null root/etc/systemd/system/systemd-firstboot.service
# Installed-system maintenance has no storage authority in the RAM kiosk.
for unit in enzimos-backup enzimos-scrub enzimos-deferred enzimos-home-history enzimos-trim enzimos-generation-retention; do
    ln -sf /dev/null "root/etc/systemd/system/$unit.timer"
    ln -sf /dev/null "root/etc/systemd/system/$unit.service"
done
ln -sf /usr/share/zoneinfo/UTC root/etc/localtime
# The kiosk session needs no desktop portal (it only crash-loops without a portal backend).
mkdir -p root/etc/systemd/user
ln -sf /dev/null root/etc/systemd/user/xdg-desktop-portal.service
# Development medium: warnings and unit failures also reach the serial console.
mkdir -p root/etc/systemd/journald.conf.d
printf '[Journal]\nForwardToConsole=yes\nTTYPath=/dev/ttyS0\nMaxLevelConsole=info\n' > root/etc/systemd/journald.conf.d/50-enzimos-live-serial.conf
echo enzimos-live > root/etc/hostname
echo LANG=C.UTF-8 > root/etc/locale.conf
cp root/usr/share/enzimos/os-release root/etc/os-release
chown -R 0:0 root/usr/lib/enzimos-installer root/usr/lib/enzimos-live root/etc/systemd/system root/etc/systemd/user root/etc/hostname root/etc/locale.conf root/etc/sudoers.d root/usr/lib/sysusers.d root/usr/lib/tmpfiles.d
chown -h 0:0 root/etc/localtime
"""


def live_root(verified, cohort, desktop, out, version_file, policy_package, installer_package,
              policy_runtime_package, *, installer=INSTALLER):
    """The live installer system: the verified packages (minus target-only ones), the enzUI
    desktop snapshot + graphical installer, as a root-owned squashfs; its own kernel and a
    small initramfs that mounts it (so the live kernel always matches its modules)."""
    work = out/'live';work.mkdir()
    excluded = LIVE_EXCLUDE | {r['name'] for r in verified['packages'] if r.get('surface_touch_only')}
    names = sorted(r['url'].rsplit('/', 1)[-1] for r in verified['packages']
                   if r['name'] not in excluded and not r['name'].startswith('lib32-'))
    (work/'live-packages.txt').write_text(''.join(n+'\n' for n in names))
    (work/'live-files.txt').write_text(''.join(f'{a} {b}\n' for a, b in LIVE_FILES.items()))
    shutil.copyfile(version_file, work/'VERSION')
    def fake(script, state_in):
        return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
                '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib', '/lib64',
                '--proc', '/proc', '--dev', '/dev', '--dir', '/etc', '--tmpfs', '/tmp', '--bind', str(work), '/work',
                '--ro-bind', str(cohort/'packages'), '/packages', '--ro-bind', str(Path(desktop).resolve(strict=True)), '/desktop',
                '--ro-bind', str(Path(policy_package).resolve(strict=True)), '/policy.pkg.tar.zst', '--ro-bind', str(installer), '/installer', '--ro-bind', str(Path(installer_package).resolve(strict=True)), '/installer-native.pkg.tar.zst', '--ro-bind', str(Path(policy_runtime_package).resolve(strict=True)), '/policy-native.pkg.tar.zst', '--setenv', 'PATH', '/usr/bin', '--setenv', 'FAKEROOTDONTTRYCHOWN', '1', '--setenv', 'LANG', 'C.UTF-8', '--',
                '/usr/bin/fakeroot', *(['-i', '/work/fakeroot.state'] if state_in else []), '-s', '/work/fakeroot.state', '--', '/usr/bin/bash', '-c', script]
    run_command(fake(LIVE_SCRIPT, False), out, 'live-root', 1800)
    root = work/'root'
    modules = [d for d in (root/'usr/lib/modules').iterdir() if (d/'pkgbase').is_file() and (d/'pkgbase').read_text().strip() == 'linux']
    if len(modules) != 1:raise Invalid('exactly one live kernel expected')
    kver = modules[0].name
    artifacts = work/'artifacts';artifacts.mkdir()
    # Extraction does not run package hooks. Populate static device groups and
    # the hardware database before mkinitcpio copies them into the early boot.
    run_command(builder_argv(root, artifacts, ['/usr/bin/systemd-sysusers']), out, 'live-sysusers', 60)
    run_command(builder_argv(root, artifacts, ['/usr/bin/systemd-hwdb', 'update', '--usr']), out, 'live-hwdb', 60)
    # Live packages are extracted without pacman hooks. AT-SPI/GTK need this
    # cache even in the installer kiosk; use the verified live GLib compiler.
    schemas=root/'usr/share/glib-2.0/schemas'
    if schemas.is_dir() and any(schemas.glob('*.gschema.xml')):
        run_command(builder_argv(root, artifacts, ['/usr/bin/glib-compile-schemas','--strict','--targetdir=/tmp/artifacts','/usr/share/glib-2.0/schemas']), out, 'live-gsettings-schemas', 60)
        shutil.copyfile(artifacts/'gschemas.compiled',schemas/'gschemas.compiled')
    run_command(builder_argv(root, artifacts, ['/usr/bin/depmod', '-a', kver]), out, 'live-depmod', 300)
    run_command(builder_argv(root, artifacts, ['/usr/bin/mkinitcpio', '-k', kver, '-c', '/etc/mkinitcpio-live.conf', '-g', '/tmp/artifacts/enzimos-live.img']), out, 'live-initrd', 600)
    shutil.copyfile(modules[0]/'vmlinuz', artifacts/'vmlinuz-linux')
    rescue_config=root/'etc/mkinitcpio-installer-rescue.conf'
    rescue_config.write_text((root/'usr/lib/enzimos-native/recovery-rust-mkinitcpio.conf').read_text().replace(' autodetect',''))
    run_command(builder_argv(root, artifacts, ['/usr/bin/mkinitcpio', '-k', kver, '-c', '/etc/mkinitcpio-installer-rescue.conf', '-g', '/tmp/artifacts/enzimos-rescue.img']), out, 'rescue-initrd', 900)
    from rescue_runtime import check as check_rescue_runtime
    check_rescue_runtime(artifacts/'enzimos-rescue.img',out/'rescue-runtime-check',constrain=False)
    # The installer's gpg-agent runs as root and keeps its socket under /run/user/0 when
    # that exists; logind deletes it when root's last session ends (a console or SSH
    # login during the install), and the agent then exits. Lingering keeps it for the boot.
    (root/'var/lib/systemd/linger').mkdir(parents=True, exist_ok=True)
    (root/'var/lib/systemd/linger/root').touch()
    # Development builds only (ENZIMOS_DEV_SSH_KEY): key-only SSH into the live installer.
    if (dev_key := dev_access.key()) is not None:
        dev_access.apply(root, dev_key)
    # ENZIMOS_DEV_FAST: quick compression for iteration (larger image, same contents).
    level, processors = ('3', '8') if os.environ.get('ENZIMOS_DEV_FAST') else ('15', '2')
    # Files the unprivileged build steps created are the real user's; they belong to root.
    # SquashFS defaults its queues to 25% of host RAM, which can exceed the
    # builder cgroup. Bound the cache independently of compressor workers.
    squash = f"cd /work && find root -xdev -uid {os.getuid()} -exec chown -h 0:0 {{}} +; mksquashfs root live.sfs -noappend -comp zstd -Xcompression-level {level} -b 1M -processors {processors} -mem 256M -no-progress -quiet"
    run_command(fake(squash, True), out, 'live-squashfs', 3600)
    return {'kernel': kver, 'packages': len(names), 'excluded': sorted(excluded), 'squashfs': work/'live.sfs',
            'vmlinuz': artifacts/'vmlinuz-linux', 'initrd': artifacts/'enzimos-live.img', 'rescue_initrd':artifacts/'enzimos-rescue.img'}


def xorriso(stage, out):
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib', '/lib64',
            '--proc', '/proc', '--dev', '/dev', '--dir', '/etc', '--tmpfs', '/tmp',
            '--ro-bind', str(stage), '/source', '--bind', str(out), '/output', '--setenv', 'PATH', '/usr/bin', '--',
            '/usr/bin/prlimit', '--cpu=600:600', f'--fsize={MAX_ISO}:{MAX_ISO}', '--',
            '/usr/bin/xorriso', '-as', 'mkisofs', '-quiet', '-R', '-J', '-V', VOLUME,
            '-b', 'boot/limine/limine-bios-cd.bin', '-no-emul-boot', '-boot-load-size', '4', '-boot-info-table',
            '--efi-boot', 'boot/limine/limine-uefi-cd.bin', '-efi-boot-part', '--efi-boot-image', '--protective-msdos-label',
            '-o', '/output/enzimos.iso', '/source']


XWAYLAND_BINARY = 'usr/lib/enzui/compositor/hyprland-current-build/Xwayland'
XWAYLAND_COPYING = 'usr/share/licenses/enzui-desktop/Xwayland-COPYING'
XWAYLAND_RUNTIME = {'xorg-xwayland', 'xorg-xkbcomp', 'xkeyboard-config', 'libbsd', 'libmd'}


def check_desktop_xwayland(desktop, packages):
    desktop = Path(desktop).resolve(strict=True)
    lock = desktop / 'usr/share/enzui/sources.lock.json'
    pin = load(lock).get('xwayland') if lock.is_file() else None
    manifest_path = desktop / 'usr/share/enzui/manifest.json'
    manifest = load(manifest_path) if manifest_path.is_file() else {}
    receipt = manifest.get('compositor', {}).get('xwayland')
    if pin is None and receipt is None and not (desktop / XWAYLAND_BINARY).exists():
        return None
    if not pin or not receipt or any(receipt.get(key) != value for key, value in pin.items()):
        raise Invalid('desktop stage must include the locked Xwayland build receipt')
    for relative, mode, checksum in (
        (XWAYLAND_BINARY, 0o755, receipt.get('binary_sha256')),
        (XWAYLAND_COPYING, 0o644, receipt.get('notice_sha256')),
    ):
        path = desktop / relative
        if (path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(desktop)
                or S_IMODE(path.stat().st_mode) != mode or digest(path) != checksum):
            raise Invalid(f'desktop Xwayland companion or license differs from its receipt: {relative}')
    if missing := XWAYLAND_RUNTIME - set(packages):
        raise Invalid('desktop Xwayland runtime packages missing: ' + ', '.join(sorted(missing)))
    return receipt


def desktop_archive(stage, media, owned=frozenset()):
    """The enzUI desktop PREVIEW snapshot as one root-owned archive plus a per-file manifest.

    Paths a native package installed on the target owns are left out: the
    package provides them, and an archived copy would replace its files with
    the archive's uniform mtime (pacman -Qkk then reports them altered)."""
    stage = Path(stage).resolve(strict=True)
    files = {p.relative_to(stage).as_posix(): digest(p) for p in sorted(stage.rglob('*')) if p.is_file() and not p.is_symlink() and p.relative_to(stage).as_posix() not in owned}
    exclude = media/'desktop-preview.exclude'
    exclude.write_text(''.join('./'+rel+'\n' for rel in sorted(owned)))
    (media/'desktop-preview.json').write_text(json.dumps({'schema': 1, 'preview_snapshot': True, 'release_authorized': False,
        'source_revision': (stage/'usr/share/enzui/SOURCE-REVISION').read_text().strip(), 'files': files}, indent=2)+'\n')
    subprocess.run(['tar', '--sort=name', '--owner=0', '--group=0', '--numeric-owner', '--mtime=@1789344000', '--exclude-from', str(exclude), '-C', str(stage), '-I', 'zstd -T2 -10', '-cf', str(media/'desktop-preview.tar.zst'), '.'], check=True, timeout=900)
    exclude.unlink()
    return len(files)


DESKTOP_INTEGRATION_MARKER = 'usr/share/libalpm/hooks/95-enzimos-desktop-integration.hook'
EVERYDAY_STAGE_FILES = ('usr/lib/firewalld/policies/enz-mdns-trust.xml',
                       'usr/lib/firewalld/policies/enz-mdns-block.xml')
GAMING_STAGE_FILES = ('usr/lib/modules-load.d/30-enzimos-controller.conf',
                      'usr/bin/enzimos-gaming-check',
                      'usr/lib/systemd/user/background.slice.d/20-enzimos.conf',
                      'usr/lib/systemd/user/enzimos-inference.service.d/20-background.conf',
                      'usr/lib/systemd/system/enzimosbackground.slice',
                      *(f'usr/lib/systemd/system/{unit}.service.d/20-background.conf'
                        for unit in ('enzimos-backup', 'enzimos-scrub', 'enzimos-deferred', 'enzimos-home-history')))


def check_desktop_integration_packages(desktop, names):
    if (Path(desktop) / 'usr/lib/enzui/bin/enzui-password-hash').is_file():
        missing = LOGIN_PERSONALIZATION - set(names)
        if missing:
            raise Invalid('login personalization providers missing: ' + ', '.join(sorted(missing)))
    if (Path(desktop) / DESKTOP_INTEGRATION_MARKER).is_file():
        missing = DESKTOP_INTEGRATION - set(names)
        if missing:
            raise Invalid('desktop integration providers missing: ' + ', '.join(sorted(missing)))
        root = Path(desktop).resolve(strict=True)
        for relative in (*EVERYDAY_STAGE_FILES, *GAMING_STAGE_FILES):
            path = root / relative
            if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root):
                raise Invalid('everyday desktop policy missing or unsafe: ' + relative)


def replaced_dependents(cohort, records, replaced):
    """The Arch body installs the target cohort before any native package: none of it may
    depend on a package the media leave out for a native replacement."""
    for record in records:
        info = subprocess.run(['bsdtar', '-qxOf', str(cohort/'packages'/record['url'].rsplit('/', 1)[-1]), '.PKGINFO'],
                              capture_output=True, text=True, check=True, timeout=120).stdout
        for line in info.splitlines():
            key, _, value = line.partition(' = ')
            if key == 'depend' and value.split('>')[0].split('<')[0].split('=')[0] in replaced:
                raise Invalid(f"{record['name']} depends on replaced Arch package {value}")


def require_background_mcp(report_path):
    if report_path is None:raise Invalid('background controls require the policy-aware MCP broker')
    report=load(report_path)
    marker=report.get('files',{}).get('usr/share/enzui/mcp-center/background-policy.json',{})
    if (report.get('status')!='PASS-mcp-center-package-built' or report.get('package_name')!='enzui-mcp-center' or
            type(report.get('release')) is not int or report['release']<9 or
            marker.get('mode')!=0o644 or marker.get('sha256')!='f3669cc298cd6da9a59626a534f294e1d387cbc40fe27f38ee1b934266836098'):
        raise Invalid('background controls require the MCP broker reading activation policy ABI 2')


def live_menu(menu, development):
    """The live boot menu; media carrying development SSH access say so in the first entry."""
    if not development:
        return menu
    marked = menu.replace('\n/Install enzimOS\n', '\n/Install enzimOS (development access)\n', 1)
    if marked == menu:
        raise Invalid('live boot menu has no "Install enzimOS" entry to mark')
    return marked

def require_runtime_graphics(repo):
    """Require both Mesa GL.default refs alongside each Flathub Platform runtime."""
    root = repo/'refs/mirrors/org.flathub.Stable/runtime'
    extensions = root/'org.freedesktop.Platform.GL.default'
    for ref in sorted((root/'org.freedesktop.Platform').glob('*/*')):
        if not ref.is_file():
            continue
        arch, branch = ref.parent.name, ref.name
        missing = [name for name in (branch, branch + '-extra')
                   if not (extensions/arch/name).is_file()]
        if missing:
            raise Invalid(f'offline Flatpak runtime org.freedesktop.Platform/{arch}/{branch} '
                          f'lacks graphics extensions: {", ".join(missing)}')


def verify_official_flatpak_media(source, receipt, selected, flathub_apps, installer_version):
    expected = Path(__file__).with_name('default-flatpaks.txt').read_text().splitlines()
    if selected != expected or receipt.get('apps') != expected or flathub_apps:
        raise Invalid('official Flatpak media must carry the default fleet and Flathub runtimes only')
    if installer_version < (0, 2, 0, 4):
        raise Invalid('official Flatpak media require installer 0.2.0-4 or newer')
    if digest(source/'enzimos.flatpakrepo') != ENZIMOS_DESCRIPTOR_SHA256:
        raise Invalid('official Flatpak media has a different repository descriptor')
    repo = source/'usb/.ostree/repo/refs/mirrors/org.enzimos.Apps'
    commits = receipt.get('commits', {})
    for app in selected:
        ref = repo/f'app/{app}/x86_64/stable'
        commit = commits.get(app, '')
        if not re.fullmatch(r'[0-9a-f]{64}', commit) or not ref.is_file() or ref.read_text().strip() != commit:
            raise Invalid(f'official Flatpak media lacks the pinned stable deployment for {app}')
    if not (repo/'runtime/dev.enzim.WebKit.Platform/x86_64/26.08-1').is_file():
        raise Invalid('official Flatpak media lacks the Browser WebKit Platform')


def stage_flatpaks(media, flatpak=None, enzimos_flatpak=None, *, installer_version=(0, 2, 0, 3)):
    """Offline Flatpak sources on the medium, one directory per remote, each a create-usb
    repository plus its .flatpakrepo and apps.txt. Returns the manifest entries."""
    flatpaks, extra = [], {}
    if enzimos_flatpak and not flatpak:raise Invalid('enzimOS Flatpak apps need the Flathub runtime source')
    def apps(source):
        values = [line.strip() for line in (source/'apps.txt').read_text().splitlines() if line.strip()]
        if len(values) > 128 or len(values) != len(set(values)):
            raise Invalid('offline Flatpak selection must contain at most 128 distinct apps')
        return values
    if flatpak:
        flatpak = Path(flatpak).resolve(strict=True)
        flatpaks = [app for app in apps(flatpak) if app != 'app.zen_browser.zen']
    if enzimos_flatpak:
        enzimos_flatpak = Path(enzimos_flatpak).resolve(strict=True)
        receipt = load(enzimos_flatpak/'build.json')
        if receipt.get('status') != 'PASS-enzimos-flatpaks-prepared':
            raise Invalid('reviewed enzimOS Flatpak export required')
        extra['enzimos_flatpaks'] = apps(enzimos_flatpak)
        if not extra['enzimos_flatpaks'] or 'app.zen_browser.zen' in extra['enzimos_flatpaks']:
            raise Invalid('invalid enzimOS offline application selection')
        if set(extra['enzimos_flatpaks']) & set(flatpaks):
            raise Invalid('enzimOS Flatpak selection overlaps Flathub')
        if receipt.get('provenance') == OFFICIAL_FLATPAK_MEDIA:
            verify_official_flatpak_media(enzimos_flatpak, receipt, extra['enzimos_flatpaks'],
                                         flatpaks, installer_version)
    if not flatpaks and not enzimos_flatpak:
        flatpak = None
    if enzimos_flatpak and not flatpaks and installer_version < (0, 2, 0, 3):
        raise Invalid('Flathub runtimes without apps require installer 0.2.0-3 or newer')
    for source in (flatpak, enzimos_flatpak):
        if source is not None:
            require_runtime_graphics(source/'usb/.ostree/repo')
    for source, directory, descriptor, selected in (
        (flatpak, 'flatpak', 'flathub.flatpakrepo', flatpaks),
        (enzimos_flatpak, 'flatpak-enzimos', 'enzimos.flatpakrepo', extra.get('enzimos_flatpaks', [])),
    ):
        if source is None:
            continue
        staged = media/directory
        shutil.copytree(source/'usb/.ostree/repo', staged/'repo', symlinks=True)
        shutil.copyfile(source/descriptor, staged/descriptor)
        (staged/'apps.txt').write_text(''.join(app + '\n' for app in selected))
    return flatpaks, extra


def write_media_checksums(media):
    """Write hashes of media files, including the contents of OSTree aliases."""
    media = media.resolve(strict=True)
    sideloads = (media/'flatpak/repo', media/'flatpak-enzimos/repo')
    entries = []
    for path in sorted(media.rglob('*')):
        if path == media/'SHA256SUMS':
            continue
        source = path
        if path.is_symlink():
            repository = next((repo for repo in sideloads if path.is_relative_to(repo)), None)
            target = path.readlink()
            if (repository is None or target.is_absolute()
                    or not Path(os.path.normpath(path.parent/target)).is_relative_to(repository)):
                raise Invalid('installation media symlink must stay inside its Flatpak repository')
            try:
                source = path.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise Invalid('unresolvable Flatpak repository symlink') from exc
            if not source.is_relative_to(repository) or not source.is_file():
                raise Invalid('Flatpak repository symlink must reference a regular repository file')
        elif not path.is_file():
            continue
        entries.append(f'{digest(source)}  {path.relative_to(media)}\n')
    (media/'SHA256SUMS').write_text(''.join(entries))


def build(assembly, cohort, policy_build, keyring, trust_lock, output, label, desktop=None, backend_build=None, flatpak=None, update_build=None, secure_key=None, secure_certificate=None, mcp_build=None, ai_build=None, activity_build=None, store_build=None, permissions_build=None, harness_build=None, developer_build=None, remote_build=None, background_build=None, terminal_build=None, installer_build=None, monitor_build=None, portal_build=None, greetd_build=None, recovery_env_build=None, enzimos_flatpak=None, app_builds=None, keyring_build=None, phone_build=None, mount_build=None, aft_build=None, icon_theme_build=None, archive_keyring_build=None, *, runtime_repos=RUNTIME_REPOS, surface_touch_package=None):
    if not installer_build:raise Invalid('native installer package summary required for current live wrappers')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', label):
        raise Invalid('ISO label must be a single portable filename component')
    if background_build:require_background_mcp(mcp_build)
    if remote_build and not backend_build:raise Invalid('remote access requires the qualified Settings backend authority')
    if developer_build and not backend_build:raise Invalid('developer setup requires the qualified Settings backend authority')
    if store_build and not permissions_build:raise Invalid('native Store requires the shared permissions package')
    if os.geteuid() == 0:raise Invalid('unprivileged ISO build required')
    resources = constrain_job(cpu_limit=8)
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR+3*1024**3:raise Invalid('ISO build headroom')
    if assembly is not None:
        Path(assembly).resolve(strict=True)
    cohort = Path(cohort).resolve(strict=True)
    runtime_repos = Path(runtime_repos).resolve(strict=True)
    installer = runtime_repos/'enzimos-installer/live'
    pbuild = load(policy_build);package = Path(pbuild['package'])
    if pbuild['status'] != 'PASS-unsigned-policy-package-built' or digest(package) != pbuild['sha256']:raise Invalid('reviewed policy build required')
    lock = load(trust_lock)
    out = new_output(output);report = {'status': 'FAIL', 'release_authorized': False, 'development_artifact': True}
    try:
        verified = verify_plan(cohort/'resolution/resolution.json', keyring, cohort/'packages', out/'verification', trust_lock)
        if not 189 <= verified['package_count'] <= 1024:raise Invalid('reviewed install cohort size expected')
        if not any(record['name'] == 'linux-firmware-marvell' for record in verified['packages']):
            raise Invalid('install cohort must include linux-firmware-marvell for Marvell Wi-Fi')
        # A native replacement (patched portal) takes an Arch package's place on the target:
        # that Arch package stays out of the media pool (the live root still has it), so the
        # installer's Arch body never installs it and the native body meets no conflict.
        replaced = set()
        from native_apps_payload import replacement_names
        for report_path in (portal_build, greetd_build, keyring_build):
            if report_path: replaced.update(replacement_names(load(report_path)))
        if replaced:
            if replaced - {r['name'] for r in verified['packages']} - ({'gnome-keyring'} if keyring_build else set()):raise Invalid('replaced Arch package missing from the reviewed cohort')
        target_packages = [r for r in verified['packages'] if r['name'] not in replaced]
        if replaced:replaced_dependents(cohort, target_packages, replaced)
        if not desktop:raise Invalid('the live installer system needs the desktop stage (graphical installer)')
        if (Path(desktop)/'usr/lib/enzui/bin/enzui-keyring-prompt').is_file() and not keyring_build:
            raise Invalid('oo7 keyring package required for this desktop')
        if terminal_build:
            from terminal_payload import overlay
            desktop = overlay(terminal_build, desktop, out/'terminal-desktop')
        check_desktop_integration_packages(desktop, [r['name'] for r in verified['packages']])
        xwayland = check_desktop_xwayland(desktop, [r['name'] for r in target_packages])
        if pbuild['release'] >= 136 and 'earlyoom' not in {r['name'] for r in verified['packages']}:
            raise Invalid('memory protection runtime missing from installer cohort')
        version = out/'VERSION';version.write_text(f"{label} native-policy 0.1.0-{pbuild['release']} cohort {digest(cohort/'resolution/resolution.json')[:12]}\n")
        from rust_installer_payload import stage as stage_installer
        installer_admission = out/'native-installer';installer_admission.mkdir()
        native_installer = stage_installer(installer_build, installer_admission, installer)
        rust_summary = load(installer_build)
        from rust_runtime_payload import owned_paths as rust_owned_paths, stage as stage_rust_runtime
        runtime_admission = out/'native-target-runtime';runtime_admission.mkdir()
        native_rust = stage_rust_runtime(installer_build, runtime_admission, runtime_repos)
        stage = out/'iso-root';(stage/'boot/limine').mkdir(parents=True);(stage/'EFI/BOOT').mkdir(parents=True)
        media = stage/'enzimos';(media/'packages').mkdir(parents=True)
        installer_runtime = native_rust['installer']
        installer_version = (*map(int, installer_runtime['version'].split('.')), installer_runtime['release'])
        surface_names = {r['name'] for r in target_packages if r.get('surface_touch_only')}
        if bool(surface_touch_package) != bool(surface_names):
            raise Invalid('IPTS package and conditional Arch build cohort must be supplied together')
        if surface_names and any((Path(desktop)/path).exists() for path in (
            'usr/lib/enzimos-surface-touch',
            'usr/lib/systemd/system/enzimos-surface-touch.service',
            'usr/lib/udev/rules.d/70-enzimos-surface-touch.rules',
        )):
            raise Invalid('the DKMS media require a desktop stage without prebuilt IPTS')
        if surface_names and (installer_version < (0, 2, 2, 1)
                              or not {'dkms', 'linux-headers', 'linux-lts-headers'} <= surface_names):
            raise Invalid('IPTS requires installer 0.2.2 and a complete conditional Arch build cohort')
        flatpaks, enzimos_flatpaks = stage_flatpaks(
            media, flatpak, enzimos_flatpak, installer_version=installer_version)
        live = live_root(verified, cohort, desktop, out, version, package, native_installer['package'], runtime_admission/'rust-packages.pkg.tar.zst', installer=installer)
        limine = out/'live/root/usr/share/limine'
        for name in ('limine-bios-cd.bin', 'limine-uefi-cd.bin', 'limine-bios.sys'):shutil.copyfile(limine/name, stage/'boot/limine'/name)
        shutil.copyfile(limine/'BOOTX64.EFI', stage/'EFI/BOOT/BOOTX64.EFI')
        (stage/'boot/limine/limine.conf').write_text(live_menu((installer/'limine.conf').read_text(), dev_access.key() is not None))
        shutil.copyfile(live['vmlinuz'], stage/'boot/vmlinuz-linux')
        shutil.copyfile(live['initrd'], stage/'boot/enzimos-live.img')
        shutil.copyfile(live['rescue_initrd'], stage/'boot/enzimos-rescue.img')
        names = []
        for record in sorted(target_packages, key=lambda r: r['name']):
            name = record['url'].rsplit('/', 1)[-1];names.append(name)
            for suffix in ('', '.sig'):os.link(cohort/'packages'/(name+suffix), media/'packages'/(name+suffix))
        # NVIDIA's proprietary userspace + open kernel modules: installed only on NVIDIA hardware.
        nvidia = {'nvidia-open', 'nvidia-open-lts', 'nvidia-utils', 'lib32-nvidia-utils'}
        by_name = {r['name']: r['url'].rsplit('/', 1)[-1] for r in target_packages}
        (media/'package-files.txt').write_text(''.join(n+'\n' for n in names if n not in {by_name[x] for x in (nvidia & set(by_name)) | surface_names}))
        (media/'nvidia-files.txt').write_text(''.join(by_name[x]+'\n' for x in sorted(nvidia & set(by_name))))
        if surface_names:
            (media/'surface-files.txt').write_text(''.join(by_name[x]+'\n' for x in sorted(surface_names)))
        (media/'packages.txt').write_text(''.join(f"{r['name']} {r['version']}\n" for r in sorted(target_packages, key=lambda r: r['name'])))
        public_cache(out/'admission', Path(keyring).resolve(strict=True), cohort/'packages', verified['packages'])
        (media/'public-keys').mkdir()
        for name in ('pubring.gpg', 'trustdb.gpg'):shutil.copyfile(out/'admission/public'/name, media/'public-keys'/name)
        shutil.copyfile(out/'admission/approved.trust', media/'public-keys/approved.trust');(media/'public-keys/gpg.conf').write_text(GPG_CONFIG)
        (media/'pacman-install.conf').write_text('[options]\nArchitecture = x86_64\nCacheDir = /run/enzimos-media/enzimos/packages\nLogFile = /var/log/pacman-install.log\n'
                                                 'SigLevel = Required TrustedOnly DatabaseOptional\nLocalFileSigLevel = Required TrustedOnly\nCheckSpace\n')
        shutil.copyfile(package, media/'native-policy.pkg.tar.zst')
        owned = rust_owned_paths(runtime_repos)
        app_builds = dict(app_builds or {})
        if set(app_builds) - {'files', 'text', 'task-manager'}:raise Invalid('unknown native app build')
        if ('task-manager' in app_builds
                and 'io.github.enzui.TaskManager' in enzimos_flatpaks.get('enzimos_flatpaks', [])):
            raise Invalid('Task Manager is already selected as a Flatpak')
        # enzimos-mount depends on the Qt-free aft-mtp-mount package; admit both or neither.
        if bool(mount_build) != bool(aft_build):raise Invalid('mount and aft-mtp builds go together')
        for report_path in (terminal_build, store_build, permissions_build, harness_build, developer_build, remote_build, background_build, monitor_build, mcp_build, portal_build, greetd_build, keyring_build, phone_build, mount_build, aft_build, icon_theme_build, archive_keyring_build, *app_builds.values()):
            if report_path:
                listed = load(report_path).get('files') or {}
                owned.update(listed.keys() if isinstance(listed, dict) else listed)
        if xwayland and owned.intersection({XWAYLAND_BINARY, XWAYLAND_COPYING}):
            raise Invalid('native package would replace an admitted Xwayland companion file')
        desktop_files = desktop_archive(desktop, media, frozenset(owned)) if desktop else 0
        os.link(live['squashfs'], media/'live.sfs')
        backend = None
        if backend_build:
            backend = load(backend_build)
            runtime_binding=backend.get('rust_runtime')
            if runtime_binding is None or runtime_binding.get('sha256') != rust_summary['packages']['packages']['sha256']:
                raise Invalid('backend unit and target Rust runtime must use the same reviewed package')
            if backend.get('package_name') != 'enzimos-system-backend' or digest(Path(backend['package'])) != backend['sha256']:raise Invalid('reviewed backend build required')
            shutil.copyfile(backend['package'], media/'backend.pkg.tar.zst')
        updater = None
        if update_build:
            updater = load(update_build)
            if updater.get('package_name') != 'enzimos-update-client' or digest(Path(updater['package'])) != updater['sha256']:raise Invalid('reviewed update client build required')
            shutil.copyfile(updater['package'], media/'update-client.pkg.tar.zst')
        recovery_env = None
        if recovery_env_build:
            # The on-disk recovery environment (recovery_env.py), installed onto the ESP.
            built_env = load(recovery_env_build)
            env_package = Path(built_env.get('package', ''))
            if built_env.get('status') != 'PASS-recovery-env-built' or not env_package.is_file():raise Invalid('reviewed recovery environment build required')
            shutil.copyfile(env_package, media/'recovery-env.pkg.tar.zst')
            recovery_env = {'release': 1, 'sha256': digest(media/'recovery-env.pkg.tar.zst')}
        broker = None
        if mcp_build:
            broker = load(mcp_build)
            if broker.get('status') != 'PASS-mcp-center-package-built' or broker.get('package_name') != 'enzui-mcp-center' or digest(Path(broker['package'])) != broker['sha256']:
                raise Invalid('reviewed MCP center build required')
            shutil.copyfile(broker['package'], media/'mcp-center.pkg.tar.zst')
        activity = None
        if activity_build:
            from activity_payload import stage as stage_activity
            activity = stage_activity(activity_build, media)
        ai_runtime = None
        if ai_build:
            from ai_payload import stage as stage_ai
            ai_runtime = stage_ai(ai_build, media)
        native_apps = {}
        from native_apps_payload import stage as stage_native_app
        for component, build_report in (('terminal', terminal_build), ('store', store_build), ('app-permissions', permissions_build), ('agent-harness', harness_build), ('developer-tools', developer_build), ('remote-access', remote_build), ('background-apps', background_build), ('dev-monitor', monitor_build), ('xdg-desktop-portal-hyprland', portal_build), ('greetd', greetd_build), ('keyring', keyring_build), ('phone-link', phone_build), ('mount', mount_build), ('aft-mtp', aft_build), ('icon-theme', icon_theme_build), ('archive-keyring', archive_keyring_build), *sorted(app_builds.items())):
            if build_report:
                native_apps[component] = stage_native_app(build_report, media, component)
        secure_media = None
        if bool(secure_key) != bool(secure_certificate):raise Invalid('both owner signing inputs required')
        if secure_key:
            from signed_install_media import prepare
            secure_media=prepare(out/'live/root',stage,out,live['vmlinuz'],live['initrd'],live['rescue_initrd'],secure_key,secure_certificate)
        for component in native_rust:
            destination=media/('rust-'+component+'.pkg.tar.zst')
            shutil.copyfile(runtime_admission/destination.name, destination)
            if digest(destination) != native_rust[component]['sha256']:raise Invalid('admitted Rust target archive changed during image assembly')
        manifest = {'native_rust':native_rust, 'native_apps':native_apps, 'activity_service':activity, 'ai_runtime':ai_runtime, 'secure_media':secure_media, 'schema': 1, 'label': label, 'development_artifact': True, 'release_authorized': False, 'native_policy': {'release': pbuild['release'], 'sha256': pbuild['sha256']},
                    'cohort_plan_sha256': digest(cohort/'resolution/resolution.json'), 'package_count': len(names), 'nvidia_conditional': sorted(nvidia & set(by_name)), 'trust_lock_sha256': digest(trust_lock),
                    'review_before': lock['review_before'], 'kernel': live['kernel'], 'live': {'packages': live['packages'], 'excluded': live['excluded'], 'graphical_installer': True, 'native_installer': native_installer}, 'installer_sha256': digest(out/'live/root/usr/lib/enzimos-installer/enzimos-install.sh'), 'desktop_preview_files': desktop_files, 'flatpaks': flatpaks, **enzimos_flatpaks, 'update_client': None if updater is None else {'release':updater['release'],'sha256':updater['sha256']}, **({} if recovery_env is None else {'recovery_env': recovery_env}), 'mcp_center': None if broker is None else {'release':broker['release'],'sha256':broker['sha256']}, 'backend': None if backend is None else {'release': backend['release'], 'sha256': backend['sha256']}}
        if xwayland:
            manifest['desktop_xwayland'] = xwayland
        if surface_touch_package:
            source = Path(surface_touch_package)
            if source.is_symlink() or not 0 < source.stat().st_size <= 2 * 1024**2:
                raise Invalid('bounded IPTS DKMS package required')
            pkginfo = subprocess.check_output(['bsdtar', '-qxOf', source, '.PKGINFO'], text=True).splitlines()
            versions = [row.removeprefix('pkgver = ') for row in pkginfo if row.startswith('pkgver = ')]
            if ('pkgname = enzimos-ipts-dkms' not in pkginfo or 'arch = any' not in pkginfo
                    or 'depend = dkms' not in pkginfo or len(versions) != 1):
                raise Invalid('unexpected IPTS DKMS package identity')
            destination = media/'ipts-dkms.pkg.tar.zst'
            shutil.copyfile(source, destination)
            manifest['surface_touch'] = {'version': versions[0], 'sha256': digest(destination),
                                         'arch_packages': sorted(surface_names)}
        if installer_version >= (0, 2, 2, 1):
            from storage_payload import measure
            manifest['storage_payload'] = measure(media)
        (media/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        write_media_checksums(media)
        run_command(xorriso(stage, out), out, 'xorriso', 900)
        iso = out/'enzimos.iso'
        # Hybrid USB boot on BIOS: Limine's stage 1 into the ISO's protective MBR.
        args = builder_argv(out/'live/root', out, ['/usr/bin/limine', 'bios-install', '/tmp/artifacts/enzimos.iso'])
        args[args.index('--bind')] = '--ro-bind'
        run_command(args, out, 'limine-bios-install', 60)
        if not 0 < iso.stat().st_size <= MAX_ISO:raise Invalid('ISO size bound')
        final = out/f'enzimos-{label}-x86_64.iso';iso.rename(final)
        report.update(status='PASS-install-iso-built', iso=str(final), iso_bytes=final.stat().st_size, iso_sha256=digest(final), manifest=manifest,
                      live_initrd_sha256=digest(live['initrd']), live_squashfs_sha256=digest(live['squashfs']), host_resource_policy=resources, checked_at=datetime.now(timezone.utc).isoformat())
        (out/(final.name+'.sha256')).write_text(f"{report['iso_sha256']}  {final.name}\n")
        return report
    except BaseException as exc:
        report['failure'] = str(exc);raise
    finally:(out/'build.json').write_text(json.dumps(report, indent=2)+'\n')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cohort', 'policy-build', 'keyring', 'trust-lock', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--assembly', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--label', default='dev')
    for name in (
        'desktop', 'backend-build', 'flatpak', 'update-build', 'mcp-build', 'ai-build',
        'activity-build', 'secure-key', 'secure-certificate', 'store-build', 'permissions-build',
        'harness-build', 'developer-build', 'remote-build', 'background-build', 'terminal-build',
        'monitor-build', 'portal-build', 'greetd-build', 'keyring-build', 'phone-build',
        'mount-build', 'aft-build', 'icon-theme-build', 'archive-keyring-build', 'recovery-env-build',
    ):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--enzimos-flatpak', type=Path,
                        help='enzimOS Flatpak sideload directory; requires --flatpak')
    parser.add_argument('--installer-build', type=Path, required=True,
                        help='reviewed Rust runtime package summary')
    parser.add_argument('--runtime-repos', type=Path, default=RUNTIME_REPOS,
                        help='directory containing the five Rust runtime component checkouts')
    parser.add_argument('--app-build', action='append', default=[], metavar='COMPONENT=REPORT')
    options = vars(parser.parse_args(argv))
    reports = {}
    for item in options.pop('app_build'):
        component, _, report = item.partition('=')
        if component not in {'files', 'text', 'task-manager'} or not report or component in reports:
            parser.error('--app-build requires a unique files, text or task-manager COMPONENT=REPORT')
        reports[component] = Path(report)
    try:
        print(json.dumps(build(**options, app_builds=reports), indent=2))
        return 0
    except (Invalid, OSError, ValueError, KeyError) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
