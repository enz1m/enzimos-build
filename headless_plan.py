# SPDX-License-Identifier: MIT
"""Resolve an empty experimental target using existing pacman; never download/install packages."""
import json
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import urlsplit
from contract import Invalid, digest, load, object_fields, same

REQUIRED = {'base', 'linux', 'linux-lts', 'mkinitcpio', 'btrfs-progs', 'cryptsetup', 'limine',
            'dosfstools', 'nano', 'dbus-broker-units'}
FOUNDATION = REQUIRED | {'kernel-modules-hook', 'snapper', 'snap-pac', 'restic',
                         'networkmanager', 'wpa_supplicant', 'firewalld', 'nftables',
                         'chrony', 'sudo', 'polkit', 'apparmor', 'dnsmasq', 'tcpdump', 'python'}


# Consumer hardware support uses distribution packages, not a custom detector.
HARDWARE = {'linux-firmware', 'linux-firmware-marvell', 'sof-firmware', 'alsa-firmware', 'intel-ucode', 'amd-ucode',
            'wireless-regdb', 'b43-fwcutter', 'iw',
            'mesa', 'vulkan-intel', 'vulkan-radeon', 'vulkan-nouveau', 'intel-media-driver',
            'nvidia-open', 'nvidia-open-lts', 'nvidia-utils',
            'pipewire', 'wireplumber', 'pipewire-pulse', 'pipewire-alsa', 'alsa-utils', 'alsa-ucm-conf', 'rtkit',
            'bluez', 'bluez-utils', 'ntfs-3g', 'ntfsprogs', 'exfatprogs', 'upower', 'power-profiles-daemon', 'usbutils',
            'fwupd',
            # Thunderbolt/USB4 device authorization (started by udev when a
            # Thunderbolt domain exists) and fingerprint readers (D-Bus activated).
            'bolt', 'fprintd'}


# Desktop runtime, session, font and software-rendering packages.
# Flatpak input resolution remains separate from native application packaging.
FLATPAK = {'flatpak'}
GAMING_COMPATIBILITY = {'steam-devices'}
# Optional applications/tools are resolved separately and never added to the ISO.
GAMING_OPTIONAL = {'steam', 'gamescope', 'linuxconsole'}
RDP_BUILD_OPTIONAL = {
    'base-devel', 'cmake', 'extra-cmake-modules', 'freerdp', 'oo7', 'kconfig', 'kcoreaddons', 'kcrash', 'kdbusaddons', 'kguiaddons', 'ki18n', 'kpipewire', 'kstatusnotifieritem', 'libei', 'libxkbcommon', 'ninja', 'pam', 'pkgconf', 'qt6-base', 'qt6-wayland', 'qtkeychain-qt6', 'systemd-libs', 'wayland'
}

RDP_RUNTIME_OPTIONAL = {'oo7', 'kcrash', 'ki18n', 'mesa', 'ffmpeg', 'libstdc++', 'pam', 'libxkbcommon', 'glibc', 'wayland', 'libva', 'kconfig', 'qtkeychain-qt6', 'kguiaddons', 'qt6-declarative', 'libdrm', 'libglvnd', 'kdbusaddons', 'libei', 'kstatusnotifieritem', 'freerdp', 'libpipewire', 'qt6-base', 'kcoreaddons', 'qt6-wayland', 'libepoxy'}

GAMING = GAMING_COMPATIBILITY | {'zram-generator', 'gamemode', 'lib32-gamemode', 'lib32-mesa',
          'lib32-vulkan-intel', 'lib32-vulkan-radeon', 'lib32-vulkan-nouveau',
          'lib32-libglvnd', 'lib32-pipewire', 'lib32-alsa-plugins',
          'lib32-libva', 'lib32-libpulse', 'lib32-nvidia-utils',
          'vulkan-tools', 'mesa-utils', 'ttf-liberation'}
DELIVERY = {'systemd-ukify', 'sbsigntools', 'efitools', 'sbctl',
            'python-cryptography', 'python-urllib3'}
DESKTOP_PREVIEW = {'abseil-cpp', 'adwaita-cursors', 'aom', 'audit', 'brotli', 'bzip2', 'cairo', 'curl', 'dav1d', 'e2fsprogs', 'expat', 'file', 'fontconfig', 'freetype2', 'fribidi', 'gdk-pixbuf2', 'glib2', 'glibc', 'glslang', 'glycin', 'graphite', 'greetd', 'gst-plugins-base-libs', 'gstreamer', 'harfbuzz', 'highway', 'icu', 'keyutils', 'krb5', 'lcms2', 'libcanberra', 'libcap-ng', 'libdatrie', 'libde265', 'libdisplay-info', 'libdrm', 'libei', 'libelf', 'libevdev', 'libffi', 'libgcc', 'libglvnd', 'libgomp', 'libgudev', 'libheif', 'libidn2', 'libinput', 'libjpeg-turbo', 'libjxl', 'libnghttp2', 'libnghttp3', 'libngtcp2', 'libogg', 'libpng', 'libpsl', 'librsvg', 'libseccomp', 'libssh2', 'libstdc++', 'libthai', 'libtool', 'libunistring', 'libunwind', 'libvorbis', 'libwacom', 'libwebp', 'libx11', 'libxau', 'libxcb', 'libxcursor', 'libxdmcp', 'libxext', 'libxfixes', 'libxkbcommon', 'libxml2', 'libxrender', 'libzip', 'lua', 'lua54', 'mesa', 'mtdev', 'muparser', 'ncurses', 'noto-fonts', 'noto-fonts-emoji', 'openh264', 'openssl', 'orc', 'pam', 'pango', 'pcre2', 'pixman', 're2', 'readline', 'seatd', 'spirv-tools', 'swaylock', 'systemd-libs', 'tdb', 'tomlplusplus', 'ttf-dejavu', 'util-linux-libs', 'vulkan-swrast', 'wayland', 'wl-clipboard', 'x264', 'x265', 'xcb-util-errors', 'xcb-util-wm', 'xdg-desktop-portal', 'xdg-user-dirs', 'xkeyboard-config', 'xorg-xwayland', 'xz', 'zlib', 'zstd'}


# Everyday devices use existing desktop services and never run sharing servers.
# WireGuard is native to NetworkManager. Drives, phones and network shares go
# through enzimos-mount  whose narrow root service makes the kernel SMB
# and NFS mounts; these are the helpers it drives (GVfs's SMB/MTP backends are
# not installed: they would compete for the same phones and shares). GVfs is
# not installed at all: any GIO program touching files would start gvfsd and
# its FUSE bridge for the rest of the session; local trash works without it.
EVERYDAY_DEVICES = {'cups', 'cups-filters', 'ghostscript', 'cups-pk-helper', 'ipp-usb', 'avahi',
                    'openssh', 'fuse3', 'sshfs', 'smbclient', 'nfs-utils', 'rclone', 'libmtp',
                    'ifuse', 'libimobiledevice', 'usbmuxd',
                    'networkmanager-openvpn', 'networkmanager-openconnect',
                    # More VPN types, plugin parts only (Settings provides the forms):
                    # Cisco IPsec, L2TP/IPsec, IKEv2 and legacy PPTP.
                    'networkmanager-vpn-plugin-vpnc', 'networkmanager-vpn-plugin-l2tp',
                    'networkmanager-vpn-plugin-pptp', 'networkmanager-strongswan', 'strongswan',
                    # Drivers for printers without driverless (IPP Everywhere) support:
                    # older Epson, Canon, HP, Brother and Lexmark models.
                    'gutenprint'}

# Reviewed desktop integration providers; no additional foreign GUI application.
DESKTOP_INTEGRATION = { 'libsecret', 'libmalcontent', 'fcitx5', 'fcitx5-gtk',
                       'fcitx5-qt', 'fcitx5-chinese-addons', 'fcitx5-mozc', 'noto-fonts-cjk',
                       'udisks2', 'gst-plugins-base', 'gst-plugins-good',
                       'gst-plugins-ugly', 'gst-plugin-pipewire', 'gst-libav', 'colord', 'wf-recorder', 'wayvnc', 'grim', 'slurp', 'libpulse',
                       'orca', 'speech-dispatcher', 'espeak-ng', 'at-spi2-core', 'unicode-emoji',
                       # Location on request only, off until the user turns it on.
                       'geoclue',
                       # The native enzimos-icon-theme ('enzim', the default) inherits Adwaita and
                       # hicolor; its GSettings override sets an org.gnome.desktop.interface key.
                       'adwaita-icon-theme', 'hicolor-icon-theme', 'gsettings-desktop-schemas'} | EVERYDAY_DEVICES | GAMING_COMPATIBILITY


# Everyday command line: commands that help pages, support answers and
# scripts assume on any desktop Linux. Developer toolchains stay in DEVELOPER_PROFILES.
CLI_ESSENTIALS = {'less', 'man-db', 'man-pages', 'bash-completion', 'unzip', 'zip', '7zip',
                  'htop', 'lsof', 'tree', 'wget', 'inetutils',
                  # The Files app's torrent and segmented downloads.
                  'aria2'}

# Installed account management and bounded login-picture imports.
LOGIN_PERSONALIZATION = {'accountsservice', 'python-pillow', 'polkit', 'bubblewrap',
                         'util-linux', 'libxcrypt'}


DEVELOPER_PROFILES = {
    'build': {'git', 'base-devel', 'cmake', 'ninja', 'meson', 'pkgconf'},
    'runtimes': {'mise'},
    'containers': {'podman', 'buildah', 'skopeo', 'passt', 'fuse-overlayfs'},
    'virtualization': {'qemu-base', 'libvirt', 'edk2-ovmf', 'swtpm', 'passt'},
}
DEVELOPER_OPTIONAL = set().union(*DEVELOPER_PROFILES.values())


def seed_purposes():
    """The reviewed package set for each seed purpose."""
    purposes = {'install-media-desktop-parity-not-release-payload': FOUNDATION | HARDWARE | DESKTOP_PREVIEW | FLATPAK | GAMING | DELIVERY | DESKTOP_INTEGRATION | {'plymouth','refind','efibootmgr','ntfsprogs','xdg-desktop-portal-hyprland','xdg-desktop-portal-gtk'},
                'install-media-desktop-zen-not-release-payload': FOUNDATION | HARDWARE | DESKTOP_PREVIEW | FLATPAK | GAMING | DELIVERY | {'plymouth','refind','efibootmgr','ntfsprogs','xdg-desktop-portal-hyprland','xdg-desktop-portal-gtk'},
                'install-media-boot-recovery-preview-not-release-payload': FOUNDATION | HARDWARE | DESKTOP_PREVIEW | FLATPAK | {'plymouth','refind','efibootmgr','ntfsprogs'},
                'install-media-delivery-rescue-gaming-not-release-payload': FOUNDATION | HARDWARE | DESKTOP_PREVIEW | FLATPAK | GAMING | DELIVERY | {'plymouth','refind','efibootmgr','ntfsprogs'},
                'v2-headless-experiment-not-product-payload': REQUIRED,
                'headless-foundation-qualification-not-product-payload': FOUNDATION,
                'headless-app-backup-qualification-not-product-payload': FOUNDATION | {'flatpak'},
                'clean-build-closure-not-product-payload': {'base', 'base-devel', 'devtools', 'python', 'dbus-broker-units'},
                'developer-setup-fixtures-not-product-payload': DEVELOPER_OPTIONAL,
                'remote-hosting-fixtures-not-product-payload': {'wayvnc'},
                'memory-pressure-fixtures-not-product-payload': {'earlyoom'},
                'rdp-server-build-fixtures-not-product-payload': RDP_BUILD_OPTIONAL,
                'rdp-server-runtime-fixtures-not-product-payload': RDP_RUNTIME_OPTIONAL,
                'everyday-protocol-fixtures-not-product-payload': {'samba', 'wireguard-tools'},
                'gaming-compatibility-fixtures-not-product-payload': GAMING_OPTIONAL | {'gst-plugins-bad','vulkan-swrast','lib32-vulkan-intel','lib32-gamemode'},
                'install-media-hardware-not-release-payload': FOUNDATION | HARDWARE,
                'install-media-desktop-preview-not-release-payload': FOUNDATION | HARDWARE | DESKTOP_PREVIEW | FLATPAK}
    purposes['install-media-desktop-memory-not-release-payload'] = purposes['install-media-desktop-parity-not-release-payload'] | {'earlyoom'} | CLI_ESSENTIALS
    purposes['install-media-desktop-login-not-release-payload'] = purposes['install-media-desktop-memory-not-release-payload'] | LOGIN_PERSONALIZATION
    purposes.update({f'developer-profile-{name}-fixtures-not-product-payload': packages
                     for name, packages in DEVELOPER_PROFILES.items()})
    return purposes


def read_seed(path):
    seed = load(path)
    object_fields(seed, 'schema_version purpose architecture repository_snapshot requested_packages databases limitations', 'headless seed')
    same(seed['schema_version'], 1, 'seed version')
    purposes = seed_purposes()
    if type(seed['purpose']) is not str or seed['purpose'] not in purposes:
        raise Invalid('unknown reviewed seed purpose')
    required = purposes[seed['purpose']]
    same(seed['architecture'], 'x86_64', 'seed architecture')
    if type(seed['repository_snapshot']) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', seed['repository_snapshot']):
        raise Invalid('invalid dated repository snapshot')
    packages = seed['requested_packages']
    if type(packages) is not list or any(type(p) is not str for p in packages) or len(packages) != len(required) or set(packages) != required:
        raise Invalid('headless seed does not match the reviewed minimal experiment')
    repositories = ('core', 'extra', 'multilib') if seed['purpose'] in ('install-media-delivery-rescue-gaming-not-release-payload', 'install-media-desktop-zen-not-release-payload', 'install-media-desktop-parity-not-release-payload', 'install-media-desktop-memory-not-release-payload', 'install-media-desktop-login-not-release-payload', 'gaming-compatibility-fixtures-not-product-payload') else ('core', 'extra')
    if type(seed['databases']) is not list or len(seed['databases']) != len(repositories):
        raise Invalid('exact reviewed repository databases required')
    for index, name in enumerate(repositories):
        item = seed['databases'][index]
        object_fields(item, 'repository file bytes sha256 server', 'database')
        same(item['repository'], name, 'database identity')
        same(item['file'], name + '.db', 'database file')
        server = f"https://archive.archlinux.org/repos/{seed['repository_snapshot'].replace('-', '/')}/{name}/os/x86_64"
        same(item['server'], server, 'database source')
        if type(item['bytes']) is not int or not 0 < item['bytes'] <= 32 * 1024**2:
            raise Invalid('database size out of bounds')
        if type(item['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', item['sha256']):
            raise Invalid('invalid database SHA-256')
    if type(seed['limitations']) is not list or not seed['limitations'] or any(type(v) is not str for v in seed['limitations']):
        raise Invalid('seed must record its limitations')
    return seed


def parse_resolution(text, seed):
    records = []
    seen = set()
    servers = {entry['repository']: entry['server'] for entry in seed['databases']}
    for line in text.splitlines():
        fields = line.split('\t')
        if len(fields) != 7:
            raise Invalid('unexpected pacman print output')
        name, version, arch, repo, url, size, checksum = fields
        if not re.fullmatch('[a-z0-9][a-z0-9@+_.-]*', name) or name in seen:
            raise Invalid('invalid/duplicate package name')
        if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9.+_:~-]*', version) or arch not in ('x86_64', 'any') or repo not in servers:
            raise Invalid('invalid package version/architecture/repository')
        parsed = urlsplit(url)
        prefix = servers[repo] + '/'
        if not url.startswith(prefix) or parsed.query or parsed.fragment or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+:-]*\.pkg\.tar\.(zst|xz)', url[len(prefix):]):
            raise Invalid('package URL is outside the exact snapshot')
        if not size.isdigit() or not 0 < int(size) <= 1024**3 or not re.fullmatch('[0-9a-f]{64}', checksum):
            raise Invalid('invalid package size/hash metadata')
        records.append({'name': name, 'version': version, 'architecture': arch, 'repository': repo,
                        'url': url, 'download_bytes_from_metadata': int(size), 'sha256_from_metadata': checksum})
        seen.add(name)
        if len(records) > 1024:
            raise Invalid('package-count budget exceeded')
    if not set(seed['requested_packages']).issubset(seen) or seen & {'grub', 'dracut', 'dbus-daemon-units'}:
        raise Invalid('required packages missing or incompatible provider selected')
    return {'status': 'RESOLVED-NOT-AUTHENTICATED-PAYLOAD', 'packages': records,
            'package_count': len(records), 'download_bytes_from_metadata': sum(r['download_bytes_from_metadata'] for r in records),
            'repository_snapshot': seed['repository_snapshot'], 'installed_target_state': 'empty',
            'repository_signatures_verified': False, 'package_signatures_verified': False,
            'package_bytes_downloaded': False, 'offline_product_payload_complete': False, 'release_authorized': False}


def resolver_argv(root, output, seed):
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', str(root), '/', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--tmpfs', '/run', '--tmpfs', '/root', '--tmpfs', '/home', '--dir', '/tmp/target',
            '--bind', str(output), '/tmp/plan', '--chdir', '/', '--setenv', 'HOME', '/tmp',
            '--setenv', 'PATH', '/usr/bin', '--setenv', 'LANG', 'C.UTF-8', '--', '/usr/bin/pacman',
            '--config', '/tmp/plan/pacman.conf', '--sync', '--print', '--noconfirm',
            '--print-format', '%n\t%v\t%a\t%r\t%l\t%s\t%h', *seed['requested_packages']]


def check_empty_target(output):
    output = Path(output)
    entries = list((output / 'db/local').iterdir())
    for entry in entries:
        if (entry.name != 'ALPM_DB_VERSION' or entry.is_symlink() or not entry.is_file()
                or entry.stat().st_size > 4 or not re.fullmatch(r'[1-9][0-9]{0,2}\n', entry.read_text())):
            raise Invalid('print-only resolution populated unexpected installed state')
    if list((output / 'cache').iterdir()):
        raise Invalid('print-only resolution populated the package cache')


def resolve(root, seed_path, databases, output):
    """Called only after preparation freshly verifies/extracts the toolroot."""
    seed = read_seed(seed_path)
    output = Path(output)
    output.mkdir(mode=0o700, exist_ok=False)
    for directory in ('db/local', 'db/sync', 'cache', 'gpg'):
        (output / directory).mkdir(parents=True, exist_ok=True)
    for item in seed['databases']:
        path = Path(databases) / item['file']
        if path.is_symlink() or not path.is_file() or path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
            raise Invalid('repository input does not match the reviewed snapshot')
        destination = output / 'db/sync' / item['file']
        shutil.copyfile(path, destination)
        if digest(destination) != item['sha256']:
            raise Invalid('database changed while copying')
    config = '[options]\nArchitecture = x86_64\nRootDir = /tmp/target\nDBPath = /tmp/plan/db\nCacheDir = /tmp/plan/cache\nGPGDir = /tmp/plan/gpg\nLogFile = /tmp/plan/pacman.log\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = Required\n'
    for item in seed['databases']:
        config += f"[{item['repository']}]\nServer = {item['server']}\n"
    (output / 'pacman.conf').write_text(config)
    argv = resolver_argv(root, output.resolve(), seed)
    (output / 'command.json').write_text(json.dumps(argv, indent=2) + '\n')
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=30,
                            env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
    if len(result.stdout) + len(result.stderr) > 2 * 1024**2:
        raise Invalid('resolver output exceeds bound')
    (output / 'stdout').write_bytes(result.stdout)
    (output / 'stderr').write_bytes(result.stderr)
    if result.returncode != 0:
        raise Invalid('readonly package resolution failed')
    report = parse_resolution(result.stdout.decode('utf-8'), seed)
    check_empty_target(output)
    report['seed_sha256'] = digest(Path(seed_path))
    report['databases'] = seed['databases']
    (output / 'resolution.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
