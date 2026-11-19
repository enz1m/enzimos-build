# SPDX-License-Identifier: MIT
"""Strict native application/service admission for development install media."""
import hashlib
import json
import posixpath
import re
from pathlib import Path
import shutil
import tarfile

COMPONENTS = {
    'phone-link': ('enzimos-phone-link', 'PASS-phone-link-package-built', 'usr/libexec/enzimos-phone-link/enzremote-signaling'),
    'mount': ('enzimos-mount', 'PASS-mount-package-built', 'usr/lib/enzimos-mount/enzimos-mountd'),
    'aft-mtp': ('enzimos-aft-mtp', 'PASS-aft-mtp-package-built', 'usr/bin/aft-mtp-mount'),
    'keyring': ('enzimos-keyring', 'PASS-keyring-package-built', 'usr/bin/oo7-daemon'),
    'greetd': ('enzimos-greetd', 'PASS-greetd-package-built', 'usr/bin/greetd'),
    'dev-monitor': ('enzimos-dev-monitor', 'PASS-dev-monitor-package-built', 'usr/lib/enzimos/enzimos-dev-monitor'),
    'terminal': ('enzimos-terminal', 'PASS-terminal-package-built', 'usr/lib/enzui/apps/terminal-emulator'),
    'background-apps': ('enzimos-background-apps', 'PASS-background-apps-package-built', 'usr/bin/enzimos-background'),
    'store': ('enzimos-store', 'PASS-store-package-built', 'usr/bin/store-app'),
    'files': ('enzimos-files', 'PASS-files-package-built', 'usr/lib/enzui/apps/files-app'),
    'text': ('enzimos-text', 'PASS-text-package-built', 'usr/lib/enzui/apps/text-app'),
    'task-manager': ('enzimos-task-manager', 'PASS-task-manager-package-built', 'usr/lib/enzui/apps/task-manager-app'),
    'app-permissions': ('enzimos-app-permissions', 'PASS-app-permissions-package-built', 'usr/bin/enzimos-app-permissions'),
    'remote-access': ('enzimos-remote-access', 'PASS-remote-access-package-built', 'usr/bin/enzimos-remote'),
    'developer-tools': ('enzimos-developer-tools', 'PASS-developer-tools-package-built', 'usr/bin/enzimos-developer'),
    'agent-harness': ('enzimos-agent-harness', 'PASS-agent-harness-package-built', 'usr/bin/enzimos-agent-harness'),
    'xdg-desktop-portal-hyprland': ('enzimos-xdg-desktop-portal-hyprland', 'PASS-portal-package-built', 'usr/lib/xdg-desktop-portal-hyprland'),
    'icon-theme': ('enzimos-icon-theme', 'PASS-icon-theme-package-built', 'usr/share/icons/enzim/index.theme'),
}
# The icon theme is data only: its identifying file is the theme index, nothing in it is
# executable, and it installs only the theme tree and its default-theme GSettings override.
ICON_THEME = 'usr/share/icons/enzim'
ICON_THEME_FILES = {ICON_THEME + '/index.theme': 0o644,
                    'usr/share/glib-2.0/schemas/20_enzim-icon-theme.gschema.override': 0o644}
# Components that take an Arch package's place: the media leave that Arch package out
# of the target cohort, and the archive must declare the replacement relationship.
REPLACES = {'keyring': 'gnome-keyring', 'xdg-desktop-portal-hyprland': 'xdg-desktop-portal-hyprland', 'greetd': 'greetd'}
GREETD_FILES = {'usr/bin/agreety': 0o755, 'etc/greetd/config.toml': 0o644, 'etc/pam.d/greetd': 0o644,
                'usr/lib/systemd/system/greetd.service': 0o644, 'usr/lib/sysusers.d/greetd.conf': 0o644}
KEYRING_FILES = {'usr/lib/security/pam_oo7.so': 0o755,
                 'usr/lib/oo7-daemon-login': 0o755,
                 'usr/lib/oo7-portal': 0o755,
                 'usr/lib/enzimos-keyring/enzimos-keyring-setup': 0o755,
                 'usr/share/dbus-1/services/org.freedesktop.secrets.service': 0o644,
                 'usr/lib/systemd/user/oo7-daemon.service': 0o644,
                 'usr/lib/systemd/user/oo7-portal.service': 0o644,
                 'usr/share/xdg-desktop-portal/portals/oo7-portal.portal': 0o644,
                 'usr/share/libalpm/hooks/95-enzimos-keyring.hook': 0o644}
PORTAL_FILES = {'usr/bin/hyprland-share-picker': 0o755,
                'usr/lib/systemd/user/xdg-desktop-portal-hyprland.service': 0o644,
                'usr/share/dbus-1/services/org.freedesktop.impl.portal.desktop.hyprland.service': 0o644,
                'usr/share/xdg-desktop-portal/portals/hyprland.portal': 0o644}


def replacement_names(report):
    """Arch package names covered by an admitted native replacement format."""
    declared = report.get('replaces') or []
    names = {declared} if isinstance(declared, str) else set(declared)
    if report.get('status') == 'PASS-greetd-package-built':
        if names != {'greetd'}:
            raise ValueError('combined greetd replacement declaration differs')
        names.add('greetd-agreety')
    return names


def enabling_link(path, target, expected):
    """A unit the package enables, the only symlink a package may carry: a
    relative link to one of the package's own units, either a timer in
    timers.target.wants, a user service started with the enzUI session, or a
    system service in multi-user.target.wants."""
    parts = Path(path).parts
    if len(parts) != 6 or target != '../' + parts[5]:
        return False
    if expected.get('/'.join(parts[:4]) + '/' + parts[5], {}).get('mode') != 0o644:
        return False
    if parts[:4] in (('usr', 'lib', 'systemd', 'system'), ('usr', 'lib', 'systemd', 'user')) and parts[4] == 'timers.target.wants':
        return parts[5].endswith('.timer')
    return parts[5].endswith('.service') and (
        (parts[:4] == ('usr', 'lib', 'systemd', 'user') and parts[4] == 'enzui-session.target.wants')
        or (parts[:4] == ('usr', 'lib', 'systemd', 'system') and parts[4] == 'multi-user.target.wants'))


def theme_link(path, target, expected):
    """An icon theme alias: a relative link from one theme icon to another inside the
    same theme (e.g. utilities-terminal.svg -> io.github.enzui.Terminal.svg), naming a
    drawing the package carries."""
    if posixpath.isabs(target) or not path.startswith(ICON_THEME + '/'):
        return False
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    return resolved.startswith(ICON_THEME + '/') and resolved.endswith('.svg') and 'sha256' in expected.get(resolved, {})


def allowed_path(component, path, directory=False):
    if component == 'icon-theme':
        if directory:
            return path in ('usr', 'usr/share', 'usr/share/icons', 'usr/share/glib-2.0', 'usr/share/glib-2.0/schemas',
                            'usr/share/licenses', 'usr/share/licenses/enzimos-icon-theme', ICON_THEME) or path.startswith(ICON_THEME + '/')
        return (path.startswith(ICON_THEME + '/') or path in ICON_THEME_FILES
                or path.startswith('usr/share/licenses/enzimos-icon-theme/'))
    if path == 'usr' and directory or path.startswith('usr/'):
        return True
    if component == 'greetd':
        return path in ('etc', 'etc/greetd', 'etc/pam.d') if directory else path in ('etc/greetd/config.toml', 'etc/pam.d/greetd')
    if component == 'developer-tools':
        return path in ('etc', 'etc/mise') if directory else path == 'etc/mise/config.toml'
    return False


def stage(report_path, media, component):
    if component not in COMPONENTS: raise ValueError('unknown native component')
    name, status, executable = COMPONENTS[component]
    report = json.loads(Path(report_path).read_text())
    if report.get('package_name') != name or report.get('status') != status or report.get('release_authorized') is not False:
        raise ValueError('reviewed development native package required')
    release = report.get('release')
    if type(release) is not int or not 1 <= release <= 9999: raise ValueError('invalid native package release')
    version = report.get('version', '0.1.0')
    if type(version) is not str or not 1 <= len(version) <= 64 or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+]*', version) is None:
        raise ValueError('invalid native package version')
    package = Path(report['package']).resolve(strict=True)
    if not package.is_file() or not 0 < package.stat().st_size <= 128 * 1024**2:
        raise ValueError('bounded native package required')
    with package.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != report['sha256']:
            raise ValueError('native package digest mismatch')
    expected = report['files']
    if executable not in expected or expected[executable]['mode'] != (0o644 if component == 'icon-theme' else 0o755):
        raise ValueError('native executable inventory required')
    if component == 'icon-theme' and (any(expected.get(path, {}).get('mode') != mode for path, mode in ICON_THEME_FILES.items())
                                      or any(item.get('mode', 0o644) != 0o644 for item in expected.values())):
        raise ValueError('icon theme index/override inventory required; nothing executable')
    if component == 'dev-monitor':
        required = {'usr/bin/devmon': 0o755,
                    'usr/lib/systemd/user/enzimos-dev-monitor.service': 0o644,
                    'usr/share/dbus-1/services/org.enzimos.DevMonitor1.service': 0o644}
        if report.get('api_version') != 2 or any(expected.get(path, {}).get('mode') != mode for path, mode in required.items()):
            raise ValueError('monitor API/CLI/activation inventory required')
    replaced = REPLACES.get(component)
    if report.get('replaces') != replaced:
        raise ValueError('native replacement declaration differs')
    if component == 'xdg-desktop-portal-hyprland' and any(expected.get(path, {}).get('mode') != mode for path, mode in PORTAL_FILES.items()):
        raise ValueError('portal unit/activation/picker inventory required')
    if component == 'keyring' and any(expected.get(path, {}).get('mode') != mode for path, mode in KEYRING_FILES.items()):
        raise ValueError('keyring login/portal/activation inventory required')
    if component == 'greetd' and any(expected.get(path, {}).get('mode') != mode for path, mode in GREETD_FILES.items()):
        raise ValueError('greetd PAM/config/service/sysusers inventory required')
    for path, item in expected.items():
        rel = Path(path)
        if 'link' in item:
            valid = (theme_link(path, item['link'], expected) if component == 'icon-theme'
                     else enabling_link(path, item['link'], expected))
            if set(item) != {'link'} or not valid:
                raise ValueError('invalid native package link')
            continue
        if rel.is_absolute() or '..' in rel.parts or not allowed_path(component, path) or item['mode'] not in (0o644, 0o755):
            raise ValueError('invalid native inventory path/mode')
        if path.startswith('etc/') and item['mode'] != 0o644:
            raise ValueError('native configuration must not be executable')
    descriptor = report.get('developer_descriptor')
    manifest_path = 'usr/share/enzimos/developer/extension/manifest.json'
    if descriptor is not None:
        if (component != 'developer-tools' or descriptor.get('package_payloads_shipped') is not False or
                manifest_path not in expected or expected[manifest_path]['sha256'] != descriptor.get('sha256') or
                expected[manifest_path]['mode'] != 0o644 or
                type(descriptor.get('bytes')) is not int or not 0 < descriptor['bytes'] <= 1024**2 or
                any(path.startswith('usr/share/enzimos/developer/extension/packages/') for path in expected)):
            raise ValueError('invalid thin developer descriptor inventory')
    total = 0; seen = set(); info = None
    with tarfile.open(package, 'r|zst') as archive:
        for member in archive:
            path = Path(member.name); total += member.size
            if path.is_absolute() or '..' in path.parts or member.uid or member.gid or total > 256*1024**2 or member.size > 128*1024**2:
                raise ValueError('invalid native package member')
            if member.name in seen: raise ValueError('duplicate native package member')
            seen.add(member.name)
            if member.issym():
                if expected.get(member.name) != {'link': member.linkname}:
                    raise ValueError('native package link mismatch')
                continue
            if not (member.isfile() or member.isdir()):
                raise ValueError('invalid native package member')
            if member.isdir():
                if not allowed_path(component, member.name.rstrip('/'), directory=True) or member.mode != 0o755:
                    raise ValueError('invalid native package directory')
                continue
            data = archive.extractfile(member).read()
            if descriptor is not None and member.name == manifest_path and len(data) != descriptor['bytes']:
                raise ValueError('developer descriptor size mismatch')
            if member.name == '.PKGINFO': info = data.decode()
            elif member.name in ('.MTREE', '.BUILDINFO'): pass
            elif member.name not in expected or member.mode != expected[member.name]['mode'] or hashlib.sha256(data).hexdigest() != expected[member.name]['sha256']:
                raise ValueError('native package inventory mismatch')
    actual = {path for path in seen if path in expected}
    if actual != set(expected) or info is None: raise ValueError('incomplete native package inventory')
    if '\npkgname = '+name+'\n' not in '\n'+info or '\npkgver = '+version+'-'+str(release)+'\n' not in '\n'+info or '\narch = x86_64\n' not in '\n'+info:
        raise ValueError('native package identity mismatch')
    if component == 'dev-monitor' and '\ndepend = enzimos-terminal>=0.1.0-2\n' not in '\n'+info:
        raise ValueError('monitor requires paired Terminal launch capability')
    if replaced is not None:
        lines = set(info.splitlines())
        for alias in replacement_names(report):
            provider = 'oo7' if component == 'keyring' else alias
            if not {'conflict = '+alias, 'replaces = '+alias} <= lines or not any(l.startswith('provides = '+provider+'=') for l in lines):
                raise ValueError('replacement package relations differ for '+component)
    destination = Path(media)/(component+'.pkg.tar.zst')
    if destination.exists(): raise ValueError('new native media destination required')
    shutil.copyfile(package, destination)
    result = {'package_name': name, 'version': version, 'release': release, 'sha256': report['sha256'],
              'revision': report.get('revision'), 'profile': report.get('profile')}
    if descriptor is not None: result['developer_descriptor'] = descriptor
    if replaced is not None: result['replaces'] = replaced
    return result
