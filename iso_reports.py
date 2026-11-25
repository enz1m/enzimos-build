# SPDX-License-Identifier: MIT
"""Write the ISO assembler's component reports from published package archives.

The assembler admits each component from a report that names its archive and
inventory. Published packages carry everything those reports state, so the
public build derives them from the downloaded archives instead of from the
original build receipts.
"""
import hashlib
import json
from pathlib import Path
import tarfile

from contract import Invalid
from native_apps_payload import COMPONENTS, REPLACES
from rust_runtime_payload import COMPONENTS as RUST_COMPONENTS

METADATA = {'.PKGINFO', '.BUILDINFO', '.MTREE'}
AI_PACKAGES = ('enzimos-inference-service', 'enzimos-ai-gateway', 'enzimos-dictation',
               'enzimos-llama-cpu', 'enzimos-llama-vulkan', 'enzimos-whisper-cpu',
               'enzimos-sherpa-onnx-cpu', 'enzimos-ai-models')
DEVELOPER_MANIFEST = 'usr/share/enzimos/developer/extension/manifest.json'
# Components the assembler takes through named options (not native_apps_payload).
SINGLE = {
    'policy': 'enzimos-native-policy',
    'backend': 'enzimos-system-backend',
    'update': 'enzimos-update-client',
    'mcp': 'enzui-mcp-center',
    'activity': 'enzimos-activity-service',
}
# Assembler option for each native component report.
NATIVE_OPTIONS = {
    'terminal': 'terminal_build', 'store': 'store_build', 'app-permissions': 'permissions_build',
    'agent-harness': 'harness_build', 'developer-tools': 'developer_build',
    'remote-access': 'remote_build', 'background-apps': 'background_build',
    'dev-monitor': 'monitor_build', 'xdg-desktop-portal-hyprland': 'portal_build',
    'greetd': 'greetd_build', 'keyring': 'keyring_build', 'phone-link': 'phone_build',
    'mount': 'mount_build', 'aft-mtp': 'aft_build', 'icon-theme': 'icon_theme_build',
}
APPS = ('files', 'text', 'task-manager')


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_archive(path):
    """Return (.PKGINFO fields, file inventory, member bytes for small metadata files)."""
    files, info, wanted = {}, None, {}
    with tarfile.open(path, 'r|*') as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            if member.isdir():
                continue
            if member.issym():
                files[name] = {'link': member.linkname}
                continue
            if not member.isfile():
                raise Invalid(f'{Path(path).name}: unsupported member {name}')
            data = archive.extractfile(member).read()
            if name == '.PKGINFO':
                info = data.decode()
            elif name in METADATA:
                continue
            else:
                files[name] = {'sha256': hashlib.sha256(data).hexdigest(), 'mode': member.mode & 0o7777}
                if name.startswith('usr/share/enzimos/rust-candidates/') or name == DEVELOPER_MANIFEST:
                    wanted[name] = data
    if info is None:
        raise Invalid(f'{Path(path).name}: not a pacman package')
    fields = {}
    for line in info.splitlines():
        key, separator, value = line.partition(' = ')
        if separator:
            fields.setdefault(key, []).append(value)
    return fields, files, wanted


def identity(fields):
    version = fields['pkgver'][0]
    if ':' in version:
        raise Invalid('epoch versions are not supported in install media')
    upstream, _, release = version.rpartition('-')
    if not release.isdigit():
        raise Invalid(f'invalid package release in {version}')
    return fields['pkgname'][0], upstream, int(release)


def base(path, status, extra=None):
    fields, files, wanted = read_archive(path)
    name, version, release = identity(fields)
    report = {'schema': 1, 'status': status, 'package_name': name, 'package': str(Path(path).resolve()),
              'sha256': sha256(path), 'version': version, 'release': release, 'files': files,
              'revision': 'published:' + Path(path).name, 'profile': 'published',
              'release_authorized': False, 'host_installed': False}
    report.update(extra or {})
    return report, fields, wanted


def native_report(component, path):
    name, status, _ = COMPONENTS[component]
    report, fields, wanted = base(path, status)
    if report['package_name'] != name:
        raise Invalid(f'{Path(path).name} is not {name}')
    report['replaces'] = REPLACES.get(component)
    if component == 'dev-monitor':
        report['api_version'] = 2
    if component == 'developer-tools' and DEVELOPER_MANIFEST in wanted:
        data = wanted[DEVELOPER_MANIFEST]
        report['developer_descriptor'] = {'package_payloads_shipped': False, 'sha256': hashlib.sha256(data).hexdigest(),
                                          'bytes': len(data)}
    return report


def rust_summary(packages):
    """The five-component runtime summary from the published runtime archives."""
    records, total = {}, 0
    for component, name in RUST_COMPONENTS.items():
        path = packages[name]
        fields, files, wanted = read_archive(path)
        pkgname, version, release = identity(fields)
        binding = json.loads(wanted[f'usr/share/enzimos/rust-candidates/{component}/build.json'])
        elf = len(binding.get('artifacts', {}))
        total += elf
        records[component] = {'package_name': pkgname, 'package': str(Path(path).resolve()), 'sha256': sha256(path),
                              'version': f'{version}-{release}', 'elf_count': elf,
                              'resource_count': len(binding.get('resources', {})),
                              'files': sorted(files), 'automatic_activation': False, 'host_installed': False}
    return {'result': 'PASS', 'packages': records, 'elf_count': total, 'automatic_activation': False,
            'installed_qualification': False, 'production_cutover': False, 'host_installed': False,
            'scope': 'published enzimOS runtime packages'}


def write(output, packages):
    """Write every report the packages allow; return assembler keyword arguments."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    def save(label, value):
        path = output / f'{label}.json'
        path.write_text(json.dumps(value, indent=2) + '\n')
        return path
    options = {}
    summary = save('installer-build', rust_summary(packages))
    options['installer_build'] = summary
    for label, name in SINGLE.items():
        if name not in packages:
            continue
        status = {'policy': 'PASS-unsigned-policy-package-built', 'backend': 'PASS-unsigned-policy-package-built',
                  'update': 'PASS-unsigned-policy-package-built', 'mcp': 'PASS-mcp-center-package-built',
                  'activity': 'PASS-activity-service-package-built'}[label]
        report, _, _ = base(packages[name], status)
        if label == 'backend':
            report['rust_runtime'] = {'sha256': json.loads(summary.read_text())['packages']['packages']['sha256']}
        options[label + '_build'] = save(label, report)
    ai = [name for name in AI_PACKAGES if name in packages]
    if ai:
        rows = [{'package_name': name, 'package': str(Path(packages[name]).resolve()), 'sha256': sha256(packages[name])}
                for name in ai]
        options['ai_build'] = save('ai', {'schema': 1, 'status': 'PASS-ai-packages-built', 'packages': rows,
                                          'models_included': 'enzimos-ai-models' in ai, 'release_authorized': False})
    for component, option in NATIVE_OPTIONS.items():
        name = COMPONENTS[component][0]
        if name in packages:
            options[option] = save(component, native_report(component, packages[name]))
    apps = {}
    for component in APPS:
        name = COMPONENTS[component][0]
        if name in packages:
            apps[component] = save(component, native_report(component, packages[name]))
    options['app_builds'] = apps
    return options
