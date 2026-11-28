# SPDX-License-Identifier: MIT
"""Strict local metadata parsing; no execution, network or privileged operations."""
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath

MAX_JSON = 2 * 1024 * 1024


class Invalid(ValueError):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid('duplicate JSON property')
        result[key] = value
    return result


def load(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise Invalid('input must be a regular JSON file, not a symlink')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise Invalid('input is not a regular file')
        raw = stream.read(MAX_JSON + 1)
    if len(raw) > MAX_JSON:
        raise Invalid('JSON exceeds size limit')
    try:
        return json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Invalid('nonfinite number')))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise Invalid('invalid JSON document') from exc


def object_fields(value, names, label):
    if type(value) is not dict or set(value) != set(names.split()):
        raise Invalid(f'{label}: missing or unexpected fields')


def same(actual, expected, label):
    if type(actual) is not type(expected) or actual != expected:
        raise Invalid(f'{label}: does not match the accepted baseline')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def runtime_archive(summary, archive):
    """Resolve a runtime archive relative to its build summary."""
    path = Path(archive)
    if path.is_absolute():
        return path
    directory = Path(summary).resolve().parent
    parts = path.parts
    if not parts or '..' in parts:
        raise Invalid('invalid runtime archive path')
    # Older builders sometimes copied their reports elsewhere under work/.
    if parts[0] == 'work':
        if parts[1:2] == (directory.name,):
            return directory.joinpath(*parts[2:])
        work = next((parent for parent in (directory, *directory.parents)
                     if parent.name == 'work'), None)
        if work is not None:
            return work.parent / path
    return directory.joinpath(*parts)


def digest(path):
    value = hashlib.sha256()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise Invalid('digest input is not a regular file')
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


BASELINE = {
    'schema_version': 1, 'product': 'enzimos', 'architecture': 'x86_64',
    'release_maturity': 'alpha-planned', 'base': 'arch-writable', 'firmware': ['uefi', 'bios'],
    'boot': {'uefi_loader': 'systemd-boot', 'bios_loader': 'limine',
             'kernels': ['linux', 'linux-lts'], 'initramfs': 'mkinitcpio-systemd',
             'secure_boot': 'preserve-setting-factory-trust-required',
             'hibernation_status': 'deferred-for-now', 'nvidia_required': True},
    'storage': {'filesystem': 'btrfs', 'compression': True, 'encryption_default': 'luks2',
                'encryption_opt_out': True, 'snapshots': 'snapper', 'os_rollback_reverts_home': False,
                'home_history_default': True, 'swap': 'btrfs-excluded-swapfile',
                'zram': True, 'zswap': False, 'recovery': 'independent-on-disk'},
    'installer': {'frontend': 'enzui', 'backend': None, 'image_builder': None,
                  'media': 'installer-focused', 'complete_offline_payload': True,
                  'windows_resize': False, 'advanced_supported_layouts_required': True},
    'updates': {'native_default': 'confirmed-live-full-transaction', 'flatpak_default': 'automatic',
                'forced_reboot': False, 'automatic_metered_payloads': False},
    'defaults': {'firewall': 'enabled-trusted-connections-only-lan-allowance', 'agent': False,
                 'phone_remote': False, 'external_backups': False, 'backup_backend': 'restic',
                 'time': 'chrony-nts-no-plain-fallback', 'dns': 'network-vpn-with-user-override',
                 'connectivity_checks': True, 'distro_telemetry': False},
}

LEGACY_PRODUCT_FIELDS = {
    'work_scope': {'ui': 'deferred', 'physical_disk_operations': False,
                   'production_signing': False, 'publishing': False,
                   'secrets_scanning_plugin_investigation': 'deferred'},
    'decision_register': {'last_product_decision': 'D-110', 'authority': 'coordination/docs/DECISIONS.md'}
}
APP_SOURCES = {'calendar': 'calendar-app', 'files': 'files-app', 'mail': 'mail-app',
               'music': 'music-app', 'reader': 'reader-app', 'remote': 'remote-app',
               'store': 'store-app', 'task-manager': 'task-manager-app',
               'terminal': 'terminal-emulator', 'text': 'text-app'}
BASE_ROLES = {'native-base', 'native-shell-login', 'native-settings-repair', 'linux', 'linux-lts',
              'nvidia', 'graphics-multilib', 'uefi-boot', 'bios-boot', 'independent-recovery', 'flatpak-runtime', 'offline-voice-typing'}
GATES = [
    'reviewed-source-pins-and-license-inventory',
    'clean-arch-build-environment-and-dependency-closure',
    'factory-trusted-secure-boot-nvidia',
    'uefi-and-bios-packaged-boot', 'genuine-enzui-login-lock-and-default-apps',
    'live-full-updates-snapshots-independent-recovery',
    'offline-install-payload-and-native-installer',
    'trusted-signing-authorization-and-release-handoff'
]


def strict_baseline(actual, expected=BASELINE, label='product'):
    if type(expected) is dict:
        object_fields(actual, ' '.join(expected), label)
        for key in expected:
            strict_baseline(actual[key], expected[key], f'{label}.{key}')
    else:
        same(actual, expected, label)


def validate_catalogue(root):
    root = Path(root)
    product, apps, artifacts = [load(root / f'{name}.json') for name in ('product', 'apps', 'artifacts')]
    # The private development catalogue still uses the original schema-1 fields.
    legacy_product = type(product) is dict and bool(LEGACY_PRODUCT_FIELDS.keys() & product.keys())
    strict_baseline(product, BASELINE | LEGACY_PRODUCT_FIELDS if legacy_product else BASELINE)
    app_fields = 'schema_version apps browser installation_scope preinstallation_activates_accounts_or_remote'
    if type(apps) is dict and 'source_builds' in apps:
        app_fields += ' source_builds'
        same(apps['source_builds'], 'deferred-ui-inputs', 'apps.work')
    object_fields(apps, app_fields, 'apps')
    same(apps['schema_version'], 1, 'apps.version')
    same(apps['installation_scope'], 'system', 'apps.scope')
    same(apps['preinstallation_activates_accounts_or_remote'], False, 'apps.activation')
    browser = {'id': 'browser', 'delivery': 'project-flatpak', 'flatpak_id': 'org.enzim.Browser'}
    if legacy_product and 'source_builds' in apps:
        browser = {'id': 'zen', 'delivery': 'flathub-flatpak', 'flatpak_id': 'app.zen_browser.zen'}
    strict_baseline(apps['browser'], browser, 'browser')
    if type(apps['apps']) is not list or len(apps['apps']) != len(APP_SOURCES):
        raise Invalid('apps: incomplete explicit current fleet')
    seen = set()
    for app in apps['apps']:
        object_fields(app, 'id source delivery flatpak_id', 'app')
        name = app['id']
        if type(name) is not str or name not in APP_SOURCES or name in seen:
            raise Invalid('app: unknown or repeated identity')
        seen.add(name)
        same(app['source'], APP_SOURCES[name], 'app.source')
        same(app['delivery'], 'native' if name in ('terminal', 'store') else 'project-flatpak', 'app.delivery')
        same(app['flatpak_id'], None, 'app.unqualified-id')
    object_fields(artifacts, 'schema_version contract_kind required_roles unqualified_gates deferred_gates artifact_versions_and_hashes image_builder installer_backend', 'artifacts')
    same(artifacts['schema_version'], 1, 'artifacts.version')
    same(artifacts['contract_kind'], 'coarse-roles-not-dependency-closure', 'artifacts.kind')
    roles = artifacts['required_roles']
    required = BASE_ROLES | {f'app-{name}' for name in APP_SOURCES} | {f'app-{browser["id"]}'}
    if type(roles) is not list or any(type(x) is not str for x in roles) or len(roles) != len(required) or set(roles) != required:
        raise Invalid('artifacts: incomplete or duplicate role inventory')
    gates = artifacts['unqualified_gates']
    if isinstance(gates, list):
        # Older schema-1 manifests used a name from before the native installer.
        gates = ['offline-install-payload-and-native-installer'
                 if gate == 'offline-install-payload-and-existing-backend' else gate
                 for gate in gates]
    same(gates, GATES, 'artifacts.gates')
    artifacts['unqualified_gates'] = gates
    same(artifacts['deferred_gates'], ['hibernation-authenticated-resume'], 'artifacts.deferred-gates')
    for name in ('artifact_versions_and_hashes', 'image_builder', 'installer_backend'):
        same(artifacts[name], None, f'artifacts.{name}')
    return product, apps, artifacts


def inventory_check(root, inventory, required_roles):
    """Checks bytes/metadata only. No authenticity or dependency-closure claim."""
    object_fields(inventory, 'schema_version artifacts', 'inventory')
    same(inventory['schema_version'], 1, 'inventory.version')
    if type(inventory['artifacts']) is not list:
        raise Invalid('inventory.artifacts must be a list')
    root = Path(root).resolve(strict=True)
    seen = set()
    paths = set()
    for entry in inventory['artifacts']:
        object_fields(entry, 'role path size sha256', 'artifact')
        role, text = entry['role'], entry['path']
        if type(role) is not str or role not in required_roles or role in seen:
            raise Invalid('artifact: unknown or repeated role')
        if type(text) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+/-]*', text):
            raise Invalid('artifact: invalid relative path')
        parts = text.split('/')
        if any(part in ('', '.', '..') for part in parts) or PurePosixPath(text).is_absolute():
            raise Invalid('artifact: noncanonical or escaping path')
        path = root
        for part in parts:
            path = path / part
            if path.is_symlink():
                raise Invalid('artifact: symlinks are forbidden')
        if path in paths:
            raise Invalid('artifact: repeated file')
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise Invalid('artifact: not a regular file')
        if type(entry['size']) is not int or entry['size'] < 0 or info.st_size != entry['size']:
            raise Invalid('artifact: size mismatch')
        if type(entry['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', entry['sha256']):
            raise Invalid('artifact: invalid SHA-256')
        if digest(path) != entry['sha256']:
            raise Invalid('artifact: hash mismatch')
        seen.add(role)
        paths.add(path)
    missing = sorted(set(required_roles) - seen)
    return {'metadata_and_bytes_valid': True, 'roles_complete': not missing,
            'missing_roles': missing, 'release_authorized': False,
            'qualification': 'hashes-only-not-signatures-or-runtime-evidence'}
