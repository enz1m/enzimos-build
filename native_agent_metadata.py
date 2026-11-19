# SPDX-License-Identifier: MIT
"""Stage package-owned app discovery and activation from exact build sources."""
import configparser
import hashlib
import json
from pathlib import Path
import re
import subprocess

APP_ID = re.compile(r'[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z][A-Za-z0-9_-]*)+')
APP_NAME = re.compile(r'[a-z][a-z0-9-]{0,79}')
MAX_METADATA = 1024 * 1024


def source_file(source, revision, relative):
    size = int(subprocess.check_output(['git', '-C', str(source), 'cat-file', '-s',
                                       revision + ':' + relative]))
    if not 0 < size <= MAX_METADATA:
        raise ValueError('bounded committed app metadata required')
    result = subprocess.run(['git', '-C', str(source), 'show', revision + ':' + relative],
                            check=True, capture_output=True)
    if len(result.stdout) != size:
        raise ValueError('committed metadata size mismatch')
    return result.stdout


def document(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate metadata key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def ini(data, repeatable=()):
    section = None
    seen = set()
    for raw in data.decode().splitlines():
        line = raw.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
            if ('section', section) in seen:
                raise ValueError('duplicate metadata section')
            seen.add(('section', section))
            continue
        key, separator, _ = line.partition('=')
        identity = (section, key.strip())
        if not separator or (identity in seen and not (section == 'Service' and key.strip() in repeatable)):
            raise ValueError('invalid or duplicate metadata directive')
        seen.add(identity)
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read_string(data.decode())
    return parser


def plan(source, binaries, destination, app):
    """Validate metadata and binary provenance without modifying the staging tree."""
    if APP_NAME.fullmatch(app) is None:
        raise ValueError('invalid native app name')
    source = Path(source).resolve(strict=True)
    binaries = Path(binaries).resolve(strict=True)
    destination = Path(destination).resolve(strict=True)
    receipt_path = binaries / (app + '.receipt.json')
    if receipt_path.is_symlink() or receipt_path.stat().st_size > MAX_METADATA:
        raise ValueError('bounded regular app receipt required')
    receipt = document(receipt_path.read_bytes())
    revision = receipt['source']['revision']
    if (receipt.get('schema') != 1 or receipt['source'].get('dirty') is not False
            or receipt.get('framework', {}).get('dirty') is not False
            or 'center' not in receipt.get('features', [])
            or re.fullmatch(r'[0-9a-f]{40}', revision) is None):
        raise ValueError('clean center-enabled native app build required')
    head = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    if head != revision:
        raise ValueError('app metadata revision differs from binary source')
    binary = binaries / app
    if (binary.is_symlink() or not binary.is_file()
            or not 0 < binary.stat().st_size <= 128 * 1024**2
            or not binary.stat().st_mode & 0o111):
        raise ValueError('bounded executable native binary required')
    with binary.open('rb') as stream:
        if stream.read(4) != b'\x7fELF':
            raise ValueError('native ELF required')
        stream.seek(0)
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != receipt['files'].get(app):
        raise ValueError('native app binary differs from receipt')
    installed = destination / 'usr/lib/enzui/apps' / app
    if installed.is_symlink() or not installed.is_file() or not installed.stat().st_mode & 0o111:
        raise ValueError('stage the native app binary before its activation metadata')
    with installed.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
            raise ValueError('staged native app binary differs from receipt')

    prefix = app + '/packaging/agent/'
    names = subprocess.check_output(['git', '-C', str(source), 'ls-tree', '-r', '--name-only',
                                     revision, '--', prefix], text=True).splitlines()
    catalogs = [name for name in names if name.startswith(prefix)
                and '/' not in name[len(prefix):] and name.endswith('.json')
                and not name.endswith('.background.json')]
    if len(catalogs) != 1:
        raise ValueError('exactly one committed app catalog required')
    catalog_data = source_file(source, revision, catalogs[0])
    catalog = document(catalog_data)
    app_id = catalog['registration']['app']['id']
    unit = 'enzui-agent-' + app_id + '.service'
    if (APP_ID.fullmatch(app_id) is None or catalog.get('schema') != 1
            or catalog.get('activation_unit') != unit
            or catalogs[0] != prefix + app_id + '.json'):
        raise ValueError('native catalog identity mismatch')
    background_data = source_file(source, revision, prefix + app_id + '.background.json')
    background = document(background_data)
    executable = '/usr/bin/' + app
    if (background.get('schema') != 1 or background.get('app_id') != app_id
            or background.get('unit') != unit or background.get('executable') != executable):
        raise ValueError('background declaration identity mismatch')
    unit_data = source_file(source, revision, prefix + unit)
    service = ini(unit_data, repeatable=('Environment', 'ReadWritePaths'))
    if (set(service.sections()) != {'Unit', 'Service'}
            or service['Service'].get('ExecStart') != executable + ' --agent-background'
            or service['Service'].get('Restart') != 'no'
            or any(key in service['Service'] for key in ('User', 'Group', 'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost'))):
        raise ValueError('fixed on-demand native user service required')
    dbus_data = source_file(source, revision, prefix + 'dbus/' + app_id + '.service')
    dbus = ini(dbus_data)
    if (dbus.sections() != ['D-BUS Service']
            or dict(dbus['D-BUS Service']) != {'Name': app_id,
                 'Exec': executable + ' --agent-background', 'SystemdService': unit}):
        raise ValueError('fixed native D-Bus activation required')

    files = {
        'usr/share/enzui/agent-apps/' + app_id + '.json': catalog_data,
        'usr/share/enzui/background-apps/' + app_id + '.json': background_data,
        'usr/lib/systemd/user/' + unit: unit_data,
        'usr/share/dbus-1/services/' + app_id + '.service': dbus_data,
    }
    alias = destination / executable.lstrip('/')
    target = '/usr/lib/enzui/apps/' + app
    if alias.exists() or alias.is_symlink():
        raise ValueError('native executable alias already exists')
    for relative in [*files, executable.lstrip('/')]:
        path = destination / relative
        if path.exists() or path.is_symlink():
            raise ValueError('activation metadata already exists')
        for parent in path.parents:
            if parent == destination:
                break
            if parent.is_symlink():
                raise ValueError('activation metadata staging parent is a symlink')
    return {'app_id': app_id, 'app': app, 'revision': revision, 'binary_sha256': digest,
            'files': files, 'alias': alias, 'target': target, 'destination': destination}


def stage(source, binaries, destination, app):
    """Install validated discovery files and an alias without enabling any service."""
    value = plan(source, binaries, destination, app)
    inventory = {}
    for relative, data in value['files'].items():
        path = value['destination'] / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o644)
        inventory[relative] = hashlib.sha256(data).hexdigest()
    value['alias'].parent.mkdir(parents=True, exist_ok=True)
    value['alias'].symlink_to(value['target'])
    return {'schema': 1, 'app': app, 'app_id': value['app_id'], 'revision': value['revision'],
            'binary_sha256': value['binary_sha256'], 'files': inventory,
            'alias': {'path': str(value['alias'].relative_to(value['destination'])),
                      'target': value['target']}, 'service_enabled': False}
