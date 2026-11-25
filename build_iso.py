#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the enzimOS installation ISO from published packages.

    sudo python3 build_iso.py --output DIR [--work DIR] [--label NAME]

Runs on any x86_64 Linux system with Python 3.11 or newer, gpg, tar, zstd,
root access and about 60 GB of free disk space. The build:

1. Downloads the current Arch Linux bootstrap image, checks its signature
   against the pinned Arch Linux release key and prepares an Arch build root.
2. Downloads the newest enzimOS packages from packages.enzim.dev (the
   `enzimos` and `enzimos-os` repositories), checking each signature against
   the pinned enzimOS repository key.
3. Resolves the newest Arch packages for the reviewed package set, downloads
   them and checks their signatures against the Arch Linux master keys.
4. Exports the default Flatpak apps from flatpak.enzim.dev and their Flathub
   runtimes.
5. Assembles the ISO as an unprivileged user with build_install_iso.py.

Package names come from this repository. Versions are whatever is newest
when the build runs. The work directory keeps downloads between runs.
"""
import argparse
import ctypes
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

HERE = Path(__file__).resolve().parent
ARCH_MIRROR = 'https://geo.mirror.pkgbuild.com'
BOOTSTRAP = 'iso/latest/archlinux-bootstrap-x86_64.tar.zst'
# Arch Linux release signing key (Pierre Schmitz), fetched over WKD.
RELEASE_KEY = '3E80CA1A8B89F69CBA57D98A76A5EF9054449A5C'
RELEASE_KEY_URL = ('https://openpgpkey.archlinux.org/.well-known/openpgpkey/archlinux.org/'
                   'hu/9hy3wi4ewwiicomnjmhewifn6d1gi87i?l=pierre')
ENZIMOS_URL = 'https://packages.enzim.dev'
ENZIMOS_KEY = '66CEB56F3018F39D2491A3B24C558611AFC55399'
ENZIMOS_REPOSITORIES = ('enzimos-os', 'enzimos')
FLATHUB_DESCRIPTOR = 'https://dl.flathub.org/repo/flathub.flatpakrepo'
ARCH_REPOSITORIES = ('core', 'extra', 'multilib')
# Build root tools (the ISO assembler runs these unprivileged inside it).
TOOLS = ('python', 'bubblewrap', 'fakeroot', 'libarchive', 'squashfs-tools', 'xorriso', 'zstd',
         'gnupg', 'flatpak', 'ostree', 'openssl', 'util-linux', 'pacman', 'archlinux-keyring',
         'mkinitcpio')
# The seed purpose whose reviewed package set the media carry.
PURPOSE = 'install-media-desktop-login-not-release-payload'
# Arch packages the enzimOS components need beyond the reviewed set.
EXTRA_ARCH = ('greetd-agreety', 'linux-firmware-marvell', 'gst-plugin-va', 'gst-plugins-bad', 'libnotify', 'poppler-glib')
# enzimOS packages the media carry, by name. The newest version across the
# enzimos-os and enzimos repositories is used.
COMPONENTS = (
    'enzimos-native-policy', 'enzimos-system-backend', 'enzimos-update-client',
    'enzimos-rust-packages', 'enzimos-rust-installer', 'enzimos-rust-remote-access',
    'enzimos-rust-updates', 'enzimos-rust-recovery-ui',
    'enzimos-keyring', 'enzimos-greetd', 'enzimos-agent-harness', 'enzimos-developer-tools',
    'enzimos-remote-access', 'enzimos-mount', 'enzimos-aft-mtp', 'enzimos-icon-theme',
    'enzimos-dev-monitor', 'enzimos-activity-service', 'enzimos-recovery-env',
    'enzimos-inference-service', 'enzimos-ai-gateway', 'enzimos-dictation', 'enzimos-llama-cpu',
    'enzimos-llama-vulkan', 'enzimos-whisper-cpu', 'enzimos-sherpa-onnx-cpu', 'enzimos-ai-models',
    'enzimos-files', 'enzimos-text', 'enzimos-terminal', 'enzimos-store',
    'enzimos-app-permissions', 'enzimos-background-apps', 'enzui-mcp-center', 'enzimos-phone-link',
    'enzimos-iso-desktop', 'enzimos-iso-runtime-layout',
)
OPTIONAL_COMPONENTS = ('enzimos-xdg-desktop-portal-hyprland',)
BUILDER = 'enzimos-builder'
INSIDE = Path('/work')


def log(message):
    print(f'[build_iso] {message}', flush=True)


def fetch(url, destination, attempts=4):
    destination = Path(destination)
    partial = destination.with_name(destination.name + '.part')
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'enzimos-build'})
            with urllib.request.urlopen(request, timeout=120) as response, partial.open('wb') as stream:
                shutil.copyfileobj(response, stream, 1024 * 1024)
            partial.replace(destination)
            return destination
        except OSError as error:
            if attempt == attempts - 1:
                raise RuntimeError(f'download failed: {url}: {error}') from error


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(*args, **kwargs):
    kwargs.setdefault('check', True)
    return subprocess.run([str(a) for a in args], **kwargs)


def gpg_fingerprints(home):
    out = run('gpg', '--homedir', home, '--batch', '--with-colons', '--fingerprint', '--list-keys',
              capture_output=True, text=True).stdout
    primary, result = False, []
    for line in out.splitlines():
        fields = line.split(':')
        if fields[0] == 'pub':
            primary = True
        elif fields[0] == 'fpr' and primary:
            result.append(fields[9])
            primary = False
    return result


def verify_detached(public_key, fingerprint, signature, data, gpg='gpg'):
    """Verify DATA with SIGNATURE, accepting only the pinned primary key."""
    with tempfile.TemporaryDirectory(prefix='enzimos-gpg-') as home:
        run(gpg, '--homedir', home, '--batch', '--quiet', '--import', public_key, capture_output=True)
        if fingerprint not in gpg_fingerprints(home):
            raise RuntimeError(f'{public_key} does not contain the pinned key {fingerprint}')
        status = run(gpg, '--homedir', home, '--batch', '--status-fd', '1', '--verify', signature, data,
                     capture_output=True, text=True, check=False).stdout
        valid = [line.split() for line in status.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
        if not valid or valid[0][-1] != fingerprint:
            raise RuntimeError(f'{data} has no valid signature from {fingerprint}')


# --- Host stage: Arch build root ---------------------------------------------------------------

libc = ctypes.CDLL(None, use_errno=True)


def mount(source, target, fstype=None, flags=0):
    if libc.mount(None if source is None else str(source).encode(), str(target).encode(),
                  None if fstype is None else fstype.encode(), ctypes.c_ulong(flags), None):
        error = ctypes.get_errno()
        raise OSError(error, f'mount {source} on {target}: {os.strerror(error)}')


MS_RDONLY, MS_REMOUNT, MS_BIND, MS_REC, MS_PRIVATE = 1, 32, 4096, 16384, 1 << 18


def enter_root(root, work, source):
    """Make ROOT the process root in a private mount namespace (pivot_root, not
    chroot, so the unprivileged build can still create user namespaces)."""
    if libc.unshare(0x00020000):
        raise OSError(ctypes.get_errno(), 'unshare(CLONE_NEWNS)')
    mount(None, '/', flags=MS_REC | MS_PRIVATE)
    mount(root, root, flags=MS_BIND | MS_REC)
    # Containers may refuse a new proc mount without a PID namespace; the
    # host's /proc (with its masked paths) serves the build equally well.
    mount('/proc', root / 'proc', flags=MS_BIND | MS_REC)
    mount('/sys', root / 'sys', flags=MS_BIND | MS_REC)
    mount('/dev', root / 'dev', flags=MS_BIND | MS_REC)
    mount('tmpfs', root / 'run', 'tmpfs')
    for target, path in ((root / 'work', work), (root / 'opt/enzimos-build', source)):
        target.mkdir(parents=True, exist_ok=True)
        mount(path, target, flags=MS_BIND | MS_REC)
    mount(source, root / 'opt/enzimos-build', flags=MS_BIND | MS_REMOUNT | MS_RDONLY)
    (root / 'tmp').mkdir(exist_ok=True)
    (work / 'tmp').mkdir(exist_ok=True)
    (work / 'tmp').chmod(0o1777)
    mount(work / 'tmp', root / 'tmp', flags=MS_BIND)
    shutil.copyfile('/etc/resolv.conf', root / 'etc/resolv.conf', follow_symlinks=True)
    os.chdir(root)
    (root / '.oldroot').mkdir(exist_ok=True)
    if libc.syscall(155, b'.', b'.oldroot'):  # pivot_root(2) on x86_64
        raise OSError(ctypes.get_errno(), 'pivot_root')
    os.chroot('.')
    os.chdir('/')
    if libc.umount2(b'/.oldroot', 2):
        raise OSError(ctypes.get_errno(), 'umount old root')
    os.rmdir('/.oldroot')


def prepare_root(work, mirror):
    """Download, verify and extract the newest Arch bootstrap image."""
    root = work / 'root'
    if (root / '.enzimos-ready').is_file():
        return root
    downloads = work / 'downloads'
    downloads.mkdir(parents=True, exist_ok=True)
    log('downloading the Arch Linux bootstrap image')
    image = fetch(f'{mirror}/{BOOTSTRAP}', downloads / 'bootstrap.tar.zst')
    signature = fetch(f'https://archlinux.org/{BOOTSTRAP}.sig', downloads / 'bootstrap.tar.zst.sig')
    key = fetch(RELEASE_KEY_URL, downloads / 'release-key.pgp')
    verify_detached(key, RELEASE_KEY, signature, image)
    log('bootstrap signature verified; extracting the build root')
    if root.exists():
        shutil.rmtree(root)
    staging = work / 'root.partial'
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir()
    run('tar', '--zstd', '--xattrs', '--xattrs-include=*', '-xpf', image, '-C', staging, '--numeric-owner')
    (staging / 'root.x86_64').rename(root)
    shutil.rmtree(staging)
    return root


def host(args):
    if os.geteuid() != 0:
        raise SystemExit('run build_iso.py as root (sudo); the ISO is still assembled by an unprivileged user')
    if os.uname().machine != 'x86_64':
        raise SystemExit('an x86_64 host is required')
    work = Path(args.work).resolve()
    output = Path(args.output).resolve()
    if output.is_relative_to(HERE) or work.is_relative_to(HERE):
        raise SystemExit('keep --work and --output outside the enzimos-build checkout')
    missing = [tool for tool in ('gpg', 'tar', 'zstd') if shutil.which(tool) is None]
    if missing:
        raise SystemExit('install these host tools first: ' + ' '.join(missing))
    work.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(work).free
    if free < 60 * 1024**3:
        raise SystemExit(f'at least 60 GB of free space is needed in {work}')
    root = prepare_root(work, args.arch_mirror)
    options = json.dumps({'label': args.label, 'arch_mirror': args.arch_mirror, 'enzimos_url': args.enzimos_url,
                          'fast': args.fast, 'no_flatpak': args.no_flatpak, 'secure_key': bool(args.secure_key),
                          'custom_desktop': bool(args.desktop)})
    custom = work / 'desktop.input'
    if custom.exists():
        shutil.rmtree(custom)
    if args.desktop:
        if not (Path(args.desktop) / 'usr/share/enzui/SOURCE-REVISION').is_file():
            raise SystemExit(f'{args.desktop} is not a desktop stage (see OUTPUT/work/build/desktop)')
        log(f'using the desktop stage in {args.desktop}')
        run('cp', '-a', '--reflink=auto', Path(args.desktop).resolve(strict=True), custom)
    for key in ('secure_key', 'secure_certificate'):
        if getattr(args, key):
            shutil.copyfile(getattr(args, key), work / f'{key}.input')
            os.chmod(work / f'{key}.input', 0o600)
    child = os.fork()
    if child == 0:
        try:
            enter_root(root, work, HERE)
            os.execve('/usr/bin/bash', ['bash', '-c', BOOTSTRAP_SCRIPT, 'bootstrap', options],
                      {'PATH': '/usr/bin', 'LANG': 'C.UTF-8', 'HOME': '/root'})
        except BaseException as error:
            print(f'[build_iso] cannot enter the build root: {error}', file=sys.stderr)
        os._exit(1)
    _, status = os.waitpid(child, 0)
    if os.waitstatus_to_exitcode(status):
        raise SystemExit('the ISO build failed; logs are in ' + str(work / 'logs'))
    result = json.loads((work / 'result.json').read_text())
    iso = work / result['iso']
    final = output / iso.name
    shutil.copyfile(iso, final)
    (output / (iso.name + '.sha256')).write_text(f"{result['iso_sha256']}  {iso.name}\n")
    shutil.copyfile(work / 'result.json', output / (iso.name.removesuffix('.iso') + '.json'))
    # The assembler's report, which install_iso_vm.py reads beside the ISO.
    shutil.copyfile(iso.with_name('build.json'), output / 'build.json')
    owner = os.environ.get('SUDO_UID'), os.environ.get('SUDO_GID')
    if all(owner):
        for path in output.iterdir():
            if path.name.startswith(iso.name.removesuffix('.iso')) or path.name == 'build.json':
                os.chown(path, int(owner[0]), int(owner[1]))
    log(f'ISO: {final}')
    log(f"SHA-256: {result['iso_sha256']}")


# Runs as root inside the build root: tools, then the Python build stages.
BOOTSTRAP_SCRIPT = r'''
set -euo pipefail
options=$1
mkdir -p /work/logs
if [[ ! -f /.enzimos-ready ]]; then
    mirror=$(printf '%s' "$options" | sed -n 's/.*"arch_mirror": "\([^"]*\)".*/\1/p')
    echo "Server = $mirror/\$repo/os/\$arch" > /etc/pacman.d/mirrorlist
    sed -i -e 's/^#\?CheckSpace/#CheckSpace/' -e 's/^#\?DisableSandbox.*/DisableSandbox/' /etc/pacman.conf
    grep -q '^DisableSandbox' /etc/pacman.conf || sed -i '/^\[options\]/a DisableSandbox' /etc/pacman.conf
    grep -q '^\[multilib\]' /etc/pacman.conf || printf '\n[multilib]\nInclude = /etc/pacman.d/mirrorlist\n' >> /etc/pacman.conf
    echo '[build_iso] initializing the build root package keyring'
    pacman-key --init >/work/logs/pacman-key.log 2>&1
    pacman-key --populate archlinux >>/work/logs/pacman-key.log 2>&1
    echo '[build_iso] installing build tools'
    pacman -Syu --noconfirm --needed __TOOLS__ >/work/logs/pacman-tools.log 2>&1 || {
        tail -30 /work/logs/pacman-tools.log >&2; exit 1; }
    id __BUILDER__ >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/__BUILDER__ __BUILDER__
    touch /.enzimos-ready
fi
# Tools added to the list since this build root was prepared.
pacman -S --noconfirm --needed __TOOLS__ >/work/logs/pacman-tools-update.log 2>&1 || {
    tail -30 /work/logs/pacman-tools-update.log >&2; exit 1; }
# Containers that hide parts of /proc (Colab, Docker) refuse a new proc mount
# inside a user namespace. Sandboxes then bind the existing /proc instead.
if [[ ! -e /usr/bin/bwrap.real ]] && ! runuser -u __BUILDER__ -- /usr/bin/bwrap --unshare-all \
        --ro-bind / / --proc /proc /usr/bin/true 2>/dev/null; then
    echo '[build_iso] this host refuses new /proc mounts; sandboxes bind the existing /proc'
    mv /usr/bin/bwrap /usr/bin/bwrap.real
    cat > /usr/bin/bwrap <<'WRAPPER'
#!/usr/bin/bash
args=()
while (($#)); do
    case $1 in
        --proc) args+=(--ro-bind /proc "$2"); shift 2 ;;
        --) args+=("$@"); break ;;
        *) args+=("$1"); shift ;;
    esac
done
exec /usr/bin/bwrap.real "${args[@]}"
WRAPPER
    chmod 0755 /usr/bin/bwrap
fi
exec /usr/bin/python3 -I /opt/enzimos-build/build_iso.py --inside "$options"
'''.replace('__TOOLS__', ' '.join(TOOLS)).replace('__BUILDER__', BUILDER)


# --- Inside the build root (root): enzimOS and Arch packages ----------------------------------

def vercmp(left, right):
    return int(run('vercmp', left, right, capture_output=True, text=True).stdout)


def parse_db(path):
    packages = {}
    with tarfile.open(path) as archive:
        for member in archive:
            if not member.name.endswith('/desc'):
                continue
            fields = {}
            for record in archive.extractfile(member).read().decode().strip().split('\n\n'):
                key, _, value = record.partition('\n')
                fields[key.strip('%')] = value.split('\n')
            packages[fields['NAME'][0]] = {
                'version': fields['VERSION'][0], 'filename': fields['FILENAME'][0],
                'sha256': fields['SHA256SUM'][0], 'depends': fields.get('DEPENDS', []),
                'provides': fields.get('PROVIDES', [])}
    return packages


def enzimos_packages(work, base_url):
    """Download the newest signed enzimOS packages named in COMPONENTS."""
    target = work / 'enzimos'
    target.mkdir(exist_ok=True)
    key = fetch(f'{base_url}/enzimos-packages.asc', target / 'enzimos-packages.asc')
    databases = {}
    for repository in ENZIMOS_REPOSITORIES:
        url = f'{base_url}/{repository}/x86_64'
        db = fetch(f'{url}/{repository}.db', target / f'{repository}.db')
        sig = fetch(f'{url}/{repository}.db.sig', target / f'{repository}.db.sig')
        verify_detached(key, ENZIMOS_KEY, sig, db)
        databases[repository] = (url, parse_db(db))
    chosen = {}
    for name in COMPONENTS + OPTIONAL_COMPONENTS:
        best = None
        for repository, (url, packages) in databases.items():
            if name in packages and (best is None or vercmp(packages[name]['version'], best[1]['version']) > 0):
                best = (url, packages[name])
        if best is None:
            if name in OPTIONAL_COMPONENTS:
                continue
            raise SystemExit(f'{name} is not published in {", ".join(ENZIMOS_REPOSITORIES)}')
        chosen[name] = best
    files = target / 'packages'
    files.mkdir(exist_ok=True)
    result = {}
    for name, (url, record) in sorted(chosen.items()):
        path = files / record['filename']
        if not path.is_file() or sha256(path) != record['sha256']:
            log(f"downloading {record['filename']}")
            fetch(f"{url}/{record['filename']}", path)
            fetch(f"{url}/{record['filename']}.sig", path.with_name(path.name + '.sig'))
        if sha256(path) != record['sha256']:
            raise SystemExit(f'{path.name} differs from the signed repository database')
        verify_detached(key, ENZIMOS_KEY, path.with_name(path.name + '.sig'), path)
        result[name] = {'path': str(path), **record}
    (work / 'enzimos-packages.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def bare(relation):
    for separator in ('>=', '<=', '=', '>', '<'):
        relation = relation.split(separator, 1)[0]
    return relation


def requested_packages(components):
    sys.path.insert(0, str(HERE))
    from headless_plan import seed_purposes
    names = set(seed_purposes()[PURPOSE]) | set(EXTRA_ARCH)
    native = set(components)
    for record in components.values():
        native.update(bare(p) for p in record['provides'])
    for name, record in components.items():
        if name in ('enzimos-iso-desktop', 'enzimos-iso-runtime-layout', 'enzimos-recovery-env'):
            continue
        names.update(bare(d) for d in record['depends'] if bare(d) not in native)
    return sorted(names)


def resolve_arch(work, mirror, requested):
    """Resolve and download the newest Arch packages; write the cohort the assembler reads."""
    plan = work / 'plan'
    if plan.exists():
        shutil.rmtree(plan)
    for directory in ('db/local', 'cache', 'root'):
        (plan / directory).mkdir(parents=True)
    servers = {repo: f'{mirror}/{repo}/os/x86_64' for repo in ARCH_REPOSITORIES}
    config = ('[options]\nArchitecture = x86_64\nRootDir = /work/plan/root\nDBPath = /work/plan/db\n'
              'CacheDir = /work/plan/cache\nLogFile = /work/plan/pacman.log\nDisableSandbox\n'
              'SigLevel = Required DatabaseOptional\n')
    config += ''.join(f'[{repo}]\nServer = {server}\n' for repo, server in servers.items())
    (plan / 'pacman.conf').write_text(config)
    log('synchronizing Arch Linux package databases')
    run('pacman', '--config', plan / 'pacman.conf', '-Sy', stdout=subprocess.DEVNULL)
    result = run('pacman', '--config', plan / 'pacman.conf', '-Sp', '--noconfirm',
                 '--print-format', '%n\t%v\t%a\t%r\t%l\t%s\t%h', *requested,
                 capture_output=True, text=True, check=False)
    if result.returncode:
        raise SystemExit('Arch package resolution failed:\n' + result.stderr[-4000:])
    records = []
    for line in result.stdout.splitlines():
        name, version, arch, repo, url, size, checksum = line.split('\t')
        if not url.startswith(servers[repo] + '/'):
            raise SystemExit(f'unexpected package URL {url}')
        records.append({'name': name, 'version': version, 'architecture': arch, 'repository': repo, 'url': url,
                        'download_bytes_from_metadata': int(size), 'sha256_from_metadata': checksum})
    log(f'{len(records)} Arch packages resolved')
    cohort = work / 'cohort'
    packages = cohort / 'packages'
    packages.mkdir(parents=True, exist_ok=True)
    cache = work / 'arch-cache'
    cache.mkdir(exist_ok=True)
    wanted = {r['url'].rsplit('/', 1)[-1] for r in records}
    for stale in packages.iterdir():
        if stale.name.removesuffix('.sig') not in wanted:
            stale.unlink()
    from concurrent.futures import ThreadPoolExecutor
    def download(record):
        filename = record['url'].rsplit('/', 1)[-1]
        path = cache / filename
        if not (path.is_file() and sha256(path) == record['sha256_from_metadata']):
            fetch(record['url'], path)
            if sha256(path) != record['sha256_from_metadata']:
                raise RuntimeError(f'{filename} differs from the Arch package database')
        signature = cache / (filename + '.sig')
        if not signature.is_file():
            fetch(record['url'] + '.sig', signature)
        for source in (path, signature):
            destination = packages / source.name
            if not destination.exists():
                os.link(source, destination)
    log('downloading Arch packages')
    with ThreadPoolExecutor(8) as pool:
        list(pool.map(download, records))
    (cohort / 'resolution').mkdir(exist_ok=True)
    (cohort / 'resolution/resolution.json').write_text(json.dumps({
        'status': 'RESOLVED-NOT-AUTHENTICATED-PAYLOAD', 'packages': records, 'package_count': len(records),
        'download_bytes_from_metadata': sum(r['download_bytes_from_metadata'] for r in records),
        'repository_snapshot': datetime.now(timezone.utc).strftime('%Y-%m-%d'), 'servers': servers,
        'requested_packages': requested, 'release_authorized': False}, indent=2) + '\n')
    # The current Arch keyring, checked by the assembler against the pinned master keys.
    keyring = cohort / 'keyring'
    keyring.mkdir(exist_ok=True)
    for name in ('archlinux.gpg', 'archlinux-revoked'):
        shutil.copyfile(f'/usr/share/pacman/keyrings/{name}', keyring / name)
    from package_trust import MASTERS
    reviewed = datetime.now(timezone.utc).replace(microsecond=0)
    (cohort / 'trust-lock.json').write_text(json.dumps({
        'schema_version': 1, 'masters': list(MASTERS), 'reviewed_at': reviewed.isoformat(),
        'review_before': (reviewed + timedelta(days=7)).isoformat(),
        'files': {name: {'bytes': (keyring / name).stat().st_size, 'sha256': sha256(keyring / name)}
                  for name in ('archlinux.gpg', 'archlinux-revoked')}}, indent=2) + '\n')
    return cohort


def inside(options):
    work = INSIDE
    options = json.loads(options)
    components = enzimos_packages(work, options['enzimos_url'])
    resolve_arch(work, options['arch_mirror'], requested_packages(components))
    for name in ('flathub.flatpakrepo',):
        fetch(FLATHUB_DESCRIPTOR, work / name)
    run('chown', '-R', f'{BUILDER}:{BUILDER}', work / 'cohort', work / 'enzimos', work / 'flathub.flatpakrepo',
        work / 'tmp', *[work / f'{k}.input' for k in ('secure_key', 'secure_certificate', 'desktop')
                        if (work / f'{k}.input').exists()])
    (work / 'tmp').chmod(0o1777)
    for stale in ('build', 'result.json'):
        path = work / stale
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    (work / 'build').mkdir()
    run('chown', f'{BUILDER}:{BUILDER}', work / 'build')
    result = run('runuser', '-u', BUILDER, '--', '/usr/bin/python3', '-I', HERE / 'build_iso.py',
                 '--assemble', json.dumps(options), check=False,
                 env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8', 'HOME': f'/var/lib/{BUILDER}', 'TMPDIR': '/tmp',
                      **({'ENZIMOS_DEV_FAST': '1'} if options['fast'] else {})})
    if result.returncode:
        raise SystemExit(result.returncode)
    shutil.copyfile(work / 'build/result.json', work / 'result.json')


# --- Inside the build root (unprivileged): reports, Flatpaks and assembly ---------------------

def extract_data(package, destination, kind):
    destination = Path(destination)
    if destination.exists():
        shutil.rmtree(destination)
    staging = destination.with_name(destination.name + '.partial')
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    run('bsdtar', '-xpf', package, '-C', staging, f'usr/share/enzimos-iso/{kind}')
    (staging / 'usr/share/enzimos-iso' / kind).rename(destination)
    shutil.rmtree(staging)
    return destination


def assemble(options):
    sys.path.insert(0, str(HERE))
    import build_install_iso
    import iso_reports
    work = INSIDE
    build = work / 'build'
    components = json.loads((work / 'enzimos-packages.json').read_text())
    packages = {name: Path(record['path']) for name, record in components.items()}
    desktop = extract_data(packages.pop('enzimos-iso-desktop'), build / 'desktop', 'desktop')
    if options.get('custom_desktop'):
        desktop = work / 'desktop.input'
    layout = extract_data(packages.pop('enzimos-iso-runtime-layout'), build / 'runtime-layout', 'runtime-layout')
    recovery = packages.pop('enzimos-recovery-env')
    log('writing component reports from the published packages')
    reports = iso_reports.write(build / 'reports', packages)
    recovery_report = build / 'reports/recovery-env.json'
    recovery_report.write_text(json.dumps({'schema': 1, 'status': 'PASS-recovery-env-built',
                                           'package': str(recovery), 'sha256': iso_reports.sha256(recovery),
                                           'release_authorized': False}, indent=2) + '\n')
    flatpak = {}
    if not options['no_flatpak']:
        log('exporting the default Flatpak apps and their runtimes')
        import prepare_flatpak_media
        prepare_flatpak_media.prepare(build / 'flatpak', work / 'flathub.flatpakrepo', [])
        flatpak = {'flatpak': build / 'flatpak/flathub', 'enzimos_flatpak': build / 'flatpak/enzimos'}
    secure = {}
    if options.get('secure_key'):
        secure = {'secure_key': work / 'secure_key.input', 'secure_certificate': work / 'secure_certificate.input'}
    cohort = work / 'cohort'
    label = options['label'] or datetime.now(timezone.utc).strftime('%Y%m%d')
    log('assembling the ISO (verifies every package signature first)')
    policy = reports.pop('policy_build')
    apps = reports.pop('app_builds')
    report = build_install_iso.build(
        None, cohort, policy, cohort / 'keyring', cohort / 'trust-lock.json', build / 'iso', label,
        desktop=desktop, recovery_env_build=recovery_report, app_builds=apps, runtime_repos=layout,
        **flatpak, **secure, **reports)
    iso = Path(report['iso'])
    (build / 'result.json').write_text(json.dumps({
        'iso': str(iso.relative_to(work)), 'iso_sha256': report['iso_sha256'], 'iso_bytes': report['iso_bytes'],
        'label': label, 'arch_packages': report['manifest']['package_count'], 'kernel': report['manifest']['kernel'],
        'enzimos_packages': {name: record['version'] for name, record in sorted(components.items())},
        'flatpaks': report['manifest'].get('enzimos_flatpaks', []), 'built_at': datetime.now(timezone.utc).isoformat(),
    }, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path, help='directory that receives the ISO')
    parser.add_argument('--work', type=Path, help='build directory, kept for later runs (default: OUTPUT/work)')
    parser.add_argument('--label', default='', help='image label (default: YYYYMMDD); the ISO is enzimos-LABEL-x86_64.iso')
    parser.add_argument('--arch-mirror', default=ARCH_MIRROR, help='Arch Linux mirror base URL')
    parser.add_argument('--enzimos-url', default=ENZIMOS_URL, help='enzimOS package server')
    parser.add_argument('--fast', action='store_true', help='quick compression for test images')
    parser.add_argument('--no-flatpak', action='store_true', help='leave out the offline Flatpak apps')
    parser.add_argument('--secure-key', type=Path, help='owner Secure Boot signing key (PEM)')
    parser.add_argument('--secure-certificate', type=Path, help='owner Secure Boot certificate (PEM)')
    parser.add_argument('--desktop', type=Path,
                        help='use this desktop stage instead of the published one (start from OUTPUT/work/build/desktop)')
    parser.add_argument('--inside', help=argparse.SUPPRESS)
    parser.add_argument('--assemble', help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.inside is not None:
            inside(args.inside)
        elif args.assemble is not None:
            assemble(json.loads(args.assemble))
        else:
            if args.output is None:
                parser.error('--output is required')
            if bool(args.secure_key) != bool(args.secure_certificate):
                parser.error('--secure-key and --secure-certificate go together')
            args.work = args.work or args.output / 'work'
            host(args)
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f'[build_iso] error: {error}', file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
