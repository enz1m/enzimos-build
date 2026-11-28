# SPDX-License-Identifier: MIT
"""Bind all five copy-only Rust runtimes to the target's offline manifest."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import tarfile
from contract import Invalid, runtime_archive

COMPONENTS={'packages':'enzimos-rust-packages','installer':'enzimos-rust-installer',
            'remote-access':'enzimos-rust-remote-access','recovery-ui':'enzimos-rust-recovery-ui',
            'updates':'enzimos-rust-updates'}
COUNTS={'packages':10,'installer':2,'remote-access':5,'recovery-ui':6,'updates':2}


def owned_paths(repository_root):
    """Files supplied by the verified runtime, excluded from a desktop snapshot."""
    paths = set()
    for component, name in COMPONENTS.items():
        spec = json.loads((Path(repository_root)/('enzimos-'+component)/'packaging/rust/runtime.json').read_text())
        paths.update(spec['binaries'].values())
        paths.update(row['target'] for row in spec.get('resources', {}).values())
        paths.update((f'usr/share/enzimos/rust-candidates/{component}/build.json', f'usr/share/licenses/{name}/LICENSE'))
    return paths


def stage(summary_path, media, repository_root):
    summary=json.loads(Path(summary_path).read_text())
    records=summary.get('packages',{})
    if summary.get('result')!='PASS' or set(records)!=set(COMPONENTS) or summary.get('elf_count')!=25 or summary.get('automatic_activation') is not False:
        raise Invalid('complete reviewed five-component Rust runtime required')
    result={}
    for component,name in COMPONENTS.items():
        record=records[component]
        spec=json.loads((Path(repository_root)/('enzimos-'+component)/'packaging/rust/runtime.json').read_text())
        package=runtime_archive(summary_path, record['package'])
        version = record.get('version')
        upstream = r'0\.2\.[012]' if component == 'installer' else r'0\.2\.0'
        match = re.fullmatch(rf'({upstream})-([1-9][0-9]{{0,3}})', version) if isinstance(version, str) else None
        if (record.get('package_name')!=name or match is None
                or record.get('automatic_activation') is not False or record.get('elf_count')!=COUNTS[component]
                or package.is_symlink() or not package.is_file() or not 0<package.stat().st_size<=128*1024**2):
            raise Invalid('paired Rust runtime package identity')
        with package.open('rb') as stream:
            if hashlib.file_digest(stream,'sha256').hexdigest()!=record['sha256']:raise Invalid('Rust runtime package digest')
        binary_paths=spec['binaries'];resources={v['target']:v for v in spec.get('resources',{}).values()}
        binding_path=f'usr/share/enzimos/rust-candidates/{component}/build.json'
        license_path=f'usr/share/licenses/{name}/LICENSE'
        expected=set(binary_paths.values())|set(resources)|{binding_path,license_path}
        if len(binary_paths)!=COUNTS[component] or len(expected)!=len(binary_paths)+len(resources)+2:
            raise Invalid('Rust runtime recipe registry differs')
        files={};seen=set();total=0;info=None
        with tarfile.open(package,'r|zst') as archive:
            for member in archive:
                path=Path(member.name);total+=member.size
                if (path.is_absolute() or '..' in path.parts or member.name in seen or member.uid or member.gid
                        or not (member.isfile() or member.isdir()) or total>256*1024**2):
                    raise Invalid('unsafe Rust runtime archive member')
                seen.add(member.name)
                if member.isdir():
                    if member.mode!=0o755 or not any(p.startswith(member.name.rstrip('/')+'/') for p in expected):
                        raise Invalid('unexpected Rust runtime directory')
                    continue
                if member.size>32*1024**2:raise Invalid('Rust runtime member bound')
                data=archive.extractfile(member).read()
                if member.name=='.PKGINFO':info=data.decode()
                elif member.name in ('.MTREE','.BUILDINFO'):pass
                elif member.name not in expected:raise Invalid('unexpected Rust runtime payload')
                else:files[member.name]=(data,member.mode)
        if set(files)!=expected or info is None:raise Invalid('incomplete Rust runtime payload')
        for line in ('pkgname = '+name,'pkgver = '+record['version'],'arch = x86_64'):
            if info.splitlines().count(line)!=1:raise Invalid('Rust runtime archive identity')
        binding=json.loads(files[binding_path][0])
        if (binding.get('schema')!=1 or binding.get('component')!=component
                or binding.get('automatic_activation') is not False or binding.get('production_cutover') is not False
                or set(binding.get('artifacts',{}))!=set(binary_paths) or set(binding.get('resources',{}))!=set(resources)):
            raise Invalid('Rust runtime build registry')
        for binary,path in binary_paths.items():
            data,mode=files[path];artifact=binding['artifacts'][binary]
            if mode!=0o755 or not data.startswith(b'\x7fELF') or len(data)!=artifact['bytes'] or hashlib.sha256(data).hexdigest()!=artifact['sha256']:
                raise Invalid('Rust runtime ELF binding')
        for path,specification in resources.items():
            data,mode=files[path];resource=binding['resources'][path]
            if mode!=specification['mode'] or mode!=resource['mode'] or hashlib.sha256(data).hexdigest()!=resource['sha256']:
                raise Invalid('Rust runtime resource binding')
        if any(files[p][1]!=0o644 for p in (binding_path,license_path)):raise Invalid('Rust runtime metadata permissions')
        filename='rust-'+component+'.pkg.tar.zst';destination=Path(media)/filename
        if destination.exists():raise Invalid('fresh Rust runtime media destination required')
        shutil.copyfile(package,destination)
        with destination.open('rb') as stream:
            if hashlib.file_digest(stream,'sha256').hexdigest()!=record['sha256']:raise Invalid('Rust runtime staging digest')
        result[component]={'package_name':name,'release':int(match[2]),'version':match[1],'sha256':record['sha256'],
                           'profile':'rust-candidate','automatic_activation':False}
    return result
