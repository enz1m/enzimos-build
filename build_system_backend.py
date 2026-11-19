#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the System1 backend activation package; the service itself is the Rust runtime."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
from build_native_policy import build
from contract import Invalid, digest, runtime_archive
from lab_resources import constrain_job
from native_package_audit import bounded_bytes, read_package_info
from signed_bootstrap import FREE_FLOOR, new_output

PACKAGES = Path(__file__).resolve().parent.parent / "enzimos-packages"
SOURCE = PACKAGES / "system-backend"
FILES = {'org.enzimos.System1.conf': 'usr/share/dbus-1/system.d/org.enzimos.System1.conf',
         'org.enzimos.System1.policy': 'usr/share/polkit-1/actions/org.enzimos.System1.policy',
         'enzimos-system-backend.service': 'usr/lib/systemd/system/enzimos-system-backend.service',
         'org.enzimos.System1.service': 'usr/share/dbus-1/system-services/org.enzimos.System1.service'}


def paired_inputs(policy_report, runtime_summary):
    """Return the versions of the native policy and its matching Rust runtime."""
    if policy_report is None or runtime_summary is None:
        raise Invalid('paired native policy report and Rust runtime summary required')
    runtime = json.loads(Path(runtime_summary).read_text())
    candidate = runtime.get('packages', {}).get('packages', {})
    runtime_version = candidate.get('version')
    if (runtime.get('result') != 'PASS' or candidate.get('package_name') != 'enzimos-rust-packages'
            or not isinstance(runtime_version, str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-[1-9][0-9]*', runtime_version)
            or candidate.get('elf_count') != 10 or digest(runtime_archive(runtime_summary, candidate['package'])) != candidate.get('sha256')):
        raise Invalid('paired native backend runtime package required')

    policy = json.loads(Path(policy_report).read_text())
    if (policy.get('status') != 'PASS-unsigned-policy-package-built'
            or policy.get('package_name') != 'enzimos-native-policy'
            or policy.get('payload_audit', {}).get('status') != 'PASS-exact-authored-package-payload'):
        raise Invalid('audited native policy build required')
    body = bounded_bytes(Path(policy['package']))
    if hashlib.sha256(body).hexdigest() != policy.get('sha256'):
        raise Invalid('native policy package differs from its build report')
    fields = read_package_info(io.BytesIO(body))
    versions = fields.get('pkgver', [])
    if (fields.get('pkgname') != ['enzimos-native-policy'] or len(versions) != 1
            or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-[1-9][0-9]*', versions[0])
            or versions[0].rsplit('-', 1)[1] != str(policy.get('release'))):
        raise Invalid('native policy package identity differs from its build report')
    runtime_dependencies = [value for value in fields.get('depend', [])
                            if value.partition('=')[0] == 'enzimos-rust-packages']
    if runtime_dependencies != [f'enzimos-rust-packages={runtime_version}']:
        raise Invalid('native policy requires a different Rust runtime')
    return policy, versions[0], candidate


def backend_recipe(template, policy_version, runtime_version):
    for marker, version in (('@NATIVE_POLICY_VERSION@', policy_version),
                            ('@RUST_RUNTIME_VERSION@', runtime_version)):
        if template.count(marker) != 1:
            raise Invalid('exact backend dependency template required: ' + marker)
        template = template.replace(marker, version)
    return template


def build_backend(output, release=1, *, policy_report=None, runtime_summary=None, packages=PACKAGES):
    if os.geteuid() == 0:raise Invalid('unprivileged package build required')
    policy, policy_version, candidate = paired_inputs(policy_report, runtime_summary)
    packages = Path(packages).resolve(strict=True)
    activation = packages / 'system-backend'
    recipe = backend_recipe((activation/'PKGBUILD.in').read_text(), policy_version, candidate['version'])
    constrain_job(cpu_limit=8)
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR+32*1024**2:raise Invalid('backend build headroom')
    out = new_output(output);source = out/'source';source.mkdir()
    for name, destination in FILES.items():
        path = activation/name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 128*1024:raise Invalid('bounded original source required')
        target = source/'root'/destination;target.parent.mkdir(parents=True, exist_ok=True);shutil.copyfile(path, target);target.chmod(0o644)
    shutil.copyfile(activation/'native-policy.install', source/'native-policy.install')
    (source/'PKGBUILD.in').write_text(recipe)
    report = build(source, packages/'LICENSE', out/'build', release, package_name='enzimos-system-backend')
    report['backend_sources'] = {name: digest(activation/name) for name in (*FILES, 'PKGBUILD.in', 'native-policy.install')}
    report['native_policy'] = {'package_name': policy['package_name'], 'version': policy_version,
                               'sha256': policy['sha256'], 'report_sha256': digest(Path(policy_report))}
    report['rust_runtime'] = {'package_name':candidate['package_name'],'version':candidate['version'],'sha256':candidate['sha256'],'summary_sha256':digest(Path(runtime_summary))}
    report['shipping_qualified'] = False
    (out/'build.json').write_text(json.dumps(report, indent=2)+'\n');return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__);parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--release', type=int, default=1)
    parser.add_argument('--native-policy', type=Path, required=True, help='audited native policy build report')
    parser.add_argument('--rust-runtime',type=Path,required=True,help='reviewed Rust runtime package summary')
    parser.add_argument('--packages', type=Path, default=PACKAGES, help='enzimos-packages checkout')
    args = parser.parse_args()
    print(json.dumps(build_backend(args.output, args.release, policy_report=args.native_policy, runtime_summary=args.rust_runtime, packages=args.packages), indent=2))
