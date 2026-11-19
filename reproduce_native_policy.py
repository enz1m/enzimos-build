#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit two-build byte comparison. No install, signing, network, or clean-toolchain claim."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from build_native_policy import build
from contract import Invalid, digest
from lab_resources import constrain_job
from signed_bootstrap import new_output


def compare(first, second):
    if first.get('package_name', 'enzimos-native-policy') != second.get('package_name', 'enzimos-native-policy'):
        raise Invalid('reproducibility package identities differ')
    for key in ('sources', 'source_modes', 'build_inputs', 'builder_sources', 'release', 'source_date_epoch'):
        if first[key] != second[key]:
            raise Invalid('reproducibility inputs differ: ' + key)
    for report in (first, second):
        if digest(report['package']) != report['sha256']:
            raise Invalid('build output changed after audit')
    if first['sha256'] != second['sha256']:
        raise Invalid('package archives differ; no metadata stripping or repacking permitted')
    if first['payload_audit'] != second['payload_audit']:
        raise Invalid('package audit results differ')
    return {'status': 'PASS-two-build-byte-reproducibility', 'package_sha256': first['sha256'],
            'package_version': '0.1.0-' + str(first['release']), 'package_name': first.get('package_name', 'enzimos-native-policy'), 'source_date_epoch': first['source_date_epoch'],
            'build_inputs': first['build_inputs'], 'builder_sources': first['builder_sources'],
            'payload_audit': first['payload_audit'], 'clean_arch_toolchain': False,
            'cross_host_reproducibility': False, 'host_installed': False, 'release_authorized': False,
            'scope': 'two fresh isolated directories using the same read-only host toolchain; full compressed archive identity, not normalized payload equivalence'}


def compare_archived(first, second, workspace=None):
    """Check preserved package bytes after obsolete scratch directories are removed.

    Live builds use compare directly. Historical evidence may resolve a missing
    workspace scratch package through the immutable cache indexed by its exact
    SHA-256. The ordinary full-byte comparison still verifies both objects.
    """
    import re
    root = Path(workspace).resolve() if workspace else Path(__file__).resolve().parents[2]
    reports=[]
    for report in (first,second):
        value=dict(report);original=Path(value['package'])
        if not original.exists():
            checksum=value['sha256']
            if not original.is_absolute() or not original.is_relative_to(root/'work') or not re.fullmatch('[0-9a-f]{64}',checksum):
                raise Invalid('missing archived package has no reviewed scratch identity')
            cached=root/'research/build-artifacts'/checksum
            if not cached.is_file() or cached.is_symlink():
                raise Invalid('archived package bytes are missing')
            value['package']=str(cached)
        reports.append(value)
    return compare(*reports)


def reproduce(source, license_path, output, release):
    if os.geteuid() == 0:
        raise Invalid('unprivileged build required')
    resources = constrain_job(cpu_limit=8)
    output = new_output(output)
    result = {'status': 'FAIL', 'release_authorized': False, 'host_resource_policy': resources}
    try:
        first = build(source, license_path, output/'first', release)
        second = build(source, license_path, output/'second', release)
        result.update(compare(first, second))
        result['build_reports'] = {name: digest(output/name/'build.json') for name in ('first', 'second')}
        return result
    except BaseException as exc:
        result['failure'] = str(exc)
        raise
    finally:
        (output/'reproducibility.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'license', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--release', type=int, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(reproduce(args.source, args.license, args.output, args.release), indent=2))
    except (Invalid, OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(2, f'reproducibility check failed: {exc}\n')
