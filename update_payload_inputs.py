#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Add exact audited package builds as a guest-local update payload (lab repository input).

The packages are placed as update-<name>.pkg.tar.zst with their build reports; the guest
fixture signs them with a disposable lab key and serves them from a file:// repository.
No host install, no network, no production keys.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
from contract import Invalid, digest, load
from lab_resources import constrain_job
from foundation_inputs import FIX
from prepare_target_lab import iso_command
from build_initrd_lab import run_command
from signed_bootstrap import FREE_FLOOR, new_output

NAMES = {'enzimos-native-policy': 'native-policy', 'enzimos-system-backend': 'system-backend'}


def prepare(base_path, builds, output, script=None):
    if os.geteuid() == 0:raise Invalid('unprivileged update payload preparation required')
    constrain_job(cpu_limit=8)
    base_path = Path(base_path).resolve(strict=True);base = load(base_path);directory = base_path.parent
    if base['status'] != 'PASS-foundation-inputs':raise Invalid('unexpired inputs required')
    for name, row in base['inputs'].items():
        if digest(directory/name) != row['sha256']:raise Invalid('base inputs changed')
    reports = [load(Path(path)) for path in builds]
    if not 1 <= len(reports) <= 2 or len({r.get('package_name') for r in reports}) != len(reports):raise Invalid('one or two distinct package builds required')
    for report in reports:
        if report.get('package_name') not in NAMES or digest(Path(report['package'])) != report['sha256']:raise Invalid('unknown or changed update package')
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR+64*1024**2:raise Invalid('update payload headroom')
    out = new_output(output);stage = out/'iso-stage';stage.mkdir()
    for path in (directory/'iso-stage').iterdir():
        if path.is_file() and path.name != 'SHA256SUMS':shutil.copyfile(path, stage/path.name)
    for path in FIX.glob('*.py'):shutil.copyfile(path, stage/path.name)
    summary = {}
    for path, report in zip(builds, reports):
        label = NAMES[report['package_name']]
        shutil.copyfile(report['package'], stage/('update-'+label+'.pkg.tar.zst'));shutil.copyfile(path, stage/('update-'+label+'-build.json'))
        summary[label] = {'release': report['release'], 'sha256': report['sha256']}
    (stage/'update-payload.json').write_text(json.dumps(summary, indent=2, sort_keys=True)+'\n')
    if script:
        if not (FIX/(script+'.py')).is_file():raise Invalid('payload-script module missing')
        (stage/'payload-script.json').write_text(json.dumps({'module': script})+'\n')
    (stage/'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.name}\n' for p in sorted(stage.iterdir())))
    args = iso_command(stage, out)
    if args[-2] != '/output/payload.iso':raise Invalid('ISO output contract')
    args[-2] = '/output/patch.iso';run_command(args, out, 'patch-iso', 60)
    if (out/'patch.iso').stat().st_size > 48*1024**2:raise Invalid('update payload ISO size bound')
    for name in base['inputs']:
        if name != 'patch.iso':os.link(directory/name, out/name)
    report = dict(base)
    report.update(update_packages=summary, payload_script=script, update_parent_inputs_sha256=digest(base_path), checked_at=datetime.now(timezone.utc).isoformat(),
                  fixture_hashes={p.name: digest(p) for p in FIX.iterdir() if p.is_file()},
                  inputs={n: {'bytes': (out/n).stat().st_size, 'sha256': digest(out/n)} for n in base['inputs']})
    (out/'inputs.json').write_text(json.dumps(report, indent=2)+'\n');return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-inputs', type=Path, required=True);parser.add_argument('--build', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True);parser.add_argument('--script-module')
    args = parser.parse_args()
    print(json.dumps(prepare(args.base_inputs, args.build, args.output, args.script_module), indent=2))
