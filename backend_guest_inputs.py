#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Add only a hash-bound System1 activation package to a new explicit guest patch ISO."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
from contract import Invalid, digest, load
from foundation_inputs import FIX
from prepare_target_lab import iso_command
from build_initrd_lab import run_command
from lab_resources import constrain_job
from signed_bootstrap import FREE_FLOOR, new_output


def prepare(base_path, backend_build, output):
    if os.geteuid() == 0:raise Invalid('unprivileged backend input preparation required')
    constrain_job(cpu_limit=8)
    base_path = Path(base_path).resolve(strict=True);base = load(base_path);directory = base_path.parent
    build = load(backend_build);package = Path(build['package'])
    if build.get('package_name') != 'enzimos-system-backend' or digest(package) != build['sha256']:raise Invalid('backend package mismatch')
    if base['status'] != 'PASS-foundation-inputs':raise Invalid('unexpired inputs required')
    for name, row in base['inputs'].items():
        if digest(directory/name) != row['sha256']:raise Invalid('base inputs changed')
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR+64*1024**2:raise Invalid('backend ISO headroom')
    out = new_output(output);stage = out/'iso-stage';stage.mkdir()
    for path in (directory/'iso-stage').iterdir():
        if path.is_file() and path.name != 'SHA256SUMS':shutil.copyfile(path, stage/path.name)
    for path in FIX.glob('*.py'):shutil.copyfile(path, stage/path.name)
    shutil.copyfile(package, stage/'system-backend.pkg.tar.zst');shutil.copyfile(backend_build, stage/'backend-build.json')
    (stage/'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.name}\n' for p in sorted(stage.iterdir())))
    args = iso_command(stage, out)
    if args[-2] != '/output/payload.iso':raise Invalid('ISO output contract')
    args[-2] = '/output/patch.iso';run_command(args, out, 'patch-iso', 60)
    if (out/'patch.iso').stat().st_size > 48*1024**2:raise Invalid('backend ISO size bound')
    for name in base['inputs']:
        if name != 'patch.iso':os.link(directory/name, out/name)
    report = dict(base)
    report.update(backend_package_sha256=build['sha256'], backend_build_sha256=digest(Path(backend_build)),
                  backend_parent_inputs_sha256=digest(base_path), checked_at=datetime.now(timezone.utc).isoformat(),
                  fixture_hashes={p.name: digest(p) for p in FIX.iterdir() if p.is_file()},
                  inputs={n: {'bytes': (out/n).stat().st_size, 'sha256': digest(out/n)} for n in base['inputs']})
    (out/'inputs.json').write_text(json.dumps(report, indent=2)+'\n');return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base-inputs', 'backend-build', 'output'):parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args();print(json.dumps(prepare(args.base_inputs, args.backend_build, args.output), indent=2))
