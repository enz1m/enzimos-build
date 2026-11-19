#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Safe, explicit non-UI development commands; never executes build recipes."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
from contract import Invalid, canonical, digest, inventory_check, load, validate_catalogue


def stage_policy(manifests, packages, output):
    product, _, _ = validate_catalogue(manifests)
    packages = Path(packages).resolve(strict=True)
    template = (packages / 'recipes/enzimos-policy/PKGBUILD.in').read_text()
    license_bytes = (packages / 'LICENSE').read_bytes()
    policy_bytes = (json.dumps(product, indent=2) + '\n').encode()
    if template.count('@POLICY_SHA256@') != 1 or template.count('@LICENSE_SHA256@') != 1:
        raise Invalid('package template must contain exactly the two checksum placeholders')
    recipe = template.replace('@POLICY_SHA256@', hashlib.sha256(policy_bytes).hexdigest())
    recipe = recipe.replace('@LICENSE_SHA256@', hashlib.sha256(license_bytes).hexdigest())
    if '@' in recipe:
        raise Invalid('unresolved package template placeholder')
    output = Path(output).absolute()
    if any(p.is_symlink() for p in (output, *output.parents)):
        raise Invalid('output may not traverse symlinks')
    if '..' in output.parts:
        raise Invalid('output may not contain parent traversal')
    output = output.resolve(strict=False)
    for source in (Path(manifests).resolve(), packages, Path(__file__).resolve().parent):
        if output.is_relative_to(source):
            raise Invalid('output must not be inside a source repository')
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, body in (('product.json', policy_bytes), ('LICENSE', license_bytes), ('PKGBUILD', recipe.encode())):
        (output / name).write_bytes(body)
    result = {'kind': 'metadata-only-development-package-input', 'executes_build': False,
              'release_authorized': False, 'inputs': {name: digest(output / name) for name in ('product.json', 'LICENSE', 'PKGBUILD')}}
    (output / 'staging.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('validate', 'plan', 'stage-policy', 'check-artifacts'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--manifests', type=Path, required=True)
        if name == 'stage-policy':
            cmd.add_argument('--packages', type=Path, required=True)
            cmd.add_argument('--output', type=Path, required=True)
        if name == 'check-artifacts':
            cmd.add_argument('--inventory', type=Path, required=True)
            cmd.add_argument('--artifact-root', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        product, apps, artifacts = validate_catalogue(args.manifests)
        result = {'valid': True, 'product_sha256': hashlib.sha256(canonical(product)).hexdigest(),
                  'current_apps': len(apps['apps']), 'release_authorized': False}
        if args.command == 'plan':
            result.update(implemented=['policy-validation', 'data-only-package-staging', 'artifact-hash-checking'],
                          ui_work='deferred-external-inputs', required_roles=artifacts['required_roles'],
                          blocked_by=artifacts['unqualified_gates'], deferred_gates=artifacts['deferred_gates'],
                          build_execution_available=False)
        elif args.command == 'stage-policy':
            result = stage_policy(args.manifests, args.packages, args.output)
        elif args.command == 'check-artifacts':
            result = inventory_check(args.artifact_root, load(args.inventory), artifacts['required_roles'])
        print(json.dumps(result, indent=2))
        return 0 if result.get('roles_complete', True) else 1
    except (Invalid, OSError, ValueError) as exc:
        # Do not echo potentially sensitive input contents or absolute host paths.
        print(json.dumps({'valid': False, 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__,
                          'release_authorized': False}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
