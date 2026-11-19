#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit supplied Linux Kconfig text; never reads running-kernel/firmware state."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from contract import Invalid, MAX_JSON

FLAGS = (
    'CONFIG_HIBERNATION', 'CONFIG_HIBERNATION_SNAPSHOT_DEV',
    'CONFIG_SECURITY_LOCKDOWN_LSM', 'CONFIG_SECURITY_LOCKDOWN_LSM_EARLY',
    'CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE', 'CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY',
    'CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY', 'CONFIG_MODULE_SIG',
    'CONFIG_MODULE_SIG_FORCE', 'CONFIG_MODULE_SIG_ALL', 'CONFIG_INTEGRITY_MACHINE_KEYRING',
    'CONFIG_INTEGRITY_PLATFORM_KEYRING', 'CONFIG_ENCRYPTED_HIBERNATION',
)


def audit(text):
    if type(text) is not str or len(text.encode('utf-8')) > MAX_JSON:
        raise Invalid('config text exceeds bound or is not text')
    values = {}
    for line in text.splitlines():
        line = line.strip()
        unset = re.fullmatch(r'# (CONFIG_[A-Za-z0-9_]+) is not set', line)
        assignment = re.fullmatch(r'(CONFIG_[A-Za-z0-9_]+)=(.+)', line)
        if unset:
            key, value = unset[1], 'n'
        elif not line or line.startswith('#'):
            continue
        elif assignment:
            key, value = assignment[1], assignment[2]
        else:
            raise Invalid('unrecognized Kconfig line')
        if key in values:
            raise Invalid('duplicate Kconfig symbol')
        if key in FLAGS and value not in ('y', 'm', 'n'):
            raise Invalid('invalid value for audited Kconfig flag')
        values[key] = value
    if not values:
        raise Invalid('empty configuration')
    flags = {key: values.get(key, 'not-present') for key in FLAGS}
    findings = []
    if flags['CONFIG_HIBERNATION'] != 'y':
        findings.append('hibernation-built-in-not-established')
    if flags['CONFIG_SECURITY_LOCKDOWN_LSM'] != 'y':
        findings.append('lockdown-built-in-not-established')
    if flags['CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE'] == 'y':
        findings.append('compile-time-lockdown-not-forced-runtime-must-be-observed')
    if flags['CONFIG_MODULE_SIG_FORCE'] != 'y':
        findings.append('unconditional-compile-time-module-enforcement-not-established')
    if flags['CONFIG_ENCRYPTED_HIBERNATION'] == 'not-present':
        findings.append('proposed-encrypted-hibernation-symbol-not-present')
    return {'kind': 'supplied-config-capability-audit', 'config_sha256': hashlib.sha256(text.encode()).hexdigest(),
            'flags': flags, 'findings': findings, 'running_kernel_examined': False,
            'secure_boot_enforcement_verified': False, 'authenticated_resume_verified': False,
            'module_signer_trust_verified': False, 'release_qualified': False}


def audit_file(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise Invalid('config must be a regular file, not a symlink')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise Invalid('config is not a regular file')
        body = stream.read(MAX_JSON + 1)
    if len(body) > MAX_JSON:
        raise Invalid('config exceeds size bound')
    return audit(body.decode('utf-8'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(audit_file(args.config), indent=2))
    except (Invalid, OSError, ValueError) as exc:
        print(json.dumps({'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__,
                          'release_qualified': False}), file=sys.stderr)
        raise SystemExit(2)
