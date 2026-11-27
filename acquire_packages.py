#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit HTTPS acquisition into a NEW directory; hashes are not signature approval."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import threading
import io
import http.client
from urllib.parse import urlsplit
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler, HTTPSHandler, Request

from contract import Invalid, load
from signed_bootstrap import new_output, FREE_FLOOR


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise Invalid('unexpected redirect; review the artifact origin explicitly')


class DeadlineReader(io.RawIOBase):
    """Apply the transfer's absolute deadline at every underlying socket read."""
    def __init__(self, sock, deadline):
        self.source = sock.makefile('rb', buffering=0)
        self.sock = sock
        self.deadline = deadline

    def readable(self):return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:raise TimeoutError('acquisition deadline reached')
        self.sock.settimeout(min(25, remaining))
        return self.source.readinto(buffer)

    def close(self):
        try:self.source.close()
        finally:super().close()


class DeadlineSocket:
    def __init__(self, sock, deadline):self.sock, self.deadline = sock, deadline
    def makefile(self, mode):
        if mode != 'rb':raise Invalid('unexpected acquisition transport mode')
        return io.BufferedReader(DeadlineReader(self.sock, self.deadline))


class DeadlineHTTPS(HTTPSHandler):
    def __init__(self, deadline):
        super().__init__()
        self.deadline = deadline

    def https_open(self, request):
        def connection(host, **options):
            conn = http.client.HTTPSConnection(host, **options)
            conn.response_class = lambda sock, **kw: http.client.HTTPResponse(
                DeadlineSocket(sock, self.deadline), **kw)
            return conn
        return self.do_open(connection, request, context=self._context)


def validate_plan(plan):
    if type(plan) is not dict:
        raise Invalid('package plan must be an object')
    items = plan.get('packages')
    if type(items) is not list or not 0 < len(items) <= 1024:
        raise Invalid('invalid package count')
    seen = set(); total = 0
    snapshot = plan.get('repository_snapshot')
    if type(snapshot) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', snapshot):
        raise Invalid('dated snapshot required')
    for item in items:
        if type(item) is not dict or type(item.get('url')) is not str:
            raise Invalid('invalid package record')
        url = item['url']
        parsed = urlsplit(url)
        filename = parsed.path.rsplit('/', 1)[-1]
        repo = item.get('repository')
        package_snapshot = item.get('repository_snapshot', snapshot)
        if type(package_snapshot) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', package_snapshot):
            raise Invalid('dated package snapshot required')
        prefix = f"https://archive.archlinux.org/repos/{package_snapshot.replace('-', '/')}/{repo}/os/x86_64/"
        if repo not in ('core', 'extra', 'multilib') or not url.startswith(prefix) or parsed.query or parsed.fragment:
            raise Invalid('package origin is outside the reviewed snapshot')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+:-]*\.pkg\.tar\.(zst|xz)', filename) or filename in seen:
            raise Invalid('invalid or duplicate package filename')
        if not re.fullmatch('[0-9a-f]{64}', item.get('sha256_from_metadata', '')):
            raise Invalid('invalid expected SHA-256')
        size = item.get('download_bytes_from_metadata')
        if type(size) is not int or not 0 < size <= 512 * 1024**2:
            raise Invalid('package size outside budget')
        seen.add(filename); total += size
    # 1.5 GiB: the install medium's consumer-hardware set (firmware, NVIDIA, both kernels).
    if total > 1536 * 1024**2:
        raise Invalid('package batch exceeds 1.5 GiB review budget')
    return items


def acquire(plan_path, output):
    if os.geteuid() == 0:
        raise Invalid('run acquisition unprivileged')
    plan = load(plan_path); items = validate_plan(plan)
    if shutil.disk_usage(Path(output).absolute().parent).free < FREE_FLOOR + 1024**3:
        raise Invalid('insufficient free-space headroom; no cleanup attempted')
    output = new_output(output)
    deadline = time.monotonic() + 600
    cancelled = threading.Event()

    def fetch(item):
        opener = build_opener(ProxyHandler({}), NoRedirects(), DeadlineHTTPS(deadline))
        name = item['url'].rsplit('/', 1)[-1]
        result = {'name': item['name'], 'files': []}
        for suffix in ('', '.sig'):
            if cancelled.is_set() or time.monotonic() > deadline:
                raise Invalid('acquisition cancelled or deadline reached')
            path = output / (name + suffix)
            cap = item['download_bytes_from_metadata'] if not suffix else 65536
            value = hashlib.sha256(); count = 0
            request = Request(item['url'] + suffix, headers={'User-Agent': 'enzimos-explicit-package-acquisition'})
            try:
                with opener.open(request, timeout=min(25, max(.001, deadline - time.monotonic()))) as response, path.open('xb') as stream:
                    if response.status != 200:
                        raise Invalid('unexpected HTTP response')
                    while chunk := response.read(1024 * 1024):
                        count += len(chunk)
                        if count > cap or cancelled.is_set() or time.monotonic() > deadline or shutil.disk_usage(output).free < FREE_FLOOR:
                            raise Invalid('acquisition size/time/free-space budget reached')
                        stream.write(chunk); value.update(chunk)
                if count == 0 or (not suffix and (count != cap or value.hexdigest() != item['sha256_from_metadata'])):
                    raise Invalid('download does not match the reviewed metadata')
            except BaseException:
                path.unlink(missing_ok=True)
                raise
            result['files'].append({'file': path.name, 'bytes': count, 'sha256': value.hexdigest()})
        return result

    def guarded_fetch(item):
        try:
            return fetch(item)
        except BaseException:
            cancelled.set()
            raise

    report = {'status': 'FAIL', 'package_signatures_verified': False, 'release_authorized': False}
    try:
        with ThreadPoolExecutor(max_workers=3) as pool:
            report['packages'] = list(pool.map(guarded_fetch, items))
        report.update(status='ACQUIRED-HASH-MATCHED-NOT-SIGNATURE-VERIFIED', checked_at=datetime.now(timezone.utc).isoformat(),
                      package_count=len(items), total_package_bytes=sum(p['download_bytes_from_metadata'] for p in items))
        return report
    finally:
        (output / 'acquisition.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = acquire(args.plan, args.output)
        print(json.dumps({k: v for k, v in result.items() if k != 'packages'}, indent=2))
    except (Invalid, OSError, ValueError) as exc:
        print(json.dumps({'status': 'FAIL', 'error': str(exc) if isinstance(exc, Invalid) else type(exc).__name__}), file=sys.stderr)
        raise SystemExit(2)
