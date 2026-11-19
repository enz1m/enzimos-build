# SPDX-License-Identifier: MIT
"""Explicit native polkit + restricted Flatpak Print portal acceptance."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import cairo
import check as backend


def job_ids():
    return {line.split()[0] for line in backend.run(['lpstat', '-W', 'all', '-o']).stdout.splitlines()}


def ready():
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            if proc.stat().st_uid == 1000 and (proc / 'exe').resolve().name == 'enzui-shell':
                return Path('/run/user/1000/bus').is_socket()
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            pass
    return False


try:
    backend.LAB.mkdir(mode=0o755)
    backend.foundation()
    backend.wait(ready, 600)
    backend.print_queue(check_conversion=False)
    backend.run(['lpadmin', '-d', 'everyday-test'])
    clients = backend.LAB / 'clients'
    clients.mkdir(mode=0o700); os.chown(clients, 1000, 1000)
    def native_client(mode):
        print('ENZIMOS_EVERYDAY_NATIVE_TERMINAL_COMMAND python /run/enzimos-testpayload/gui_client.py ' + mode, flush=True)
        output = clients / (mode + '.json')
        backend.wait(output.is_file, 600)
        assert not output.is_symlink() and output.stat().st_uid == 1000 and output.stat().st_size < 65536
        result = json.loads(output.read_text())
        assert result['uid'] == 1000 and result['mode'] == mode
        print(result['stdout'] + result['stderr'], flush=True)
        return result
    print('ENZIMOS_EVERYDAY_NATIVE_POLKIT_DENY_READY', flush=True)
    rejected = native_client('deny')
    assert 'everyday-ui' not in backend.run(['lpstat', '-p']).stdout
    assert rejected['returncode'] != 0 or rejected['stdout'].strip() not in ["('',)", '("",)']
    print('ENZIMOS_EVERYDAY_NATIVE_POLKIT_ALLOW_READY', flush=True)
    accepted = native_client('allow')
    assert accepted['returncode'] == 0 and accepted['stdout'].strip() in ["('',)", '("",)'], accepted
    assert 'everyday-ui' in backend.run(['lpstat', '-p']).stdout
    backend.run(['lpadmin', '-x', 'everyday-ui'])
    backend.mark('native-polkit-denial-admin-approval-real-printer-add')
    directory = backend.LAB / 'portal'
    directory.mkdir(mode=0o755)
    client = directory / 'portal-client'
    shutil.copyfile(backend.CD / 'portal-client', client)
    client.chmod(0o755)
    document = directory / 'document.pdf'
    surface = cairo.PDFSurface(str(document), 320, 240)
    context = cairo.Context(surface)
    context.move_to(24, 80)
    context.set_font_size(16)
    context.show_text('enzimOS sandbox Print portal')
    surface.finish()
    for mode in ['cancel', 'print']:
        before = job_ids()
        print('ENZIMOS_EVERYDAY_SANDBOX_PRINT_' + mode.upper() + '_READY', flush=True)
        # Existing signed Zen runtime and identity; temporary, narrowly scoped
        # fixture executable/data grant, no CUPS socket and no network namespace.
        # This is an explicit test client, not a claim about Zen's own menu action.
        result = native_client(mode)
        assert result['returncode'] == 0, result
        assert 'ENZIMOS_FLATPAK_NO_DIRECT_CUPS_OR_NETWORK' in result['stdout']
        assert 'ENZIMOS_FLATPAK_PRINT_RESPONSE ' + ('1' if mode == 'cancel' else '0') in result['stdout']
        if mode == 'cancel':
            assert job_ids() == before
        else:
            backend.wait(lambda: len(job_ids() - before) == 1, 30)
            backend.wait(lambda: not backend.run(['lpstat', '-W', 'not-completed', '-o']).stdout.strip(), 60)
        backend.mark('flatpak-fd-print-portal-' + mode + '-no-direct-cups-or-network')
    print('ENZIMOS_EVERYDAY_GUI_PASS', flush=True)
finally:
    backend.cleanup()
