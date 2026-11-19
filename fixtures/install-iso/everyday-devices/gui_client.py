# SPDX-License-Identifier: MIT
"""Run from the actual native Terminal, not a root service's runuser process."""
import json
import os
from pathlib import Path
import subprocess
import sys

LAB = Path('/run/enzimos-everyday-lab')
mode = sys.argv[1]
assert os.getuid() == 1000 and mode in ('deny', 'allow', 'cancel', 'print')
if mode in ('deny', 'allow'):
    command = ['gdbus', 'call', '--system', '--timeout', '150', '--dest', 'org.opensuse.CupsPkHelper.Mechanism',
               '--object-path', '/', '--method', 'org.opensuse.CupsPkHelper.Mechanism.PrinterAdd',
               'everyday-ui', 'ipp://localhost:8631/ipp/print', 'everywhere', 'Everyday UI test', 'Lab']
else:
    directory = LAB / 'portal'
    command = ['flatpak', 'run', '--nosocket=cups', '--unshare=network',
               '--filesystem=' + str(directory) + ':ro', '--command=' + str(directory / 'portal-client'),
               'app.zen_browser.zen', mode, str(directory / 'document.pdf')]
print('Native desktop request: ' + mode, flush=True)
result = subprocess.run(command, capture_output=True, text=True, timeout=220)
print(result.stdout + result.stderr, flush=True)
record = {'mode': mode, 'uid': os.getuid(), 'pid': os.getpid(),
          'session_id': os.environ.get('XDG_SESSION_ID'),
          'returncode': result.returncode, 'stdout': result.stdout[-16000:], 'stderr': result.stderr[-16000:]}
output = LAB / 'clients' / (mode + '.json')
assert not output.exists()
temporary = output.with_suffix('.tmp')
temporary.write_text(json.dumps(record))
temporary.replace(output)
print('ENZIMOS_EVERYDAY_NATIVE_CLIENT_DONE ' + mode, flush=True)
