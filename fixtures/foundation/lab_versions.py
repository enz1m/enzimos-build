#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Expected package identities for the bytes under test, read from the patch payload."""
import json
from pathlib import Path

PATCHES=Path('/patches')


def native():
    value=json.loads((PATCHES/'policy-manifest.json').read_text())
    return 'enzimos-native-policy 0.1.0-'+str(int(value['release']))


def backend():
    value=json.loads((PATCHES/'backend-build.json').read_text())
    return 'enzimos-system-backend 0.1.0-'+str(int(value['release']))
