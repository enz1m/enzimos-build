# SPDX-License-Identifier: MIT
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import factory_shim
from contract import Invalid

class FactoryShimTests(unittest.TestCase):
    def test_unreviewed_source_refused_before_output_or_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'source').write_bytes(b'unreviewed tar');(root/'cert').write_bytes(b'certificate')
            with patch.object(factory_shim.subprocess,'run') as run,self.assertRaises(Invalid):factory_shim.build(root/'source',root/'cert',root/'output')
            run.assert_not_called();self.assertFalse((root/'output').exists())

    def test_private_or_invalid_public_certificate_refused_before_output(self):
        for body in (b'-----BEGIN PRIVATE KEY-----',b'\x30not a certificate'):
            with self.subTest(body=body[:1]),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);source=b'fixture source';(root/'source').write_bytes(source);(root/'cert').write_bytes(body)
                with patch.object(factory_shim,'SHIM_SOURCE_SHA256',hashlib.sha256(source).hexdigest()),patch.object(factory_shim.subprocess,'run') as run,self.assertRaises(Invalid):factory_shim.build(root/'source',root/'cert',root/'output')
                run.assert_not_called();self.assertFalse((root/'output').exists())

if __name__=='__main__':unittest.main()
