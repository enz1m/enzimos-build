# SPDX-License-Identifier: MIT
import json
from pathlib import Path
import tempfile
import unittest
from build_install_iso import require_background_mcp
from contract import Invalid

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'build.json'
        self.value={'status':'PASS-mcp-center-package-built','package_name':'enzui-mcp-center','release':9,'files':{'usr/share/enzui/mcp-center/background-policy.json':{'mode':0o644,'sha256':'f3669cc298cd6da9a59626a534f294e1d387cbc40fe27f38ee1b934266836098'}}}
    def admit(self):self.path.write_text(json.dumps(self.value));require_background_mcp(self.path)
    def test_fixed_broker_policy_ABI_is_required_for_background_controls(self):self.admit()
    def test_missing_older_or_forged_policy_descriptor_is_refused(self):
        with self.assertRaises(Invalid):require_background_mcp(None)
        for field,value in [('release',5),('release',True),('status','FAIL'),('package_name','other')]:
            old=self.value[field];self.value[field]=value
            with self.subTest(field=field),self.assertRaises(Invalid):self.admit()
            self.value[field]=old
        marker=self.value['files']['usr/share/enzui/mcp-center/background-policy.json']
        for field,value in [('mode',0o755),('sha256','0'*64)]:
            old=marker[field];marker[field]=value
            with self.subTest(field=field),self.assertRaises(Invalid):self.admit()
            marker[field]=old
