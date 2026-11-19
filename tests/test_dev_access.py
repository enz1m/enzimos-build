# SPDX-License-Identifier: MIT
import os,tempfile,unittest
from pathlib import Path
from unittest import mock
import build_install_iso,dev_access
INSTALLER_MENU=Path(__file__).resolve().parents[2]/'enzimos-installer/live/limine.conf'
class DevAccessTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.key=Path(self.tmp.name)/'id.pub';self.key.write_text('ssh-ed25519 AAAAC3Nza test\n')
 def tearDown(self):self.tmp.cleanup()
 def test_development_build_takes_the_key(self):
  with mock.patch.dict(os.environ,{'ENZIMOS_DEV_SSH_KEY':str(self.key)},clear=True):
   self.assertEqual(dev_access.key(),'ssh-ed25519 AAAAC3Nza test')
 def test_release_build_refuses_the_key(self):
  with mock.patch.dict(os.environ,{'ENZIMOS_DEV_SSH_KEY':str(self.key),'ENZIMOS_RELEASE':'1'},clear=True):
   with self.assertRaises(ValueError):dev_access.key()
  with mock.patch.dict(os.environ,{'ENZIMOS_RELEASE':'1'},clear=True):self.assertIsNone(dev_access.key())
 @unittest.skipUnless(INSTALLER_MENU.exists(),'installer checkout beside this repository')
 def test_live_menu_marks_development_access_only(self):
  menu=INSTALLER_MENU.read_text()
  self.assertNotIn('development',menu)
  self.assertIn('\n/Install enzimOS (development access)\n',build_install_iso.live_menu(menu,True))
  self.assertEqual(build_install_iso.live_menu(menu,False),menu)
  with self.assertRaises(ValueError):build_install_iso.live_menu('/Other\n',True)
if __name__=='__main__':unittest.main()
