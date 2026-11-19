# SPDX-License-Identifier: MIT
"""Shipped AppArmor confinement of the NAS (SMB) Restic roles."""
from pathlib import Path
import re
import unittest

PACKAGES=Path(__file__).resolve().parents[2]/'enzimos-packages'
REMOTE=('enzimos-restic-native-replicate','enzimos-restic-native-retrieve','enzimos-restic-native-remote-rotation-read',
        'enzimos-restic-native-remote-initialize','enzimos-restic-native-remote-check')


class RemoteProfileTests(unittest.TestCase):
    def test_remote_restic_roles_cannot_read_the_share_password_or_use_the_network(self):
        # Only the worker's mount child reads the SMB share password; Restic reaches
        # the NAS through that private kernel mount, never through a socket of its own.
        text=(PACKAGES/'native-policy/root/etc/apparmor.d/enzimos-restic').read_text()
        for name in REMOTE:
            body=re.search(r'^profile '+re.escape(name)+r' [^{]*\{\n(.*?)^\}',text,re.M|re.S)
            self.assertTrue(body,name)
            rules=body.group(1)
            self.assertIn('deny /etc/enzimos/backup-remote.share-password r,',rules,name)
            self.assertIn('audit deny network,',rules,name)
            self.assertNotRegex(rules,r'^\s*network\b',name)
            self.assertNotIn(' Cx ',rules,name)
            self.assertRegex(rules,r'/backup-remote/\*\* r',name)


if __name__=='__main__':unittest.main()
