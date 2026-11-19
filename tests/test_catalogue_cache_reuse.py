# SPDX-License-Identifier: MIT
import errno
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from foundation_catalogue import reuse_file

class Tests(unittest.TestCase):
    def test_cross_device_cache_copy_preserves_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'package';source.write_bytes(b'authenticated package bytes')
            with patch('foundation_catalogue.os.link',side_effect=OSError(errno.EXDEV,'different filesystem')):
                reuse_file(source,root/'copy')
            self.assertEqual((root/'copy').read_bytes(),source.read_bytes())
    def test_unrelated_link_error_is_not_silently_retried(self):
        with patch('foundation_catalogue.os.link',side_effect=PermissionError(errno.EACCES,'refused')),patch('foundation_catalogue.shutil.copyfile') as copy:
            with self.assertRaises(PermissionError):reuse_file('source','target')
            copy.assert_not_called()
