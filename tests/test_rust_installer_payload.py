# SPDX-License-Identifier: MIT
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from contract import Invalid
from rust_installer_payload import BINARIES, WRAPPERS, MANIFEST, LICENSE, stage

class InstallerPayloadTests(unittest.TestCase):
    def fixture(self, root, change=None):
        installer=root/'live';installer.mkdir()
        payload={p:b'#!/usr/bin/bash\nexec native\n' for p in WRAPPERS}
        payload.update({p:b'\x7fELFpaired-byte-fixture' for p in BINARIES.values()})
        payload[LICENSE]=b'MIT\n'
        binding={'component':'installer','automatic_activation':False,'production_cutover':False,
                 'source_heads':{},'artifacts':{name:{'sha256':hashlib.sha256(payload[path]).hexdigest(),'bytes':len(payload[path])} for name,path in BINARIES.items()},
                 'resources':{path:{'sha256':hashlib.sha256(payload[path]).hexdigest(),'mode':0o755} for path in WRAPPERS}}
        payload[MANIFEST]=json.dumps(binding).encode()
        wrappers=root/'packaging/rust/live';wrappers.mkdir(parents=True)
        for path in WRAPPERS:(wrappers/Path(path).stem).write_bytes(payload[path])
        if change:change(payload)
        package=root/'installer.pkg.tar.zst'
        with tarfile.open(package,'w:zst') as archive:
            members={'.PKGINFO':b'pkgname = enzimos-rust-installer\npkgver = 0.2.0-1\narch = x86_64\n',**payload}
            for path,data in members.items():
                info=tarfile.TarInfo(path);info.size=len(data)
                info.mode=0o755 if path in WRAPPERS or path in BINARIES.values() else 0o644
                archive.addfile(info,io.BytesIO(data))
        record={'package_name':'enzimos-rust-installer','package':str(package),'sha256':hashlib.sha256(package.read_bytes()).hexdigest(),'version':'0.2.0-1','automatic_activation':False,'elf_count':2,'resource_count':3}
        summary=root/'summary.json';summary.write_text(json.dumps({'result':'PASS','packages':{'installer':record}}))
        out=root/'admitted';out.mkdir()
        return summary,out,installer
    def test_paired_installer_and_all_three_current_wrappers(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.fixture(Path(tmp));result=stage(*args)
            self.assertFalse(result['production_cutover'])
            self.assertTrue(Path(result['package']).is_file())
    def test_rejects_replaced_elf(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.fixture(Path(tmp),lambda p:p.update({next(iter(BINARIES.values())):b'\x7fELFforeign'}))
            with self.assertRaises(Invalid):stage(*args)
    def test_rejects_current_wrapper_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.fixture(Path(tmp));(args[2].parent/'packaging/rust/live/ui-install').write_text('old Python wrapper')
            with self.assertRaises(Invalid):stage(*args)
    def test_rejects_archive_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.fixture(Path(tmp),lambda p:p.update({'../escape':b'x'}))
            with self.assertRaises(Invalid):stage(*args)
    def test_rejects_missing_paired_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.fixture(Path(tmp),lambda p:p.pop(BINARIES['enzimos-installer-package-worker']))
            with self.assertRaises(Invalid):stage(*args)
    def test_rejects_package_bytes_changed_after_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.fixture(Path(tmp));(Path(tmp)/'installer.pkg.tar.zst').write_bytes(b'foreign')
            with self.assertRaises(Invalid):stage(*args)
