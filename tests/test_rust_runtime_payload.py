# SPDX-License-Identifier: MIT
import hashlib,io,json,tarfile,tempfile,unittest
from pathlib import Path
from contract import Invalid
from rust_runtime_payload import COMPONENTS,COUNTS,owned_paths,stage
from build_install_iso import desktop_archive

class RuntimePayloadTests(unittest.TestCase):
    def fixture(self,root,mutate=None,versions=None):
        repos=root/'repos';records={}
        for component,name in COMPONENTS.items():
            binaries={f'bin-{n}':f'usr/lib/{component}/bin-{n}' for n in range(COUNTS[component])}
            resource=f'usr/lib/{component}/launch.sh'
            spec={'binaries':binaries,'resources':{'launch':{'target':resource,'mode':0o755}}}
            recipe=repos/('enzimos-'+component)/'packaging/rust';recipe.mkdir(parents=True)
            (recipe/'runtime.json').write_text(json.dumps(spec))
            payload={path:b'\x7fELFfixture-'+binary.encode() for binary,path in binaries.items()}
            payload[resource]=b'#!/usr/bin/bash\nexec native\n'
            binding={'schema':1,'component':component,'automatic_activation':False,'production_cutover':False,
                     'artifacts':{binary:{'bytes':len(payload[path]),'sha256':hashlib.sha256(payload[path]).hexdigest()} for binary,path in binaries.items()},
                     'resources':{resource:{'mode':0o755,'sha256':hashlib.sha256(payload[resource]).hexdigest()}}}
            binding_path=f'usr/share/enzimos/rust-candidates/{component}/build.json'
            license_path=f'usr/share/licenses/{name}/LICENSE'
            payload[binding_path]=json.dumps(binding).encode();payload[license_path]=b'MIT\n'
            if mutate and component=='packages':mutate(payload,binaries)
            package=root/(component+'.pkg.tar.zst')
            version=(versions or {}).get(component, '0.2.0-2' if component=='packages' else '0.2.0-1')
            with tarfile.open(package,'w:zst') as archive:
                entries={'.PKGINFO':f'pkgname = {name}\npkgver = {version}\narch = x86_64\n'.encode(),**payload}
                for path,data in entries.items():
                    info=tarfile.TarInfo(path);info.size=len(data);info.mode=0o644 if path in (binding_path,license_path,'.PKGINFO','.INSTALL') else 0o755
                    archive.addfile(info,io.BytesIO(data))
            records[component]={'package_name':name,'package':f'work/{root.name}/{package.name}' if component == 'packages' else package.name,'sha256':hashlib.sha256(package.read_bytes()).hexdigest(),'version':version,'automatic_activation':False,'elf_count':COUNTS[component]}
        summary=root/'summary.json';summary.write_text(json.dumps({'result':'PASS','packages':records,'elf_count':sum(COUNTS.values()),'automatic_activation':False}))
        media=root/'media';media.mkdir()
        return summary,media,repos
    def test_complete_five_component_offline_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.fixture(Path(tmp));result=stage(*args)
            self.assertEqual(set(result),set(COMPONENTS));self.assertEqual(len(list(args[1].iterdir())),5)
            self.assertTrue(all(v['automatic_activation'] is False for v in result.values()))
            self.assertEqual(result['packages']['release'], 2)
            self.assertEqual(result['installer']['release'], 1)
            desktop = Path(tmp)/'desktop'
            native = desktop/'usr/lib/installer/bin-0'
            native.parent.mkdir(parents=True);native.write_bytes(b'old helper')
            resource = desktop/'usr/lib/installer/launch.sh';resource.write_bytes(b'old wrapper')
            ui = desktop/'usr/share/enzui/SOURCE-REVISION'
            ui.parent.mkdir(parents=True);ui.write_text('current desktop\n')
            desktop_archive(desktop, args[1], owned_paths(args[2]))
            with tarfile.open(args[1]/'desktop-preview.tar.zst', 'r:zst') as archive:
                files = {str(Path(member.name)): archive.extractfile(member).read()
                         for member in archive if member.isfile()}
            self.assertEqual(files, {'usr/share/enzui/SOURCE-REVISION': b'current desktop\n'})
    def test_only_installer_can_advance_to_0_2_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp), versions={'installer': '0.2.1-1'})
            installer = stage(*args)['installer']
            self.assertEqual((installer['version'], installer['release']), ('0.2.1', 1))
        with tempfile.TemporaryDirectory() as tmp:
            args = self.fixture(Path(tmp), versions={'updates': '0.2.1-1'})
            with self.assertRaisesRegex(Invalid, 'paired Rust runtime package identity'):
                stage(*args)

    def test_package_hooks_cannot_enter_copy_only_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.fixture(Path(tmp),lambda p,b:p.update({'.INSTALL':b'unsafe'}))
            with self.assertRaises(Invalid):stage(*args)
    def test_rehashed_foreign_backend_elf_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.fixture(Path(tmp),lambda p,b:p.update({next(iter(b.values())):b'\x7fELFforeign'}))
            with self.assertRaises(Invalid):stage(*args)
    def test_missing_backend_elf_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.fixture(Path(tmp),lambda p,b:p.pop(next(iter(b.values()))))
            with self.assertRaises(Invalid):stage(*args)
    def test_incomplete_component_set_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=self.fixture(Path(tmp));summary=json.loads(args[0].read_text());summary['packages'].pop('updates');args[0].write_text(json.dumps(summary))
            with self.assertRaises(Invalid):stage(*args)
