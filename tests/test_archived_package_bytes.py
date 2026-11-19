"""Historical proof survives scratch cleanup without skipping byte verification."""
import hashlib,tempfile,unittest,sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import reproduce_native_policy as proof

class ArchivedBytes(unittest.TestCase):
    def test_missing_scratch_uses_exact_preserved_bytes_and_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);body=b'exact compressed package fixture';checksum=hashlib.sha256(body).hexdigest()
            cache=root/'research/build-artifacts'/checksum;cache.parent.mkdir(parents=True);cache.write_bytes(body)
            report={'package':str(root/'work/obsolete/package.pkg.tar.zst'),'sha256':checksum,
                    'sources':{},'source_modes':{},'build_inputs':{},'builder_sources':{},
                    'release':108,'source_date_epoch':0,'payload_audit':{}}
            with patch.object(proof,'__file__',str(root/'repos/enzimos-build/reproduce_native_policy.py')):
                self.assertEqual(proof.compare_archived(report,report)['package_sha256'],checksum)
                cache.write_bytes(b'changed')
                with self.assertRaises(proof.Invalid):proof.compare_archived(report,report)
    def test_existing_bad_scratch_and_missing_external_paths_never_use_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);checksum=hashlib.sha256(b'exact').hexdigest()
            cache=root/'research/build-artifacts'/checksum;cache.parent.mkdir(parents=True);cache.write_bytes(b'exact')
            original=root/'work/obsolete/package.pkg.tar.zst';original.parent.mkdir(parents=True);original.write_bytes(b'bad')
            report={'package':str(original),'sha256':checksum,'sources':{},'source_modes':{},
                    'build_inputs':{},'builder_sources':{},'release':108,'source_date_epoch':0,'payload_audit':{}}
            with patch.object(proof,'__file__',str(root/'repos/enzimos-build/reproduce_native_policy.py')):
                with self.assertRaises(proof.Invalid):proof.compare_archived(report,report)
                original.unlink();report['package']=str(root/'external-missing.pkg')
                with self.assertRaises(proof.Invalid):proof.compare_archived(report,report)
