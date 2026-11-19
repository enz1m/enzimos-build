# SPDX-License-Identifier: MIT
import hashlib,json,tempfile,unittest
from pathlib import Path
import ai_payload
class AiPayloadTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.media=self.root/'media';self.media.mkdir();self.rows=[]
  for name in sorted(ai_payload.REQUIRED):
   p=self.root/(name+'.pkg.tar.zst');p.write_bytes(name.encode());self.rows.append({'package_name':name,'package':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
  self.report=self.root/'build.json';self.write()
 def tearDown(self):self.tmp.cleanup()
 def write(self):self.report.write_text(json.dumps({'schema':1,'status':'PASS-ai-packages-built','models_included':False,'packages':self.rows}))
 def test_stage_all_validated(self):
  r=ai_payload.stage(self.report,self.media);self.assertEqual(len(r['packages']),3);self.assertTrue((self.media/'ai-inference-service.pkg.tar.zst').exists())
 def test_tampering_has_no_partial_output(self):
  self.rows[-1]['sha256']='0'*64;self.write()
  with self.assertRaises(ValueError):ai_payload.stage(self.report,self.media)
  self.assertEqual(list(self.media.iterdir()),[])
 def test_unknown_or_incomplete(self):
  self.rows.pop();self.write()
  with self.assertRaises(ValueError):ai_payload.stage(self.report,self.media)
 def test_models_only_in_their_package_and_declared(self):
  p=self.root/'enzimos-ai-models.pkg.tar.zst';p.write_bytes(b'weights')
  self.rows.append({'package_name':'enzimos-ai-models','package':str(p),'sha256':hashlib.sha256(b'weights').hexdigest()});self.write()
  with self.assertRaises(ValueError):ai_payload.stage(self.report,self.media)
  data=json.loads(self.report.read_text());data['models_included']=True;self.report.write_text(json.dumps(data))
  r=ai_payload.stage(self.report,self.media);self.assertTrue(r['models_included']);self.assertTrue((self.media/'ai-ai-models.pkg.tar.zst').exists())
