# SPDX-License-Identifier: MIT
"""Pure export-boundary tests; guest bytes never execute on the host."""
import base64
import hashlib
import json
import unittest
from core_artifacts import decode_export, MAX_ARTIFACT
from contract import Invalid


def line(label,body=b'fixture'):
    return 'ENZIMOS_CORE_ARTIFACT='+json.dumps({'label':label,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'base64':base64.b64encode(body).decode()})


class CoreExportTests(unittest.TestCase):
    def test_exact_two_named_exports(self):
        result=decode_export('noise\n'+line('native')+'\n'+line('backend'))
        self.assertEqual(set(result),{'native','backend'})
        self.assertEqual(result['native'][1],b'fixture')

    def test_missing_duplicate_unknown_or_tampered_export(self):
        for text in (line('native'),line('native')+'\n'+line('native'),line('../escape')+'\n'+line('backend'),
                     line('native').replace('fixture','x')+'\n'+line('other'),line('native').replace('"bytes": 7','"bytes": true')+'\n'+line('backend')):
            with self.assertRaises((Invalid,ValueError)):decode_export(text)
        body=json.loads(line('native').split('=',1)[1]);body['sha256']='0'*64
        with self.assertRaisesRegex(Invalid,'digest'):decode_export('ENZIMOS_CORE_ARTIFACT='+json.dumps(body)+'\n'+line('backend'))

    def test_excess_export_before_decode(self):
        with self.assertRaisesRegex(Invalid,'line bound'):decode_export('ENZIMOS_CORE_ARTIFACT='+'x'*(MAX_ARTIFACT*2))


if __name__=='__main__':unittest.main()
