# SPDX-License-Identifier: MIT
"""Offline parser/lifecycle boundaries; real cryptographic/firmware lab is explicit."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import factory_boot as boot
from contract import Invalid


def image(role='normal', command='lockdown=integrity quiet', generation=1):
    upstream='shim' if role=='shim' else 'systemd'
    parts={'.text':b'fixture executable', '.sbat':f'sbat,1,SBAT,sbat,1,https://example.com\n{upstream},1,upstream,upstream,1,https://example.com\n{role}.enzimos,{generation},enzimOS,component,1,https://example.com\n'.encode()}
    if role in boot.UKIS:parts.update({'.linux':b'kernel', '.initrd':b'initrd', '.cmdline':command.encode()+b'\0'})
    body=bytearray(4096);body[:2]=b'MZ';struct.pack_into('<I',body,60,64);body[64:68]=b'PE\0\0'
    struct.pack_into('<HH',body,68,0x8664,len(parts));struct.pack_into('<H',body,84,240)
    start=88;struct.pack_into('<H',body,start,0x20b);struct.pack_into('<HH',body,start+68,10,0x100)
    struct.pack_into('<I',body,start+108,16);struct.pack_into('<II',body,start+144,4080,16)
    for i,(name,value) in enumerate(parts.items()):
        p=start+240+i*40;body[p:p+8]=name.encode().ljust(8,b'\0');raw=1024+i*256
        struct.pack_into('<IIII',body,p+8,len(value),raw,256,raw);body[raw:raw+len(value)]=value
    struct.pack_into('<IHH',body,4080,16,0x200,2)
    return bytes(body)


class FactoryBootTests(unittest.TestCase):
    def fixture(self, folder):
        certs={}
        for name in ('firmware','vendor'):
            body=b'-----BEGIN CERTIFICATE-----\n'+name.encode()+b'\n-----END CERTIFICATE-----\n'
            (folder/(name+'.pem')).write_bytes(body)
            certs[name]={'file':name+'.pem','sha256':hashlib.sha256(body).hexdigest()}
        records={}
        for role in boot.ROLES:
            body=image(role);(folder/(role+'.efi')).write_bytes(body)
            records[role]={'file':role+'.efi','sha256':hashlib.sha256(body).hexdigest(),'vendor_sbat':role+'.enzimos'}
        value={'schema':1,'purpose':'lab','certificates':certs,'sbat_minimum':{r+'.enzimos':1 for r in boot.ROLES},'artifacts':records}
        path=folder/'policy.json';path.write_text(json.dumps(value));return value,path

    def test_pe_architecture_nx_certificate_and_overlaps(self):
        self.assertIn('.linux',boot.pe(image()))
        for offset,fmt,value in [(68,'H',0x14c),(88,'H',0x10b),(158,'H',0),(232,'I',4081),(236,'I',9999),(4084,'H',0x100),(4086,'H',1),(388,'I',1024)]:
            b=bytearray(image());struct.pack_into('<'+fmt,b,offset,value)
            with self.subTest(offset=offset),self.assertRaises(Invalid):boot.pe(bytes(b))
        with self.assertRaises(Invalid):boot.pe(image()[:-1])

    def test_sbat_malformed_duplicate_and_generation(self):
        for b in [b'',b'bad\n',b'sbat,1,A,B,C,D\nfoo,1,A,B,C,D\nfoo,1,A,B,C,D\n',b'sbat,1,A,B,C,D\nfoo,0,A,B,C,D\nbar,1,A,B,C,D\n',b'sbat,1,A,B,C,D\nfoo,1,A,B,C,D\nbar,1,A,B,C,D']:
            with self.assertRaises(Invalid):boot.sbat(b)

    def test_prepare_complete_snapshot_no_keys_and_no_authorization(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);folder=root/'inputs';folder.mkdir();value,p=self.fixture(folder)
            seen=[]
            def verify(path,cert,verifier):
                self.assertFalse(path.is_relative_to(folder));seen.append(path.read_bytes())
                self.assertIn(cert.read_bytes(),[(folder/'vendor.pem').read_bytes(),(folder/'firmware.pem').read_bytes()])
            with patch.object(boot,'verify_signature',side_effect=verify),patch.object(boot,'digest',return_value='verifier-sha'):
                result=boot.prepare(folder,p,Path('/fixture-verifier'),root/'bundle')
            self.assertEqual(len(seen),6);self.assertFalse(result['release_authorized']);self.assertFalse(result['factory_firmware_qualified'])
            self.assertEqual(set(result['artifacts']),set(boot.ROLES))
            self.assertEqual((root/'bundle/EFI/BOOT/BOOTX64.EFI').read_bytes(),image('shim'))
            self.assertFalse(list((root/'bundle').rglob('*.key')))

    def test_bad_hash_and_revocation_create_no_output(self):
        for kind in ('digest','certificate','revoked','missing-role','duplicate-file','authority','private-key','symlink','foreign-write'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);folder=root/'inputs';folder.mkdir();v,p=self.fixture(folder)
                if kind=='digest':v['artifacts']['normal']['sha256']='0'*64
                if kind=='certificate':v['certificates']['vendor']['sha256']='0'*64
                if kind=='revoked':v['sbat_minimum']['normal.enzimos']=2
                if kind=='missing-role':del v['artifacts']['recovery']
                if kind=='duplicate-file':v['artifacts']['normal']['file']='shim.efi'
                if kind=='authority':v['purpose']='release-authorized'
                if kind=='private-key':
                    body=b'-----BEGIN PRIVATE KEY-----\nfixture';(folder/'vendor.pem').write_bytes(body);v['certificates']['vendor']['sha256']=hashlib.sha256(body).hexdigest()
                if kind=='symlink':(folder/'normal.efi').unlink();(folder/'normal.efi').symlink_to(folder/'lts.efi')
                if kind=='foreign-write':(folder/'normal.efi').chmod(0o666)
                p.write_text(json.dumps(v))
                with patch.object(boot,'verify_signature'),self.assertRaises(Invalid):boot.prepare(folder,p,Path('/fixture'),root/'bundle')
                self.assertFalse((root/'bundle').exists())

    def test_command_line_bypass_refused(self):
        for command in ('quiet','lockdown=none','lockdown=integrity lockdown=none','lockdown=integrity initrd=/evil','lockdown=integrity init=/bin/sh','lockdown=integrity rdinit=/shell','lockdown=integrity module.sig_enforce=0'):
            with self.subTest(command=command),tempfile.TemporaryDirectory() as temp:
                folder=Path(temp);v,p=self.fixture(folder);b=image(command=command);(folder/'normal.efi').write_bytes(b);v['artifacts']['normal']['sha256']=hashlib.sha256(b).hexdigest();p.write_text(json.dumps(v))
                with patch.object(boot,'verify_signature'),self.assertRaises(Invalid):boot.inspect(folder,p,Path('/fixture'))

    def test_signature_refusal_and_existing_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);folder=root/'inputs';folder.mkdir();v,p=self.fixture(folder)
            with patch.object(boot,'verify_signature',side_effect=Invalid('bad signature')),self.assertRaises(Invalid):boot.prepare(folder,p,Path('/fixture'),root/'bundle')
            self.assertFalse((root/'bundle').exists())
            with patch.object(boot,'verify_signature'),patch.object(boot,'digest',return_value='fixture'),self.assertRaises(Invalid):boot.prepare(folder,p,Path('/fixture'),folder)

    def test_rotation_rejects_dropped_or_decreased_revocation_and_lab_relabel(self):
        with tempfile.TemporaryDirectory() as temp:
            previous,_=self.fixture(Path(temp))
            for mutation in ('drop','decrease','relabel'):
                current=copy.deepcopy(previous)
                if mutation=='drop':del current['sbat_minimum']['normal.enzimos']
                elif mutation=='decrease':
                    previous['sbat_minimum']['systemd']=2;current['sbat_minimum']['systemd']=1
                else:current['purpose']='submission-preparation'
                with self.subTest(mutation=mutation),self.assertRaises(Invalid):boot.check_transition(previous,current)
            current=copy.deepcopy(previous);current['sbat_minimum']['normal.enzimos']=2
            self.assertEqual(boot.check_transition(previous,current)['status'],'PASS-monotonic-policy-preparation')

    def test_unsigned_and_older_sbat_retained_cannot_be_admitted(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp);v,p=self.fixture(folder)
            v['sbat_minimum']['systemd']=2;p.write_text(json.dumps(v))
            with patch.object(boot,'verify_signature'),self.assertRaises(Invalid):boot.inspect(folder,p,Path('/fixture'))
        b=bytearray(image());struct.pack_into('<II',b,232,0,0)
        with self.assertRaises(Invalid):boot.pe(bytes(b))

if __name__=='__main__':unittest.main()
