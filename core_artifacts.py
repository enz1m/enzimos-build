# SPDX-License-Identifier: MIT
"""Decode only two small named guest core artifacts, then audit before any use."""
import base64
import hashlib
import json
from pathlib import Path
import tarfile
from contract import Invalid, load, digest
from native_package_audit import audit

MAX_ARTIFACT=256*1024


def decode_export(text):
    rows={}
    for line in text.splitlines():
        if not line.startswith('ENZIMOS_CORE_ARTIFACT='):continue
        if len(line)>MAX_ARTIFACT*2:raise Invalid('core export line bound')
        row=json.loads(line.split('=',1)[1]);label=row.get('label')
        if set(row)!={'label','bytes','sha256','base64'} or label not in ('native','backend') or label in rows:raise Invalid('core export identity')
        if type(row['bytes']) is not int or not 0<row['bytes']<MAX_ARTIFACT:raise Invalid('core export size')
        body=base64.b64decode(row['base64'],validate=True)
        if len(body)!=row['bytes'] or hashlib.sha256(body).hexdigest()!=row['sha256']:raise Invalid('core export digest')
        rows[label]=(row,body)
    if set(rows)!={'native','backend'}:raise Invalid('two exact core exports required')
    return rows


def audit_exports(text,inputs,output):
    rows=decode_export(text);output=Path(output);output.mkdir(mode=0o700)
    result={}
    for label,(row,body) in rows.items():
        source=Path(inputs)/'iso-stage'/('core-source-'+label);report=load(source/'original-build.json');entries={}
        for name in ('policy.tar','PKGBUILD','native-policy.install','LICENSE','makepkg.conf'):
            if digest(source/name)!=report['build_inputs'][name]:raise Invalid('core source receipt mismatch')
        with tarfile.open(source/'policy.tar','r:') as archive:
            for member in archive:
                if not member.name.startswith('policy/') or not (member.isfile() or member.isdir()) or member.size>2*1024**2:raise Invalid('core source member')
                name=member.name[len('policy/'):]
                if name in entries or len(entries)>=256:raise Invalid('duplicate/excess core source member')
                entries[name]={'mode':member.mode,'body':archive.extractfile(member).read() if member.isfile() else None}
        if {name:value['mode'] for name,value in entries.items()}!=report['source_modes']:raise Invalid('core source modes differ')
        if {name:hashlib.sha256(value['body']).hexdigest() for name,value in entries.items() if value['body'] is not None}!=report['sources']:raise Invalid('core source bytes differ')
        file=output/(label+'.pkg.tar.zst');file.write_bytes(body)
        checked=audit(file,entries,(source/'LICENSE').read_bytes(),(source/'native-policy.install').read_bytes(),report['release'],
                      package_name='enzimos-native-policy' if label=='native' else 'enzimos-system-backend',
                      recipe=(source/'PKGBUILD').read_text())
        result[label]={'bytes':len(body),'sha256':row['sha256'],'audit':checked}
    return result
