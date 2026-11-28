# SPDX-License-Identifier: MIT
"""Explicit local AI package staging for development installation media."""
import hashlib,json,shutil
from pathlib import Path
NAMES={'enzimos-inference-service','enzimos-ai-gateway','enzimos-dictation','enzimos-llama-cpu','enzimos-llama-vulkan','enzimos-whisper-cpu','enzimos-sherpa-onnx-cpu','enzimos-ai-models','enzimos-streaming-speech'}
LIMITS={'enzimos-ai-models':2*1024*1024*1024}
REQUIRED={'enzimos-inference-service','enzimos-ai-gateway','enzimos-llama-cpu'}
def stage(report_path,media):
    report=json.loads(Path(report_path).read_text());rows=report.get('packages',[])
    names=[row.get('package_name') for row in rows]
    models='enzimos-ai-models' in names
    if report.get('schema')!=1 or report.get('status')!='PASS-ai-packages-built' or report.get('models_included') is not models:raise ValueError('reviewed AI package build required (models only in enzimos-ai-models)')
    if len(names)!=len(set(names)) or not REQUIRED<=set(names)<=NAMES:raise ValueError('invalid AI package set')
    if 'enzimos-streaming-speech' in names and 'enzimos-dictation' not in names:
        raise ValueError('streaming speech requires the dictation client')
    verified=[]
    for row in rows:
        p=Path(row['package']).resolve(strict=True)
        if not p.is_file() or p.stat().st_size>LIMITS.get(row['package_name'],256*1024*1024):raise ValueError('invalid AI package artifact')
        with p.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
        if digest!=row['sha256']:raise ValueError('AI package digest mismatch')
        verified.append((row,p))
    # No destination mutation until every package has passed validation.
    results=[]
    for row,p in verified:
        name='ai-'+row['package_name'].removeprefix('enzimos-');dest=Path(media)/(name+'.pkg.tar.zst');shutil.copyfile(p,dest);results.append({'package_name':row['package_name'],'media_file':dest.name,'sha256':row['sha256']})
    result={'schema':1,'packages':results,'models_included':models,'release_authorized':False}
    (Path(media)/'ai-packages.json').write_text(json.dumps(result,indent=2)+'\n');return result
