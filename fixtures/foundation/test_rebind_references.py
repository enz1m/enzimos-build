#!/usr/bin/python
# SPDX-License-Identifier: MIT
"""Real completed rebind journal references stay protective; no deletion."""
from pathlib import Path
import boot_inventory as boot
import generation_registry as registry
import native
import root_rebind


def qualify(check):
    check(native.output(['pacman','-Q','enzimos-native-policy'])=='enzimos-native-policy 0.1.0-42','wrong rebind reference candidate')
    folder=root_rebind.journal_directory();journals={p.stem:root_rebind.load_journal(p) for p in folder.glob('*.json')}
    check(journals and all(v['phase']=='complete' for v in journals.values()),'completed real rebind journals required')
    before={str(p):native.sha(p) for p in folder.glob('*.json')};inventory=native.output(['pacman','-Q']);authority=native.authority_identity()
    report=boot.collect();graph=report['recovery_references'];check(graph is not None,'rebind graph missing')
    edges={(row['source'],row['target'],row['reason']) for row in graph['edges']}
    for identifier,value in journals.items():
        key='rebind:'+identifier
        check(key in graph['nodes'],'completed journal not protected')
        for role in ('source','target'):check((key,'root:'+value[role]['uuid'],'rebind-'+role) in edges,'rebind root reference lost')
        for side in ('before_catalog','after_catalog'):
            for name,record in value[side]['generations'].items():
                for item in record['material']['files']:
                    check((key,'boot:/enzimos/generations/'+name+'/'+item['name'],'rebind-'+side+'-artifact') in edges,'journal artifact not retained')
    partial=folder/'.unresolved-reference.tmp';partial.write_text('interrupted');partial.chmod(0o600)
    try:
        blocked=boot.collect()
        check(blocked['recovery_references'] is None and any('interrupted rebind journal' in v for v in blocked['blockers']),'orphan journal ignored')
    finally:partial.unlink()
    check({str(p):native.sha(p) for p in folder.glob('*.json')}==before,'journal bytes changed')
    check(native.output(['pacman','-Q'])==inventory and native.authority_identity()==authority,'graph changed packages/authority')
    check(not graph['complete'] and not graph['execution_available'],'journal graph authorized retirement')
    return {'real_completed_rebind_roots_linked':True,'before_after_artifacts_protected':True,
            'orphan_reference_blocks':True,'journal_packages_authority_preserved':True,'retirement_enabled':False}
