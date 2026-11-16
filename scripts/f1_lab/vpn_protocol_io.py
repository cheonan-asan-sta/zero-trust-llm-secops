"""Pinned legacy model dependency and complete raw VPN source readers."""

import hashlib
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import load_operation_refinement
from scripts.f1_lab.raw_observations import raw_time
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.vpn_risk_retention import RiskRetention


def legacy(path,pin):
    require(sha(path)==pin,'protocol_legacy_manifest_pin')
    value=decode(Path(path).read_bytes())
    require(set(value)=={'schema','models'} and value['schema']=='vpn-legacy-models-1'
        and set(value['models'])=={'web','heads','vpn','policy'},'protocol_legacy_manifest')
    models=value['models']
    for spec in models.values():
        require(set(spec)=={'path','sha256'} and sha(spec['path'])==spec['sha256'],'protocol_legacy_weight_pin')
    identity=hashlib.sha256(canonical({k:v['sha256'] for k,v in models.items()})).hexdigest()
    base=load_operation_refinement(models['policy']['path'],models['policy']['sha256'],
        models['web']['path'],models['web']['sha256'],models['heads']['path'],models['heads']['sha256'],
        models['vpn']['path'],models['vpn']['sha256'])
    return RiskRetention(base),identity


def records(raw_directory,preparation):
    raw=Path(raw_directory)
    require(sha(raw/'audit.json')==preparation['source_manifest_sha256'],'protocol_raw_manifest_pin')
    manifest=decode((raw/'audit.json').read_bytes())
    require(manifest['completed'] is True and manifest['timestamp_basis']==
        'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check','protocol_timezone')
    result={};pins={}
    for index,pair in enumerate(preparation['pairs']):
        # Only exact sources are admitted; rotated sources need a separate
        # declared intake and remain in the baseline when not admitted here.
        if not pair['raw_member'].endswith('/openvpn.log'):continue
        provenance=manifest['pairs'][index]['provenance']
        require(all(provenance[k]==pair[k] for k in ('raw_member','raw_sha256')),'protocol_source_binding')
        path=raw/f'pair-{index}-raw.source';require(sha(path,64*1024**2)==pair['raw_sha256'],'protocol_raw_pin')
        pins[path]=pair['raw_sha256'];rows=[];time_errors=0
        with path.open('rb') as stream:
            for ordinal,body in enumerate(stream,1):
                require(len(body)<=MAX_ROW and ordinal<=100000,'protocol_source_bound')
                try:
                    line=body.decode('utf8');moment=raw_time(line,provenance['simulation_start'],
                        provenance['simulation_end'],source_timezone='UTC')
                except (UnicodeError,ValueError,RecursionError):line,moment='',None;time_errors+=1
                rows.append((ordinal,moment,line))
        require(len(rows)==pair['rows'],'protocol_source_population')
        result[index]=(pair['raw_sha256'],rows,time_errors)
    require(all(sha(p)==pin for p,pin in pins.items()),'protocol_source_drift')
    return result
