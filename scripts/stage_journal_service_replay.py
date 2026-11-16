"""Stage complete baseline/audit rows plus pinned label-free journal sidecars."""

import argparse
import json
import re
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha
from scripts.stage_vpn_protocol_replay import stage as base_stage

JOURNAL_FIELDS={'__REALTIME_TIMESTAMP','_SOURCE_REALTIME_TIMESTAMP','_BOOT_ID','_MACHINE_ID','_HOSTNAME',
    '_TRANSPORT','_AUDIT_ID','MESSAGE','_PID','_UID','_CMDLINE','_EXE','UNIT','JOB_TYPE','INVOCATION_ID',
    '_SYSTEMD_UNIT','_SYSTEMD_INVOCATION_ID'}


def stage(catalog_path,pin,output):
    report=base_stage(catalog_path,pin,output,profile='apparmor-causal')
    report['completed']=False
    (Path(output)/'stage.json').write_bytes(canonical(report)+b'\n')
    catalog=decode(Path(catalog_path).read_bytes());support=catalog.get('journal_support')
    require(type(support) is list and 1<=len(support)<=64,'journal_support_scope')
    scenarios={s['name']:s for s in catalog['scenarios']}
    out=Path(output);inputs=out/'inputs';folder=inputs/'journal';folder.mkdir()
    members=[];total=0;seen=set()
    for n,spec in enumerate(support):
        require(set(spec)=={'scenario','source_index','raw_source_sha256','member','path','sha256','binary_path',
            'binary_sha256','archive_sha256','hostname'},'journal_support_fields')
        name=spec['scenario'];index=spec['source_index']
        require(name in scenarios and type(index) is int and index>=0,'journal_support_scenario')
        prep=decode(Path(scenarios[name]['preparation']).read_bytes())
        require(index<len(prep['pairs']) and prep['pairs'][index]['raw_member'].endswith('/internal_share/logs/audit/audit.log')
            and prep['pairs'][index]['raw_sha256']==spec['raw_source_sha256'],'journal_support_audit_binding')
        match=re.fullmatch(r'gather/internal_share/logs/journal/([a-f0-9]{32})/[^/]{1,255}[.]journal',spec['member'])
        require(match is not None and spec['hostname']=='internal-share' and re.fullmatch('[a-f0-9]{64}',spec['archive_sha256']),
            'journal_support_host')
        path=Path(spec['path']);binary=Path(spec['binary_path'])
        require(sha(path,64*1024**2)==spec['sha256'] and sha(binary,32*1024**2)==spec['binary_sha256'],
            'journal_support_pin')
        key=(name,index,spec['sha256']);require(key not in seen,'journal_support_duplicate');seen.add(key)
        total+=path.stat().st_size;require(total<=128*1024**2,'journal_support_total_bytes')
        target=folder/f'member-{n}.jsonl';count=0
        with path.open('rb') as source,target.open('xb') as destination:
            while body:=source.readline(MAX_ROW+1):
                count+=1;require(len(body)<=MAX_ROW and count<=100000,'journal_support_row_bound')
                row=decode(body)
                destination.write(canonical({k:row[k] for k in JOURNAL_FIELDS if k in row})+b'\n')
        members.append({'scenario':name,'source_index':index,'raw_source_sha256':spec['raw_source_sha256'],
            'path':'/inputs/journal/'+target.name,'sha256':sha(target),'original_decoded_sha256':spec['sha256'],
            'physical_rows':count,'member':spec['member'],
            'binary_sha256':spec['binary_sha256'],'archive_sha256':spec['archive_sha256'],
            'machine_id':match[1],'hostname':spec['hostname']})
        report['source_pins'].extend({'path':str(p),'sha256':sha(p)} for p in (path,binary))
    (inputs/'journal-catalog.json').write_bytes(canonical({'schema':'journal-service-sidecars-1',
        'goal_qualified':False,'members':members})+b'\n')
    # The base stager supplies audit/auth bytes; this pipeline has no model.
    (inputs/'models/head.json').unlink()
    require(all(sha(p['path'])==p['sha256'] for p in report['source_pins']),'journal_support_source_drift')
    report.update(completed=True,profile='journal-service',model_sha256=None,journal_catalog_sha256=sha(inputs/'journal-catalog.json'),
        input_pins={p.relative_to(inputs).as_posix():sha(p) for p in inputs.rglob('*') if p.is_file()})
    (out/'stage.json').write_bytes(canonical(report)+b'\n');return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('catalog','sha256','output'):parser.add_argument('--'+name,required=True)
    a=parser.parse_args();r=stage(a.catalog,a.sha256,a.output)
    print(json.dumps({'completed':r['completed'],'goal_qualified':False}));return 0


if __name__=='__main__':raise SystemExit(main())
