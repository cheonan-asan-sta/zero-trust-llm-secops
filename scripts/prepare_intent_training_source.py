"""Bounded exact publisher audit/auth pairs for declared development training."""

import argparse
import hashlib
import json
import os
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from scripts.f1_lab.audit_member_transfer import select_pairs
from scripts.f1_lab.bounded_zip import fingerprint, inspect
from scripts.f1_lab.line_truth import annotations
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha
from scripts.prepare_transfer_source import timezone


def prepare(plan_path, pin, output):
    require(sha(plan_path)==pin,'intent_intake_plan_pin')
    plan=decode(Path(plan_path).read_bytes())
    require(plan['schema']=='audit-intent-training-intake-1' and plan['role']=='training'
            and plan['goal_qualified'] is False and plan['metadata_source']=='https://zenodo.org/records/19483937'
            and re.fullmatch('[a-z]{1,32}',plan['name']) is not None
            and type(plan['simulation_start']) is int and type(plan['simulation_end']) is int
            and 0<=plan['simulation_start']<plan['simulation_end']<4102444800,'intent_intake_scope')
    require(sha(plan['acquisition'])==plan['acquisition_sha256'],'intent_intake_acquisition_pin')
    acquisition=decode(Path(plan['acquisition']).read_bytes())
    asset=acquisition['asset'];archive=Path(plan['archive'])
    require(acquisition['completed'] is True and acquisition['publisher_md5_verified'] is True
            and asset['record_id']==19483937 and asset['record_version']=='v2_1'
            and asset['license_id']=='cc-by-nc-sa-4.0'
            and asset['filename']==plan['name']+'_no-pcaps.zip' and archive.name==asset['filename']
            and archive.stat().st_size==asset['bytes'],'intent_intake_publisher')
    pin_archive=acquisition['local_sha256']
    inventory=inspect(archive,pin_archive)
    selected,excluded=select_pairs(inventory['entries'],[])
    out=Path(output);out.mkdir(parents=True,exist_ok=False);raw=out/'raw';raw.mkdir()
    labels=out/'labels';labels.mkdir()
    report={'completed':False,'role':'training','goal_qualified':False,'new_independent_evaluation':False,
        'intake_plan_sha256':pin,'archive_sha256':pin_archive,'pairs':selected,'excluded_unpaired':excluded}
    (out/'selected.json').write_bytes(canonical(report)+b'\n')
    ledger=out/'training-access.jsonl'
    def access(phase,member):
        with ledger.open('ab') as stream:
            stream.write(canonical({'phase':phase,'member':member,'at':datetime.now(UTC).isoformat(),
                'role':'training','archive_sha256':pin_archive,'intake_plan_sha256':pin})+b'\n')
            stream.flush();os.fsync(stream.fileno())
    access('metadata_selection_frozen',sha(out/'selected.json'))
    copied={}
    with archive.open('rb') as stream:
        require(fingerprint(stream)==pin_archive,'intent_intake_archive_before');stream.seek(0)
        with zipfile.ZipFile(stream) as package:
            def copy(member,target,phase):
                require(not target.exists() and not target.is_symlink(),'intent_intake_fresh_member')
                info=package.getinfo(member);require(info.file_size<=64*1024**2,'intent_intake_member_size')
                access(phase,member);size=0;digest=hashlib.sha256()
                with package.open(info) as source,target.open('xb') as destination:
                    while body:=source.read(1024**2):
                        size+=len(body);require(size<=64*1024**2,'intent_intake_member_bound')
                        destination.write(body);digest.update(body)
                require(size==info.file_size,'intent_intake_member_population')
                copied[member]={'sha256':digest.hexdigest(),'bytes':size,'zip_crc_verified_at_eof':True}
            hosts={}
            for i,pair in enumerate(selected):
                facts=pair['facts_member']
                if facts not in hosts:
                    path=raw/f'host-{len(hosts)}.metadata';copy(facts,path,'timezone_metadata')
                    require(path.stat().st_size<=4*1024**2,'intent_intake_facts_bound')
                    hosts[facts]=timezone(decode(path.read_bytes()))
                copy(pair['raw_member'],raw/f'pair-{i}-raw.source','raw_training')
                copy(pair['label_member'],labels/f'pair-{i}-labels.source','label_training')
        require(fingerprint(stream)==pin_archive,'intent_intake_archive_after')
    manifest={'completed':True,'timestamp_basis':
        'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check','pairs':[]}
    prep={'completed':True,'inputs_contain_truth':False,'pairs':[]}
    total=0
    with (out/'truth.jsonl').open('xb') as truth:
        for i,pair in enumerate(selected):
            source=raw/f'pair-{i}-raw.source';source_sha=copied[pair['raw_member']]['sha256']
            annotation,_=annotations(labels/f'pair-{i}-labels.source',copied[pair['label_member']]['sha256'])
            n=0
            with source.open('rb') as source_stream:
                while body:=source_stream.readline(MAX_ROW+1):
                    n+=1;require(n<=100000 and len(body)<=MAX_ROW,'intent_intake_row_bound')
                    truth.write(canonical({'case_id':hashlib.sha256((source_sha+':'+str(n)).encode()).hexdigest(),
                        'malicious':n in annotation,'attack_labels':list(annotation.get(n,()))})+b'\n')
            require(n>0 and (not annotation or max(annotation)<=n),'intent_intake_annotation_bounds')
            total+=n;require(total<=200000,'intent_intake_total_bound')
            manifest['pairs'].append({'provenance':{'raw_member':pair['raw_member'],'raw_sha256':source_sha,
                'simulation_start':plan['simulation_start'],'simulation_end':plan['simulation_end']}})
            prep['pairs'].append({'raw_member':pair['raw_member'],'raw_sha256':source_sha,'rows':n})
    (raw/'audit.json').write_bytes(canonical(manifest)+b'\n')
    prep['source_manifest_sha256']=sha(raw/'audit.json')
    (out/'preparation.json').write_bytes(canonical(prep)+b'\n')
    require(sha(archive)==pin_archive and sha(plan['acquisition'])==plan['acquisition_sha256'],
            'intent_intake_inputs_unchanged')
    report.update(completed=True,population=total,copied=copied,preparation_sha256=sha(out/'preparation.json'),
        truth_sha256=sha(out/'truth.jsonl'),training_access_sha256=sha(ledger),unpaired_assumed_benign=False,
        aws_calls=0,paid_api_calls=0,code_executed_from_archive=False)
    (out/'run.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('plan','sha256','output'):parser.add_argument('--'+name,required=True)
    a=parser.parse_args();r=prepare(a.plan,a.sha256,a.output)
    print(json.dumps({k:r[k] for k in ('completed','role','population','goal_qualified')}))
    return 0


if __name__=='__main__':raise SystemExit(main())
