"""Explicit pinned development training; evaluation-role labels are rejected."""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.vpn_protocol_head import ProtocolHead
from scripts.f1_lab.vpn_protocol_io import legacy, records
from scripts.f1_lab.vpn_protocol_review import project


def fit(plan_path,pin,output):
    require(sha(plan_path)==pin,'protocol_training_plan_pin')
    plan=decode(Path(plan_path).read_bytes())
    require(plan['schema']=='vpn-protocol-training-plan-1' and plan['goal_qualified'] is False
        and plan['scope']=='observed_development' and 1<=len(plan['sources'])<=10,'protocol_training_scope')
    model,identity=legacy(plan['legacy_models'],plan['legacy_models_sha256']);head=ProtocolHead(identity)
    out=Path(output);out.mkdir(parents=True,exist_ok=False);provenance=[];seen=set()
    for spec in plan['sources']:
        require(spec['role']=='training' and spec['name'] not in seen,'protocol_training_role')
        seen.add(spec['name'])
        require(sha(spec['preparation'])==spec['preparation_sha256']
            and sha(spec['truth'])==spec['truth_sha256'],'protocol_training_input_pin')
        prep=decode(Path(spec['preparation']).read_bytes())
        require(prep['completed'] is True and prep['inputs_contain_truth'] is False,'protocol_training_preparation')
        selected={}
        for index,(source,rows,_) in records(spec['raw'],prep).items():
            for ordinal,value in project(rows,source,model).items():selected[index,ordinal]=value
        source=ordinal=total=eligible=0
        with Path(spec['truth']).open('rb') as stream:
            while body:=stream.readline(MAX_ROW+1):
                require(len(body)<=MAX_ROW and source<len(prep['pairs']) and total<2000000,'protocol_training_truth_bound')
                ordinal+=1;pair=prep['pairs'][source];row=decode(body)
                case=hashlib.sha256((pair['raw_sha256']+':'+str(ordinal)).encode()).hexdigest()
                require(row['case_id']==case and type(row['malicious']) is bool,'protocol_training_truth_alignment')
                if (source,ordinal) in selected:
                    old,observation,_=selected[source,ordinal];head.add(old,observation,row['malicious'])
                    eligible+=observation.available
                total+=1
                if ordinal==pair['rows']:source,ordinal=source+1,0
        require(source==len(prep['pairs']) and ordinal==0 and sha(spec['truth'])==spec['truth_sha256'],
            'protocol_training_population_or_drift')
        provenance.append({'name':spec['name'],'role':'training','population':total,'vpn_available':eligible,
            'preparation_sha256':spec['preparation_sha256'],'truth_sha256':spec['truth_sha256']})
    model_pin=head.save(out/'model.json')
    report={'completed':True,'model_sha256':model_pin,'training_plan_sha256':pin,'legacy_identity_sha256':identity,
        'training':provenance,'minimum_support':5,'training_attack_veto':True,'frozen_training_label_counts':True,
        'new_independent_evaluation':False,'goal_qualified':False,'aws_calls':0,'paid_api_calls':0}
    (out/'training-provenance.json').write_bytes(canonical(report)+b'\n');return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('plan','sha256','output'):parser.add_argument('--'+name,required=True)
    a=parser.parse_args();print(json.dumps(fit(a.plan,a.sha256,a.output)));return 0


if __name__=='__main__':raise SystemExit(main())
