"""Explicit development-only fitting; never accepts an evaluation-role source."""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.f1_lab.apparmor_causal_intent import PROFILE as APPARMOR_PROFILE
from scripts.f1_lab.audit_intent_context import PROFILE as INTENT_PROFILE
from scripts.f1_lab.audit_intent_head import IntentHead
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha
from scripts.run_audit_intent_review import observations


def fit(plan_path, pin, output,*,with_apparmor_causality=False):
    require(type(with_apparmor_causality) is bool,'intent_apparmor_option')
    require(sha(plan_path)==pin, 'intent_training_plan_pin')
    plan=decode(Path(plan_path).read_bytes())
    require(plan['schema']=='audit-intent-training-plan-1' and plan['goal_qualified'] is False
            and plan['scope']=='previously_observed_development' and 1<=len(plan['sources'])<=10,
            'intent_training_scope')
    out=Path(output);out.mkdir(parents=True,exist_ok=False)
    model=IntentHead(minimum_support=plan['minimum_support'])
    provenance=[]
    seen=set()
    for spec in plan['sources']:
        require(spec['role']=='training' and spec['name'] not in seen, 'intent_training_role')
        seen.add(spec['name'])
        require(sha(spec['preparation'])==spec['preparation_sha256']
                and sha(spec['truth'])==spec['truth_sha256'],'intent_training_input_pin')
        preparation=decode(Path(spec['preparation']).read_bytes())
        selected=observations(spec['raw'],preparation,with_apparmor_causality=with_apparmor_causality)
        source=ordinal=count=eligible=0
        with Path(spec['truth']).open('rb') as truth:
            while body:=truth.readline(MAX_ROW+1):
                require(len(body)<=MAX_ROW and source<len(preparation['pairs']), 'intent_training_truth_bound')
                ordinal+=1;pair=preparation['pairs'][source];row=decode(body)
                case=hashlib.sha256((pair['raw_sha256']+':'+str(ordinal)).encode()).hexdigest()
                require(row['case_id']==case and type(row['malicious']) is bool, 'intent_training_truth_alignment')
                if (source,ordinal) in selected:
                    model.add(selected[source,ordinal][0],row['malicious']);eligible+=1
                count+=1
                if ordinal==pair['rows']:source,ordinal=source+1,0
        require(source==len(preparation['pairs']) and ordinal==0
                and sha(spec['truth'])==spec['truth_sha256'], 'intent_training_complete_population')
        provenance.append({'name':spec['name'],'role':'training','population':count,'eligible':eligible,
            'preparation_sha256':spec['preparation_sha256'],'truth_sha256':spec['truth_sha256']})
    model_pin=model.save(out/'model.json')
    report={'completed':True,'model_sha256':model_pin,'training_plan_sha256':pin,'training':provenance,
        'training_label_counts_in_model':True,'new_independent_evaluation':False,'goal_qualified':False,
        'minimum_support':model.minimum_support,'aws_calls':0,'paid_api_calls':0}
    report['with_apparmor_causality']=with_apparmor_causality
    report['feature_profile']=APPARMOR_PROFILE if with_apparmor_causality else INTENT_PROFILE
    (out/'training-provenance.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('plan','sha256','output'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--with-apparmor-causality',action='store_true')
    a=parser.parse_args();print(json.dumps(fit(a.plan,a.sha256,a.output,with_apparmor_causality=a.with_apparmor_causality)))
    return 0


if __name__=='__main__':raise SystemExit(main())
