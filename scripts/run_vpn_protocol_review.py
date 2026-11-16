"""Complete-population frozen VPN advisory replay; no validation label access."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.vpn_protocol_head import ProtocolHead
from scripts.f1_lab.vpn_protocol_io import legacy, records
from scripts.f1_lab.vpn_protocol_review import project


def predict(head,model,prep,raw,baseline,pin,output):
    require(sha(baseline)==pin,'protocol_prediction_baseline_pin')
    selected={};time_errors=0
    for index,(source,rows,errors) in records(raw,prep).items():
        values=project(rows,source,model)
        for ordinal,_,line in rows:selected[index,ordinal]=(*values[ordinal],line)
        time_errors+=errors
    output=Path(output);require(not output.exists() and not output.with_suffix('.part').exists(),'protocol_fresh_prediction')
    source=ordinal=total=errors=changed=mismatches=unavailable=0
    with Path(baseline).open('rb') as old,output.with_suffix('.part').open('xb') as target:
        while body:=old.readline(MAX_ROW+1):
            require(len(body)<=MAX_ROW and source<len(prep['pairs']),'protocol_baseline_bound')
            ordinal+=1;pair=prep['pairs'][source];row=decode(body)
            case=hashlib.sha256((pair['raw_sha256']+':'+str(ordinal)).encode()).hexdigest()
            require(row['case_id']==case and row['source_index']==source,'protocol_prediction_order')
            before=row['after'] if row['error'] is None else None
            after,score,reason=before,row['after_score'],row['reason']
            if row['error'] is None and (source,ordinal) in selected:
                projection,observation,previous,line=selected[source,ordinal]
                unavailable+=not observation.available
                if observation.available:
                    # The pinned baseline already incorporates all earlier
                    # refinements. Never replace a different/current denial.
                    if previous.alert==before and previous.score==score and previous.reason==reason:
                        decision=head.refine(previous,projection,observation,source_sha256=pair['raw_sha256'],
                            ordinal=ordinal,raw=line)
                        after,score,reason=decision.alert,decision.score,decision.reason
                    else:mismatches+=1
            changed+=before!=after;errors+=row['error'] is not None;total+=1
            target.write(canonical({'case_id':case,'source_index':source,'before':before,'after':after,
                'before_score':row['after_score'],'after_score':score,'reason':reason,'error':row['error']})+b'\n')
            if ordinal==pair['rows']:source,ordinal=source+1,0
    require(source==len(prep['pairs']) and ordinal==0 and sha(baseline)==pin,'protocol_prediction_population_or_drift')
    output.with_suffix('.part').rename(output)
    return {'population':total,'inference_errors':errors,'changed_alerts':changed,'raw_time_errors':time_errors,
        'protected_baseline_mismatches':mismatches,'unavailable_observations':unavailable,
        'predictions_sha256':sha(output),'validation_labels_opened':False}


def run(plan_path,pin,model_path,model_pin,legacy_path,legacy_pin,output):
    require(sha(plan_path)==pin,'protocol_plan_pin');plan=decode(Path(plan_path).read_bytes())
    require(plan['schema']=='ordered-audit-replay-1' and plan['scope']=='observed_development_only'
        and plan['goal_qualified'] is False and sha(plan['baseline'])==plan['baseline_sha256'],'protocol_plan_scope')
    baseline=decode(Path(plan['baseline']).read_bytes())
    require(baseline['completed'] is True and baseline['goal_qualified'] is False
        and len(plan['scenarios'])==len(baseline['scenarios']),'protocol_baseline_scope')
    model,identity=legacy(legacy_path,legacy_pin);head=ProtocolHead.load(model_path,model_pin,identity)
    output=Path(output);output.mkdir(parents=True,exist_ok=False);(output/'prediction').mkdir()
    report={'completed':False,'schema':'vpn-protocol-prediction-1','goal_qualified':False,'new_independent_evaluation':False,
        'validation_labels_opened':False,'frozen_training_parameters_available':True,'model_sha256':model_pin,
        'legacy_identity_sha256':identity,'scenarios':{},'aws_calls':0,'paid_api_calls':0}
    for spec in plan['scenarios']:
        name=spec['name'];require(type(name) is str and re.fullmatch('[a-z0-9_-]{1,64}',name)
            and name not in report['scenarios'] and sha(spec['preparation'])==spec['preparation_sha256'],
            'protocol_preparation_pin')
        prep=decode(Path(spec['preparation']).read_bytes())
        require(prep['completed'] is True and prep['inputs_contain_truth'] is False,'protocol_preparation_scope')
        prior=baseline['scenarios'][name]
        result=predict(head,model,prep,spec['raw'],spec['prediction'],prior['prediction']['predictions_sha256'],
            output/'prediction'/(name+'-predictions.jsonl'))
        require(result['population']==prior['population'],'protocol_complete_population')
        report['scenarios'][name]=result
        (output/'prediction-seal.json').write_bytes(canonical(report)+b'\n')
    report['completed']=True;(output/'prediction-seal.json').write_bytes(canonical(report)+b'\n');return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('plan','sha256','model','model-sha256','legacy-models','legacy-models-sha256','output'):
        parser.add_argument('--'+name,required=True)
    a=parser.parse_args();report=run(a.plan,a.sha256,a.model,a.model_sha256,a.legacy_models,a.legacy_models_sha256,a.output)
    print(json.dumps({'completed':report['completed'],'scenarios':len(report['scenarios']),'goal_qualified':False}));return 0


if __name__=='__main__':raise SystemExit(main())
