"""Complete-population frozen VPN advisory replay; no validation label access."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.vpn_attack_evidence import DIRECT_REASON, RETAINED_REASON, AttackEvidenceReview
from scripts.f1_lab.vpn_control_review import ControlHead
from scripts.f1_lab.vpn_issuer_review import IssuerHead, IssuerRelationReview
from scripts.f1_lab.vpn_protocol_head import ProtocolHead
from scripts.f1_lab.vpn_protocol_io import legacy, records
from scripts.f1_lab.vpn_protocol_review import project


def predict(head,model,prep,raw,baseline,pin,output,*,with_attack_evidence=False,control_head=None,issuer_head=None):
    require(type(with_attack_evidence) is bool,'protocol_attack_option')
    require(control_head is None or isinstance(control_head,ControlHead) and control_head.frozen,'control_frozen_head')
    require(issuer_head is None or isinstance(issuer_head,IssuerHead) and issuer_head.frozen
            and control_head is not None and with_attack_evidence,'issuer_frozen_pipeline')
    require(sha(baseline)==pin,'protocol_prediction_baseline_pin')
    selected={};time_errors=0
    for index,(source,rows,errors) in records(raw,prep).items():
        values=project(rows,source,model)
        review=AttackEvidenceReview(head,source) if with_attack_evidence else None
        issuer=IssuerRelationReview(source) if issuer_head is not None else None
        for ordinal,moment,line in rows:
            projection,observation,previous=values[ordinal]
            issuer_observation=(issuer.observe(ordinal,line,moment,observation,source_sha256=source)
                                if issuer is not None else None)
            normal=head.refine(previous,projection,observation,source_sha256=source,ordinal=ordinal,raw=line)
            candidate=(review.refine(previous,projection,observation,ordinal=ordinal,raw=line,moment=moment)
                if review is not None else normal)
            prior_candidate=candidate
            if control_head is not None:
                candidate=control_head.refine(candidate,observation.control,source_sha256=source,ordinal=ordinal,raw=line)
            control_candidate=candidate
            if issuer_head is not None:
                candidate=issuer_head.refine(candidate,issuer_observation,source_sha256=source,ordinal=ordinal,raw=line)
            selected[index,ordinal]=(projection,observation,previous,line,normal,prior_candidate,control_candidate,candidate)
        time_errors+=errors
    output=Path(output);require(not output.exists() and not output.with_suffix('.part').exists(),'protocol_fresh_prediction')
    source=ordinal=total=errors=changed=mismatches=unavailable=direct=retained=0
    with Path(baseline).open('rb') as old,output.with_suffix('.part').open('xb') as target:
        while body:=old.readline(MAX_ROW+1):
            require(len(body)<=MAX_ROW and source<len(prep['pairs']),'protocol_baseline_bound')
            ordinal+=1;pair=prep['pairs'][source];row=decode(body)
            case=hashlib.sha256((pair['raw_sha256']+':'+str(ordinal)).encode()).hexdigest()
            require(row['case_id']==case and row['source_index']==source,'protocol_prediction_order')
            before=row['after'] if row['error'] is None else None
            after,score,reason=before,row['after_score'],row['reason']
            if row['error'] is None and (source,ordinal) in selected:
                _projection,observation,previous,_line,normal,prior_candidate,control_candidate,candidate=selected[source,ordinal]
                unavailable+=not observation.available
                if observation.available:
                    # The pinned baseline already incorporates all earlier
                    # refinements. Never replace a different/current denial.
                    actual=(before,score,reason)
                    compatible={(d.alert,d.score,d.reason) for d in (previous,normal,prior_candidate,control_candidate)}
                    if with_attack_evidence or control_head is not None:compatible.add((candidate.alert,candidate.score,candidate.reason))
                    if actual in compatible:
                        decision=candidate
                        after,score,reason=decision.alert,decision.score,decision.reason
                        if not before and after:
                            direct+=reason==DIRECT_REASON;retained+=reason==RETAINED_REASON
                    else:mismatches+=1
            changed+=before!=after;errors+=row['error'] is not None;total+=1
            target.write(canonical({'case_id':case,'source_index':source,'before':before,'after':after,
                'before_score':row['after_score'],'after_score':score,'reason':reason,'error':row['error']})+b'\n')
            if ordinal==pair['rows']:source,ordinal=source+1,0
    require(source==len(prep['pairs']) and ordinal==0 and sha(baseline)==pin,'protocol_prediction_population_or_drift')
    output.with_suffix('.part').rename(output)
    return {'population':total,'inference_errors':errors,'changed_alerts':changed,'raw_time_errors':time_errors,
        'protected_baseline_mismatches':mismatches,'unavailable_observations':unavailable,
        'direct_attack_reviews':direct,'retained_attack_reviews':retained,
        'predictions_sha256':sha(output),'validation_labels_opened':False}


def run(plan_path,pin,model_path,model_pin,legacy_path,legacy_pin,output,*,with_attack_evidence=False,
        control_model=None,control_model_pin=None,issuer_model=None,issuer_model_pin=None):
    require((control_model is None)==(control_model_pin is None),'control_model_pair')
    require((issuer_model is None)==(issuer_model_pin is None)
            and (issuer_model is None or control_model is not None and with_attack_evidence),'issuer_model_pair_and_pipeline')
    require(sha(plan_path)==pin,'protocol_plan_pin');plan=decode(Path(plan_path).read_bytes())
    require(plan['schema']=='ordered-audit-replay-1' and plan['scope']=='observed_development_only'
        and plan['goal_qualified'] is False and sha(plan['baseline'])==plan['baseline_sha256'],'protocol_plan_scope')
    baseline=decode(Path(plan['baseline']).read_bytes())
    require(baseline['completed'] is True and baseline['goal_qualified'] is False
        and len(plan['scenarios'])==len(baseline['scenarios']),'protocol_baseline_scope')
    model,identity=legacy(legacy_path,legacy_pin);head=ProtocolHead.load(model_path,model_pin,identity)
    control=ControlHead.load(control_model,control_model_pin,identity,model_pin) if control_model is not None else None
    issuer=(IssuerHead.load(issuer_model,issuer_model_pin,{'legacy_identity_sha256':identity,
        'protocol_model_sha256':model_pin,'control_model_sha256':control_model_pin}) if issuer_model is not None else None)
    output=Path(output);output.mkdir(parents=True,exist_ok=False);(output/'prediction').mkdir()
    report={'completed':False,'schema':'vpn-protocol-prediction-1','goal_qualified':False,'new_independent_evaluation':False,
        'validation_labels_opened':False,'frozen_training_parameters_available':True,'model_sha256':model_pin,
        'legacy_identity_sha256':identity,'scenarios':{},'aws_calls':0,'paid_api_calls':0}
    report['with_attack_evidence']=with_attack_evidence
    report['control_model_sha256']=control_model_pin
    report['issuer_model_sha256']=issuer_model_pin
    for spec in plan['scenarios']:
        name=spec['name'];require(type(name) is str and re.fullmatch('[a-z0-9_-]{1,64}',name)
            and name not in report['scenarios'] and sha(spec['preparation'])==spec['preparation_sha256'],
            'protocol_preparation_pin')
        prep=decode(Path(spec['preparation']).read_bytes())
        require(prep['completed'] is True and prep['inputs_contain_truth'] is False,'protocol_preparation_scope')
        prior=baseline['scenarios'][name]
        result=predict(head,model,prep,spec['raw'],spec['prediction'],prior['prediction']['predictions_sha256'],
            output/'prediction'/(name+'-predictions.jsonl'),with_attack_evidence=with_attack_evidence,control_head=control,
            issuer_head=issuer)
        require(result['population']==prior['population'],'protocol_complete_population')
        report['scenarios'][name]=result
        (output/'prediction-seal.json').write_bytes(canonical(report)+b'\n')
    report['completed']=True;(output/'prediction-seal.json').write_bytes(canonical(report)+b'\n');return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('plan','sha256','model','model-sha256','legacy-models','legacy-models-sha256','output'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--with-attack-evidence',action='store_true')
    parser.add_argument('--control-model')
    parser.add_argument('--control-model-sha256')
    parser.add_argument('--issuer-model')
    parser.add_argument('--issuer-model-sha256')
    a=parser.parse_args();report=run(a.plan,a.sha256,a.model,a.model_sha256,a.legacy_models,a.legacy_models_sha256,a.output,
        with_attack_evidence=a.with_attack_evidence,control_model=a.control_model,control_model_pin=a.control_model_sha256,
        issuer_model=a.issuer_model,issuer_model_pin=a.issuer_model_sha256)
    print(json.dumps({'completed':report['completed'],'scenarios':len(report['scenarios']),'goal_qualified':False}));return 0


if __name__=='__main__':raise SystemExit(main())
