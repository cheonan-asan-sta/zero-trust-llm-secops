"""Frozen learned intent head replay; labels never enter this command."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from scripts.f1_lab.apparmor_causal_intent import AppArmorCausalReview
from scripts.f1_lab.audit_auth_review import refine as add_observed_risk
from scripts.f1_lab.audit_intent_context import AuditIntentReview
from scripts.f1_lab.audit_intent_head import IntentHead
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.ordered_audit_login import OrderedAuditReview
from scripts.f1_lab.sensitive_auth_context import SensitiveAuthReview
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.web_firewall_context import WebFirewallReview
from scripts.run_audit_auth_review import signals


def observations(raw_directory,preparation,*,with_apparmor_causality=False):
    require(type(with_apparmor_causality) is bool,'intent_apparmor_option')
    # This reuses the exact physical source/hash/timezone validation, but not
    # risk decisions or labels, from the existing audit observation reader.
    signals(raw_directory,preparation)
    result={}
    for index,pair in enumerate(preparation['pairs']):
        if not pair['raw_member'].endswith('/logs/audit/audit.log'):
            continue
        path=Path(raw_directory)/f'pair-{index}-raw.source'
        require(sha(path)==pair['raw_sha256'],'intent_raw_pin')
        reviewer=(AppArmorCausalReview if with_apparmor_causality else AuditIntentReview)(pair['raw_sha256'])
        n=0
        with path.open('rb') as stream:
            for n,body in enumerate(stream,1):
                require(len(body)<=MAX_ROW and n<=100000,'intent_raw_bound')
                try:line=body.decode('utf8')
                except UnicodeError:line=''
                stamp=re.search(r'\bmsg=audit\((\d+(?:\.\d+)?):',line)
                observation=reviewer.observe(n,line,float(stamp[1]) if stamp else None,
                                             source_sha256=pair['raw_sha256'])
                if observation.eligible:result[index,n]=(observation,line)
        require(n==pair['rows'] and sha(path)==pair['raw_sha256'],'intent_raw_population')
    return result


def predict(head,preparation,raw_directory,baseline,baseline_sha256,output,*,with_risk_observations=False,
            with_apparmor_causality=False,with_network_audit_context=False,supplemental_head=None):
    require(type(with_risk_observations) is bool,'intent_risk_option')
    require(type(with_network_audit_context) is bool,'intent_network_option')
    require(sha(baseline)==baseline_sha256,'intent_baseline_pin')
    selected=observations(raw_directory,preparation,with_apparmor_causality=with_apparmor_causality)
    require(supplemental_head is None or isinstance(supplemental_head,IntentHead)
        and supplemental_head.frozen and with_apparmor_causality,'intent_supplemental_scope')
    supplemental=observations(raw_directory,preparation) if supplemental_head is not None else {}
    observed=(signals(raw_directory,preparation,review_factory=OrderedAuditReview,
        auth_review_factory=SensitiveAuthReview)[0] if with_risk_observations else {})
    if with_network_audit_context:
        for index,pair in enumerate(preparation['pairs']):
            if not pair['raw_member'].endswith('/logs/audit/audit.log'):continue
            reader=WebFirewallReview(pair['raw_sha256']);path=Path(raw_directory)/f'pair-{index}-raw.source'
            digest=hashlib.sha256();size=count=0
            with path.open('rb') as stream:
                for ordinal,body in enumerate(stream,1):
                    require(len(body)<=MAX_ROW and ordinal<=100000,'intent_network_bound')
                    digest.update(body);size+=len(body);count=ordinal
                    require(size<=64*1024**2,'intent_network_bytes')
                    try:line=body.decode('utf8')
                    except UnicodeError:line=''
                    stamp=re.search(r'\bmsg=audit\((\d+(?:\.\d+)?):',line)
                    reason=reader.observe(ordinal,line,float(stamp[1]) if stamp else None,source_sha256=pair['raw_sha256'])
                    if reason:observed.setdefault((index,ordinal),reason)
            require(count==pair['rows'] and digest.hexdigest()==pair['raw_sha256']
                and sha(path)==pair['raw_sha256'],'intent_network_source_or_population')
    output=Path(output)
    require(not output.exists() and not output.with_suffix('.part').exists(),'intent_fresh_output')
    source=ordinal=count=errors=changed=0
    with Path(baseline).open('rb') as old,output.with_suffix('.part').open('xb') as target:
        while body:=old.readline(MAX_ROW+1):
            require(len(body)<=MAX_ROW and source<len(preparation['pairs']),'intent_prediction_bound')
            ordinal+=1;pair=preparation['pairs'][source];prior=decode(body)
            case=hashlib.sha256((pair['raw_sha256']+':'+str(ordinal)).encode()).hexdigest()
            require(prior['case_id']==case and prior['source_index']==source,'intent_case_order')
            before=prior['after'] if prior['error'] is None else None
            after,score,reason=before,prior['after_score'],prior['reason']
            if prior['error'] is None:
                require(type(before) is bool,'intent_baseline_decision')
                previous=OperationDecision(prior['before_score'],score,before,before,reason)
                decision=add_observed_risk(previous,observed.get((source,ordinal)))
                if (source,ordinal) in selected:
                    observation,line=selected[source,ordinal]
                    decision=head.refine(decision,observation,source_sha256=pair['raw_sha256'],ordinal=ordinal,raw=line)
                if (source,ordinal) in supplemental:
                    observation,line=supplemental[source,ordinal]
                    decision=supplemental_head.refine(decision,observation,source_sha256=pair['raw_sha256'],ordinal=ordinal,raw=line)
                after,score,reason=decision.alert,decision.score,decision.reason
            changed+=before!=after;errors+=prior['error'] is not None
            target.write(canonical({'case_id':case,'source_index':source,'before':before,'after':after,
                'before_score':prior['after_score'],'after_score':score,'reason':reason,'error':prior['error']})+b'\n')
            count+=1
            if ordinal==pair['rows']:source,ordinal=source+1,0
    require(source==len(preparation['pairs']) and ordinal==0 and sha(baseline)==baseline_sha256,
            'intent_previous_population_or_drift')
    output.with_suffix('.part').rename(output)
    return {'population':count,'inference_errors':errors,'changed_alerts':changed,
            'predictions_sha256':sha(output),'validation_labels_opened':False}


def run(plan_path,pin,model_path,model_pin,output,*,with_risk_observations=False,with_apparmor_causality=False,
        with_network_audit_context=False,supplemental_model=None,supplemental_model_pin=None):
    require((supplemental_model is None)==(supplemental_model_pin is None),'intent_supplemental_pair')
    require(sha(plan_path)==pin,'intent_plan_pin')
    plan=decode(Path(plan_path).read_bytes())
    require(plan['schema']=='ordered-audit-replay-1' and plan['scope']=='observed_development_only'
            and plan['goal_qualified'] is False and sha(plan['baseline'])==plan['baseline_sha256'],
            'intent_plan_scope')
    baseline=decode(Path(plan['baseline']).read_bytes())
    require(baseline['completed'] is True and baseline['goal_qualified'] is False
            and len(plan['scenarios'])==len(baseline['scenarios']),'intent_baseline_scope')
    head=IntentHead.load(model_path,model_pin)
    supplemental_head=(IntentHead.load(supplemental_model,supplemental_model_pin) if supplemental_model is not None else None)
    output=Path(output);output.mkdir(parents=True,exist_ok=False);(output/'prediction').mkdir()
    report={'schema':'learned-audit-intent-prediction-1','completed':False,'goal_qualified':False,
        'new_independent_evaluation':False,'validation_labels_opened':False,
        'frozen_training_parameters_available':True,'model_sha256':model_pin,
        'with_v102_v105_risk_observations':with_risk_observations,
        'with_apparmor_causality':with_apparmor_causality,
        'with_network_audit_context':with_network_audit_context,
        'supplemental_intent_model_sha256':supplemental_model_pin,
        'scenarios':{},'aws_calls':0,'paid_api_calls':0}
    for spec in plan['scenarios']:
        name=spec['name']
        require(name not in report['scenarios'] and sha(spec['preparation'])==spec['preparation_sha256'],
                'intent_preparation_pin')
        prepared=decode(Path(spec['preparation']).read_bytes())
        require(prepared['completed'] is True and prepared['inputs_contain_truth'] is False,'intent_preparation_scope')
        before=baseline['scenarios'][name]
        row=predict(head,prepared,spec['raw'],spec['prediction'],before['prediction']['predictions_sha256'],
                    output/'prediction'/(name+'-predictions.jsonl'),with_risk_observations=with_risk_observations,
                    with_apparmor_causality=with_apparmor_causality,with_network_audit_context=with_network_audit_context,
                    supplemental_head=supplemental_head)
        require(row['population']==before['population'],'intent_complete_population')
        report['scenarios'][name]=row
        (output/'prediction-seal.json').write_bytes(canonical(report)+b'\n')
    report['completed']=True
    (output/'prediction-seal.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('plan','sha256','model','model-sha256','output'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--with-risk-observations',action='store_true')
    parser.add_argument('--with-apparmor-causality',action='store_true')
    parser.add_argument('--with-network-audit-context',action='store_true')
    parser.add_argument('--supplemental-intent-model')
    parser.add_argument('--supplemental-intent-model-sha256')
    a=parser.parse_args();report=run(a.plan,a.sha256,a.model,a.model_sha256,a.output,
        with_risk_observations=a.with_risk_observations,with_apparmor_causality=a.with_apparmor_causality,
        with_network_audit_context=a.with_network_audit_context,supplemental_model=a.supplemental_intent_model,
        supplemental_model_pin=a.supplemental_intent_model_sha256)
    print(json.dumps({'completed':report['completed'],'scenarios':len(report['scenarios']),'goal_qualified':False}))
    return 0


if __name__=='__main__':raise SystemExit(main())
