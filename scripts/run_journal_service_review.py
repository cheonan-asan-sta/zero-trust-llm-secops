"""Add review from pinned prior journal evidence, retaining every baseline row."""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.f1_lab.journal_service_review import REASON, JournalServiceReview
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha


def predict(prep,raw,baseline,pin,output,members):
    require(sha(baseline)==pin,'journal_baseline_pin');selected={};proof=[]
    by_source={}
    for member in members:
        index=member['source_index'];require(type(index) is int and 0<=index<len(prep['pairs']),'journal_source_index')
        pair=prep['pairs'][index]
        require(pair['raw_member'].endswith('/internal_share/logs/audit/audit.log')
            and member['raw_source_sha256']==pair['raw_sha256'],'journal_host_source_binding')
        by_source.setdefault(index,[]).append(member)
    for index,parts in by_source.items():
        pair=prep['pairs'][index];path=Path(raw)/f'pair-{index}-raw.source'
        require(sha(path,64*1024**2)==pair['raw_sha256'],'journal_raw_pin')
        with path.open('rb') as stream:lines=list(stream)
        require(len(lines)==pair['rows']<=100000 and sum(map(len,lines))<=64*1024**2
            and all(len(b)<=MAX_ROW for b in lines),'journal_raw_population')
        text=[b.decode('utf8') for b in lines];reader=JournalServiceReview(pair['raw_sha256'],text,parts)
        for ordinal,line in enumerate(text,1):
            evidence=reader.observe(ordinal,line,source_sha256=pair['raw_sha256'])
            if evidence:selected[index,ordinal]=evidence
        reader.verify();require(sha(path)==pair['raw_sha256'],'journal_raw_drift')
    out=Path(output);require(not out.exists() and not out.with_suffix('.part').exists(),'journal_fresh_prediction')
    source=ordinal=total=errors=changed=0
    with Path(baseline).open('rb') as old,out.with_suffix('.part').open('xb') as target:
        while body:=old.readline(MAX_ROW+1):
            require(len(body)<=MAX_ROW and source<len(prep['pairs']),'journal_baseline_bound')
            ordinal+=1;pair=prep['pairs'][source];prior=decode(body)
            case=hashlib.sha256((pair['raw_sha256']+':'+str(ordinal)).encode()).hexdigest()
            require(prior['case_id']==case and prior['source_index']==source,'journal_case_order')
            before=prior['after'] if prior['error'] is None else None
            after,score,reason=before,prior['after_score'],prior['reason']
            evidence=selected.get((source,ordinal))
            if before is False and prior['error'] is None and reason=='unchanged' and evidence:
                after=True;score=max(score,.95);reason=REASON;proof.append({'case_id':case,**evidence})
            changed+=before!=after;errors+=prior['error'] is not None;total+=1
            target.write(canonical({'case_id':case,'source_index':source,'before':before,'after':after,
                'before_score':prior['after_score'],'after_score':score,'reason':reason,'error':prior['error']})+b'\n')
            if ordinal==pair['rows']:source,ordinal=source+1,0
    require(source==len(prep['pairs']) and ordinal==0 and sha(baseline)==pin,'journal_complete_population_or_drift')
    out.with_suffix('.part').rename(out)
    evidence_path=out.with_suffix('.evidence.jsonl');evidence_path.write_bytes(b''.join(canonical(r)+b'\n' for r in proof))
    return {'population':total,'inference_errors':errors,'changed_alerts':changed,
        'predictions_sha256':sha(out),'evidence_sha256':sha(evidence_path),'validation_labels_opened':False}


def run(plan_path,pin,journal_path,journal_pin,output):
    require(sha(plan_path)==pin and sha(journal_path)==journal_pin,'journal_plan_pins')
    plan=decode(Path(plan_path).read_bytes());journals=decode(Path(journal_path).read_bytes())
    require(plan['schema']=='ordered-audit-replay-1' and plan['scope']=='observed_development_only'
        and plan['goal_qualified'] is False and sha(plan['baseline'])==plan['baseline_sha256'],'journal_plan_scope')
    require(journals['schema']=='journal-service-sidecars-1' and journals['goal_qualified'] is False
        and type(journals['members']) is list and len(journals['members'])<=64,'journal_catalog_scope')
    baseline=decode(Path(plan['baseline']).read_bytes())
    require(baseline['completed'] is True and baseline['goal_qualified'] is False
        and len(baseline['scenarios'])==len(plan['scenarios']),'journal_baseline_scope')
    names={s['name'] for s in plan['scenarios']}
    require(all(m['scenario'] in names for m in journals['members']),'journal_scenario_binding')
    out=Path(output);out.mkdir(parents=True,exist_ok=False);(out/'prediction').mkdir()
    report={'schema':'journal-service-prediction-1','completed':False,'goal_qualified':False,
        'new_independent_evaluation':False,'validation_labels_opened':False,'journal_catalog_sha256':journal_pin,
        'models_refitted':False,'scenarios':{},'aws_calls':0,'paid_api_calls':0}
    for spec in plan['scenarios']:
        name=spec['name'];require(name not in report['scenarios'] and sha(spec['preparation'])==spec['preparation_sha256'],
            'journal_preparation_pin')
        prep=decode(Path(spec['preparation']).read_bytes())
        require(prep['completed'] is True and prep['inputs_contain_truth'] is False,'journal_preparation_scope')
        members=[m for m in journals['members'] if m['scenario']==name]
        prior=baseline['scenarios'][name]
        row=predict(prep,spec['raw'],spec['prediction'],prior['prediction']['predictions_sha256'],
            out/'prediction'/(name+'-predictions.jsonl'),members)
        require(row['population']==prior['population'],'journal_scenario_population')
        report['scenarios'][name]=row
        (out/'prediction-seal.json').write_bytes(canonical(report)+b'\n')
    report['completed']=True;(out/'prediction-seal.json').write_bytes(canonical(report)+b'\n');return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('plan','sha256','journal-catalog','journal-catalog-sha256','output'):parser.add_argument('--'+name,required=True)
    a=parser.parse_args();r=run(a.plan,a.sha256,a.journal_catalog,a.journal_catalog_sha256,a.output)
    print(json.dumps({'completed':r['completed'],'goal_qualified':False}));return 0


if __name__=='__main__':raise SystemExit(main())
