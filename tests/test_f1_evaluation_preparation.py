from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from scripts.f1_lab.evaluation_preparation import (
    AXES,
    DOMAINS,
    CaseMetadata,
    ExposureLedger,
    PreparationProtocol,
    analyze,
)
from scripts.f1_lab.operation_context import canonical
from scripts.prepare_independent_evaluation import build_catalog, digest, local_path, read_pinned

NOW = datetime(2026,11,13,tzinfo=UTC)


def protocol():
    return PreparationProtocol(schema_version='f1-independent-preparation-1', stage='preparation_only',
        candidate_freeze_sha256=None, metric_tracks=['event_detection','session_any_alert','policy_control'],
        domains=list(DOMAINS), disjoint_axes=list(AXES),
        targets={'precision':.95,'recall':.95,'f1':.95,'false_positive_rate':.05},
        planned_final_sessions={'normal':300,'threat':300}, inputs={}, reserved_sources=[], notes=[])


def ledger(**updates):
    return ExposureLedger(schema_version='f1-exposure-ledger-1', observed_source_sha256=[],
                          observed_payload_sha256=[], observed_pattern_sha256=[], evidence_references=[], **updates)


def case(n, split='development', **updates):
    data={'case_id':'case-'+str(n), 'source_id':'source-'+str(n), 'source_sha256':digest(['source',n]),
        'payload_sha256':digest(['payload',n]), 'source_kind':'organization_observation',
        'metric_unit':'session_any_alert','label_purpose':'malicious_activity','label':None,
        'exposure':'sealed_unseen','requested_split':split,'original_split':'custodian-candidate',
        'identity_namespace_status':'documented','start':NOW+timedelta(days=n),'end':NOW+timedelta(days=n),
        'domains':['credential'],'groups':{axis:[digest([axis,n])] for axis in AXES}}
    data.update(updates)
    return CaseMetadata.model_validate(data)


def test_transitive_subject_and_device_links_cannot_be_split_apart():
    a,b,c=case(1),case(2,'calibration'),case(3,'final_reserved')
    b.groups['subject']=a.groups['subject']
    c.groups['device']=b.groups['device']
    report, components=analyze([a,b,c],ledger(),protocol())
    assert len(components)==1 and components[0]['cross_split_conflict']
    assert report['cases_preserved']==report['largest_component_cases']==3
    assert 'connected_component_crosses_splits' in report['structural_blockers']


def test_missing_identity_is_not_a_shared_person_and_not_proof_of_independence():
    a,b,c=case(1),case(2,'calibration'),case(3,'final_reserved')
    for r in [a,b,c]:
        r.groups['subject']=[]
        r.groups['device']=[]
    report, components=analyze([a,b,c],ledger(),protocol())
    assert len(components)==3
    assert 'required_group_metadata_missing' in report['final_case_blockers'][c.case_id]


def test_payload_duplicate_is_linked_even_when_case_source_and_entities_are_renamed():
    a,b=case(1),case(2,'final_reserved')
    b.payload_sha256=a.payload_sha256
    report,groups=analyze([a,b],ledger(),protocol())
    assert len(groups)==1 and report['components_crossing_splits']==1


@pytest.mark.parametrize('axis',AXES)
def test_every_declared_axis_is_preserved(axis):
    a,b=case(1),case(2,'final_reserved')
    b.groups[axis]=a.groups[axis]
    assert analyze([a,b],ledger(),protocol())[0]['components_crossing_splits']==1


@pytest.mark.parametrize('kind',['source','payload','pattern','source_id'])
def test_global_exposure_ledger_rejects_aliases_and_semantic_clones(kind):
    r=case(1,'final_reserved')
    seen=ledger()
    if kind=='source':
        seen.observed_source_sha256=[r.source_sha256]
    elif kind=='payload':
        seen.observed_payload_sha256=[r.payload_sha256]
    elif kind=='pattern':
        seen.observed_pattern_sha256=r.groups['pattern']
    else:
        seen.observed_source_ids=[r.source_id]
    result,_=analyze([r],seen,protocol())
    assert result['observed_cases']==1 and r.case_id in result['final_case_blockers']


@pytest.mark.parametrize('value',['normal','threat','unknown'])
def test_unseen_final_metadata_cannot_carry_opened_labels(value):
    with pytest.raises(ValueError, match='sealed_label'):
        case(1,'final_reserved',label=value)


def test_observed_unknown_labels_are_preserved_and_never_counted_normal():
    r=case(1,exposure='observed',label='unknown')
    result,_=analyze([r],ledger(),protocol())
    support=result['support']['development']['session_any_alert']['known_labels']
    assert support=={'unknown':1} and result['cases_dropped']==0


def test_policy_alert_labels_cannot_be_submitted_as_detection_ground_truth():
    with pytest.raises(ValueError,match='policy_labels'):
        case(1,metric_unit='event_detection',label_purpose='expected_alert_policy')
    r=case(1,'final_reserved',metric_unit='policy_control',label_purpose='expected_alert_policy')
    result,_=analyze([r],ledger(),protocol())
    assert 'policy_or_unadjudicated_labels_not_malicious_truth' in result['final_case_blockers'][r.case_id]


def test_units_are_separate_and_label_changes_cannot_change_components():
    a=case(1,exposure='observed',label='normal')
    b=case(2,exposure='observed',label='threat',metric_unit='event_detection')
    before,groups=analyze([a,b],ledger(),protocol())
    changed=a.model_copy(update={'label':'threat'})
    after,newgroups=analyze([changed,b],ledger(),protocol())
    assert groups==newgroups and before['support']!=after['support']
    assert before['support']['development']['session_any_alert']['cases']==1
    assert before['support']['development']['event_detection']['cases']==1


def test_metadata_success_does_not_freeze_a_candidate_or_approve_independence():
    result,_=analyze([case(1),case(2,'calibration'),case(3,'final_reserved')],ledger(),protocol())
    assert result['metadata_structure_ready']
    assert not result['candidate_frozen'] and not result['final_evaluation_ready'] and not result['goal_qualified']
    assert result['final_observation_bodies_opened']==result['final_label_bodies_opened']==0


def test_equal_time_and_overlapping_sessions_fail_strict_forward_time():
    a,b,c=case(1),case(2,'calibration'),case(3,'final_reserved')
    b.start=a.end
    result,_=analyze([a,b,c],ledger(),protocol())
    assert not result['forward_time_contract_passed']


@pytest.mark.parametrize('change',[
    {'source_kind':'authored_regression'},{'identity_namespace_status':'unverified'},
    {'exposure':'unestablished'},{'domains':[]},
])
def test_missing_or_authored_provenance_cannot_become_independent_final(change):
    result,_=analyze([case(1,'final_reserved',**change)],ledger(),protocol())
    assert result['final_case_blockers']


@pytest.mark.parametrize('change',[
    {'candidate_freeze_sha256':'a'*64},{'domains':['credential']},
    {'disjoint_axes':['session']},{'targets':{'precision':.94}},
    {'metric_tracks':['event_detection']},{'planned_final_sessions':{'normal':3,'threat':3}},
])
def test_original_scope_targets_and_preparation_stage_cannot_be_relaxed(change):
    data={**protocol().model_dump(),**change}
    with pytest.raises((ValueError,ValidationError)):
        PreparationProtocol.model_validate(data)


def test_duplicate_case_identity_is_an_error_not_silently_deduplicated():
    a=case(1)
    with pytest.raises(ValueError,match='duplicate_case'):
        analyze([a,a],ledger(),protocol())


def test_invalid_times_hashes_and_group_keys_are_rejected():
    with pytest.raises(ValueError):
        case(1,start=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError):
        case(1,start=NOW+timedelta(days=9),end=NOW)
    with pytest.raises(ValueError):
        case(1,payload_sha256='bad')
    r=case(1).model_dump()
    r['groups']['unexpected']=[]
    with pytest.raises(ValueError):
        CaseMetadata.model_validate(r)


@pytest.mark.parametrize('name',['../ap2.txt','/tmp/key','C:/secret','folder\\file'])
def test_metadata_input_paths_cannot_escape_workspace(name):
    with pytest.raises(ValueError,match='relative_path'):
        local_path(name)


def test_pinned_metadata_rejects_changed_or_oversized_file(tmp_path):
    p=tmp_path/'file'
    p.write_bytes(b'{}')
    from hashlib import sha256
    sha=sha256(p.read_bytes()).hexdigest()
    assert read_pinned(p,sha)==b'{}'
    with pytest.raises(ValueError,match='bounded'):
        read_pinned(p,sha,1)
    p.write_bytes(b'[]')
    with pytest.raises(ValueError,match='pin'):
        read_pinned(p,sha)


def legacy_row():
    from app.scenarios import synthetic_events
    event=synthetic_events()[0].model_dump(mode='json',exclude={'ground_truth'})
    return {'case_id':'example','session_id':'session','family_id':'family','domain':'credential',
            'split':'holdout','threat':False,'event':event}


def test_observed_legacy_holdout_keeps_original_split_but_is_only_regression_metadata():
    row=legacy_row()
    records=build_catalog(canonical(row)+b'\n',1)
    assert records[0].original_split=='holdout' and records[0].requested_split=='development'
    assert records[0].exposure=='observed' and records[0].source_kind=='authored_regression'


def test_catalog_never_defaults_missing_security_facts_or_relabels_bad_rows():
    row=legacy_row()
    del row['event']['user']['active']
    with pytest.raises(ValueError,match='explicit_security_fields'):
        build_catalog(canonical(row),1)
    row=legacy_row();row['threat']='false'
    with pytest.raises(ValueError,match='legacy_case_contract'):
        build_catalog(canonical(row),1)
    with pytest.raises(ValueError,match='exact_benchmark_population'):
        build_catalog(canonical(legacy_row()),2)


@pytest.fixture
def packet(tmp_path,monkeypatch):
    import hashlib

    import scripts.prepare_independent_evaluation as runner
    original_root=runner.ROOT
    root=tmp_path/'workspace'
    root.mkdir()
    case_bytes=(original_root/'app/data/benchmark/cases.jsonl').read_bytes()
    manifest_bytes=(original_root/'app/data/benchmark/manifest.json').read_bytes()
    first=__import__('json').loads(case_bytes.splitlines()[0])
    evidence={'family_id':first['family_id'],'case_id':first['case_id'],'domain':first['domain'],
        'outcome':'FP','split':first['split'],'missed_expected_rule_ids':[],
        'unexpected_rule_ids':['example'],'observed_input':first['event']}
    baseline=root/'baseline';baseline.mkdir()
    raw=canonical(evidence)+b'\n'
    (baseline/'evidence.jsonl').write_bytes(raw)
    (baseline/'reviews.jsonl').write_bytes(b'')
    freeze={'schema':'f1-baseline-review-1','independent_review':'pending','detector_changed':False,
        'evidence_cases':1,'review_families':1,'files':{'evidence.jsonl':hashlib.sha256(raw).hexdigest()}}
    freeze_bytes=canonical(freeze)
    (baseline/'freeze.json').write_bytes(freeze_bytes)
    payloads={'benchmark_manifest':manifest_bytes,'benchmark_cases':case_bytes,
        'baseline_freeze':freeze_bytes,'native_plan':canonical({'scenarios':[]}),
        'native_comparison':canonical({'completed':True,'scenarios':{}}),
        'vpn_evidence':canonical({'final_run':{'report':{'controls':{
            'scope':'authored prospective functional controls; not independent performance',
            'after':{'population':1},'controls':[{'raw_line_sha256':'f'*64}]}}}})}
    specs={}
    for key,payload in payloads.items():
        name='baseline/freeze.json' if key=='baseline_freeze' else 'inputs/'+key+'.json'
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(payload)
        specs[key]={'path':name,'sha256':hashlib.sha256(payload).hexdigest()}
    for name in ['scripts/f1_lab/evaluation_preparation.py','scripts/prepare_independent_evaluation.py',
                 'scripts/prepare_f1_intake.py','scripts/prepare_f1_review.py','scripts/audit_f1_features.py']:
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text('raise AssertionError("copied sources must never execute")\n',encoding='utf-8')
    config={**protocol().model_dump(),'inputs':specs,'reserved_sources':[
        {'source_id':'unread','reference':str(tmp_path/'never-open-this-file')}]}
    config_path=root/'protocol.json';config_path.write_bytes(canonical(config))
    monkeypatch.setattr(runner,'ROOT',root)
    out=root/'packet'
    result=runner.prepare(config_path,hashlib.sha256(config_path.read_bytes()).hexdigest(),out)
    return runner,out,result


def test_full_preparation_preserves_observed_720_cases_without_running_copied_sources(packet):
    runner,out,result=packet
    checked=runner.verify(out,result['freeze_sha256'])
    assert checked['cases_preserved']==720 and checked['observed_cases']==720
    assert checked['original_source_splits_preserved']=={'development':360,'holdout':360}
    assert checked['model_inference_runs']==checked['final_label_bodies_opened']==0
    assert not checked['final_evaluation_ready']
    assert len((out/'catalog.jsonl').read_bytes().splitlines())==720


def test_output_fingerprint_rejects_changed_catalog(packet):
    runner,out,result=packet
    p=out/'catalog.jsonl';p.write_bytes(p.read_bytes()+b'\n')
    with pytest.raises(ValueError,match='pin'):
        runner.verify(out,result['freeze_sha256'])


def test_output_fingerprint_rejects_extra_file_even_with_original_freeze(packet):
    runner,out,result=packet
    (out/'unexpected.txt').write_bytes(b'data')
    with pytest.raises(ValueError,match='inventory'):
        runner.verify(out,result['freeze_sha256'])


def test_check_cli_reports_not_ready_and_exit_two(packet,monkeypatch,capsys):
    import json
    import sys
    runner,out,result=packet
    monkeypatch.setattr(sys,'argv',['prepare','check','--expected-sha256',result['freeze_sha256'],'--directory',str(out)])
    assert runner.main()==2
    reply=json.loads(capsys.readouterr().out)
    assert reply['verified'] and not reply['final_evaluation_ready']


def test_existing_packet_is_not_overwritten(packet):
    import hashlib
    runner,out,_=packet
    p=out.parent/'protocol.json'
    before=(out/'freeze.json').read_bytes()
    with pytest.raises(ValueError,match='fresh_output'):
        runner.prepare(p,hashlib.sha256(p.read_bytes()).hexdigest(),out)
    assert (out/'freeze.json').read_bytes()==before
