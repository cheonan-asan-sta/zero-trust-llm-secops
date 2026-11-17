import json
from dataclasses import replace

import pytest

from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.vpn_attack_evidence import DIRECT_REASON, RETAINED_REASON, AttackEvidenceReview
from scripts.f1_lab.vpn_protocol_head import ProtocolHead
from scripts.f1_lab.vpn_protocol_io import records
from scripts.f1_lab.vpn_protocol_review import ProtocolReview
from scripts.run_local_vpn_protocol_batch import run as batch
from scripts.run_vpn_protocol_review import predict
from tests.test_vpn_protocol_review import (
    LEGACY,
    MODELS,
    SOURCE,
    START,
    FixedLegacy,
    io_packet,
    observe,
    trained,
)


def quiet(reason='vpn_history_risk_review'):
    return OperationDecision(.1,.1,False,True,reason)


@pytest.mark.parametrize('normal,attack,raises',[(0,4,False),(0,5,True),(1,100,False)])
def test_attack_support_and_any_normal_example_veto(tmp_path,normal,attack,raises):
    obs,raw=observe(ProtocolReview(SOURCE),1,'VERIFY KU OK')
    head,_,_=trained(tmp_path,obs,normal=normal,attack=attack)
    result=AttackEvidenceReview(head,SOURCE).refine(quiet(),LEGACY,obs,ordinal=1,raw=raw,moment=START)
    assert result.alert is raises and result.review and not result.automatic_enforcement_allowed
    if raises:assert result.reason==DIRECT_REASON and result.score==.95


def setup(tmp_path):
    reader=ProtocolReview(SOURCE);obs,raw=observe(reader,1,'VERIFY KU OK')
    head,_,_=trained(tmp_path,obs,normal=0,attack=5)
    review=AttackEvidenceReview(head,SOURCE)
    assert review.refine(quiet(),LEGACY,obs,ordinal=1,raw=raw,moment=START).reason==DIRECT_REASON
    return reader,head,review


@pytest.mark.parametrize('peer,port,held',[('192.0.2.1',10000,True),('192.0.2.1',10001,False),
    ('203.0.113.2',10000,False)])
def test_retention_requires_exact_connection(tmp_path,peer,port,held):
    reader,_,review=setup(tmp_path)
    obs,raw=observe(reader,2,'Control Channel: TLSv1.3',at=1,peer=peer,port=port)
    result=review.refine(quiet(),LEGACY,obs,ordinal=2,raw=raw,moment=START+1)
    assert result.alert is held
    if held:assert result.reason==RETAINED_REASON


def test_same_timestamp_original_order_is_causal_and_retention_does_not_renew(tmp_path):
    reader,_,review=setup(tmp_path)
    for ordinal,at,body,expected in [(2,0,'Control Channel: TLSv1.3',True),
        (3,30,'TLS: Initial packet',True),(4,60,'VERIFY OK: depth=0, CN=claimed',True),
        (5,61,'Control Channel: TLSv1.3',False)]:
        obs,raw=observe(reader,ordinal,body,at=at)
        result=review.refine(quiet(),LEGACY,obs,ordinal=ordinal,raw=raw,moment=START+at)
        assert result.alert is expected
        if expected:assert result.reason==RETAINED_REASON


def test_no_future_trigger_and_no_source_sharing(tmp_path):
    first,_=observe(ProtocolReview(SOURCE),1,'VERIFY KU OK')
    head,_,_=trained(tmp_path,first,normal=0,attack=5)
    reader=ProtocolReview(SOURCE);review=AttackEvidenceReview(head,SOURCE)
    obs,raw=observe(reader,1,'Control Channel: TLSv1.3')
    assert not review.refine(quiet(),LEGACY,obs,ordinal=1,raw=raw,moment=START).alert
    _,_,triggered=setup(tmp_path)
    isolated=AttackEvidenceReview(head,'d'*64)
    raw_obs=replace(obs,source_sha256='d'*64)
    assert triggered.retained and not isolated.refine(quiet(),LEGACY,raw_obs,
        ordinal=1,raw=raw,moment=START).alert


@pytest.mark.parametrize('fault',['ordinal','regression','clock','missing_time','nan','unavailable'])
def test_bad_order_clock_or_availability_cannot_carry_learned_risk(tmp_path,fault):
    reader,_,review=setup(tmp_path)
    obs,raw=observe(reader,2,'Control Channel: TLSv1.3',at=2)
    moment=START+2;ordinal=2
    if fault=='ordinal':ordinal=3;obs=replace(obs,ordinal=3)
    if fault=='regression':
        obs,raw=observe(ProtocolReview(SOURCE),1,'Control Channel: TLSv1.3',at=-1)
        obs=replace(obs,ordinal=2);moment=START-1
    if fault=='clock':moment+=1
    if fault=='missing_time':moment=None
    if fault=='nan':moment=float('nan')
    if fault=='unavailable':obs=replace(obs,available=False,protected=True)
    previous=quiet()
    assert review.refine(previous,LEGACY,obs,ordinal=ordinal,raw=raw,moment=moment) is previous
    assert not review.retained
    if fault!='unavailable':assert review.disabled


@pytest.mark.parametrize('reason',['vpn_verified_current_denial','verified_current_execution_or_caller_denial',
    'unrelated_current_policy','unknown'])
def test_explicit_policy_and_other_independent_reasons_remain_unchanged(tmp_path,reason):
    reader,_,review=setup(tmp_path)
    obs,raw=observe(reader,2,'Control Channel: TLSv1.3',at=1)
    previous=OperationDecision(.95,.99,True,True,reason)
    assert review.refine(previous,LEGACY,obs,ordinal=2,raw=raw,moment=START+1) is previous


@pytest.mark.parametrize('fault',['source','line','ordinal_binding'])
def test_bound_raw_observation_is_checked_even_after_review_is_disabled(tmp_path,fault):
    reader,_,review=setup(tmp_path);review.disabled=True
    obs,raw=observe(reader,2,'Control Channel: TLSv1.3',at=1)
    if fault=='source':obs=replace(obs,source_sha256='d'*64)
    if fault=='line':raw+='changed'
    if fault=='ordinal_binding':obs=replace(obs,ordinal=3)
    with pytest.raises(ValueError,match='protocol_observation_binding'):
        review.refine(quiet(),LEGACY,obs,ordinal=2,raw=raw,moment=START+1)


def test_supported_normal_lowering_works_without_an_attack_trigger(tmp_path):
    obs,raw=observe(ProtocolReview(SOURCE),1,'VERIFY KU OK');head,_,_=trained(tmp_path,obs)
    previous=OperationDecision(.1,.99,True,True,'vpn_history_risk_review')
    result=AttackEvidenceReview(head,SOURCE).refine(previous,LEGACY,obs,ordinal=1,raw=raw,moment=START)
    assert not result.alert and result.reason=='learned_vpn_protocol_review' and result.review


def test_existing_alert_does_not_start_new_retention(tmp_path):
    obs,raw=observe(ProtocolReview(SOURCE),1,'VERIFY KU OK');head,_,_=trained(tmp_path,obs,normal=0,attack=5)
    review=AttackEvidenceReview(head,SOURCE)
    previous=OperationDecision(.1,.99,True,True,'vpn_history_risk_review')
    assert review.refine(previous,LEGACY,obs,ordinal=1,raw=raw,moment=START) is previous
    assert not review.retained


def test_opt_in_replay_accepts_previous_normalization_preserves_denials_and_all_rows(tmp_path,monkeypatch):
    raw,prep,_,baseline,_,_=io_packet(tmp_path)
    source,rows,_=records(raw,prep)[0];reader=ProtocolReview(source);projected={}
    head=ProtocolHead(MODELS)
    for ordinal,moment,body in rows:
        obs=reader.observe(ordinal,body,moment,source_sha256=source)
        previous=quiet() if ordinal==1 else OperationDecision(.1,.99,True,True,'vpn_history_risk_review')
        projected[ordinal]=(LEGACY,obs,previous)
        if ordinal in {1,2}:
            for _ in range(5):head.add(LEGACY,obs,ordinal==1)
    model=tmp_path/'head.json';pin=head.save(model);head=ProtocolHead.load(model,pin,MODELS)
    monkeypatch.setattr('scripts.run_vpn_protocol_review.project',lambda *_:projected)
    original=[json.loads(r) for r in baseline.read_text().splitlines()]
    for ordinal,row in enumerate(original[:-1],1):
        row.update(after=False,after_score=.1,
            reason='vpn_history_risk_review' if ordinal==1 else 'learned_vpn_protocol_review')
    baseline.write_text(''.join(json.dumps(r)+'\n' for r in original),encoding='utf8')
    default=predict(head,FixedLegacy(),prep,raw,baseline,sha(baseline),tmp_path/'default.jsonl')
    assert default['changed_alerts']==0 and default['direct_attack_reviews']==0
    enabled=predict(head,FixedLegacy(),prep,raw,baseline,sha(baseline),tmp_path/'enabled.jsonl',
        with_attack_evidence=True)
    assert enabled['changed_alerts']==6 and enabled['direct_attack_reviews']==1
    assert enabled['retained_attack_reviews']==5 and enabled['protected_baseline_mismatches']==0
    actual=[json.loads(r) for r in (tmp_path/'enabled.jsonl').read_text().splitlines()]
    assert len(actual)==7 and [r['case_id'] for r in actual]==[r['case_id'] for r in original]
    assert actual[-1]['after'] is None and actual[-1]['error']=='previous-error'
    original[1].update(after=True,after_score=.99,reason='vpn_verified_current_denial')
    baseline.write_text(''.join(json.dumps(r)+'\n' for r in original),encoding='utf8')
    guarded=predict(head,FixedLegacy(),prep,raw,baseline,sha(baseline),tmp_path/'guarded.jsonl',
        with_attack_evidence=True)
    assert guarded['changed_alerts']==5 and guarded['protected_baseline_mismatches']==1
    actual=json.loads((tmp_path/'guarded.jsonl').read_text().splitlines()[1])
    assert actual['after'] is True and actual['reason']=='vpn_verified_current_denial'


@pytest.mark.parametrize('value',[None,1,'true'])
def test_batch_attack_evidence_flag_requires_explicit_boolean(value):
    with pytest.raises(ValueError,match='protocol_attack_option'):
        batch('not-opened','unused','unused',with_attack_evidence=value)
