import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.vpn_protocol_head import ProtocolHead
from scripts.f1_lab.vpn_protocol_review import ProtocolReview
from scripts.run_vpn_protocol_review import predict
from scripts.train_vpn_protocol import fit

SOURCE='a'*64
LEGACY='b'*64
MODELS='c'*64
START=int(datetime(2025,1,1,tzinfo=UTC).timestamp())


def line(body,*,at=0,peer='192.0.2.1',port=10000,name=''):
    stamp=datetime.fromtimestamp(START+at,UTC).strftime('%Y-%m-%d %H:%M:%S')
    return f'{stamp} {name+"/" if name else ""}{peer}:{port} {body}\n'


def observe(reader,ordinal,body,*,at=0,peer='192.0.2.1',port=10000,name=''):
    raw=line(body,at=at,peer=peer,port=port,name=name)
    return reader.observe(ordinal,raw,START+at,source_sha256=SOURCE),raw


def trained(tmp_path,observation,normal=5,attack=0):
    model=ProtocolHead(MODELS)
    for _ in range(normal):model.add(LEGACY,observation,False)
    for _ in range(attack):model.add(LEGACY,observation,True)
    path=tmp_path/f'model-{normal}-{attack}.json';pin=model.save(path)
    return ProtocolHead.load(path,pin,MODELS),path,pin


def test_identifiers_and_absolute_time_are_not_learned_projection_values():
    a,b=ProtocolReview(SOURCE),ProtocolReview(SOURCE)
    for n,body in enumerate(['TLS: Initial packet','VERIFY OK: depth=0, CN=user-a','peer info: IV_PLAT=linux'],1):
        first,_=observe(a,n,body)
        second,_=observe(b,n,body.replace('user-a','user-b'),at=1000,peer='203.0.113.50')
        assert first.projection_sha256==second.projection_sha256
        assert first.line_sha256!=second.line_sha256 and first.available and second.available


def test_past_state_not_future_and_connection_restart_resets_only_protocol():
    r=ProtocolReview(SOURCE)
    initial,_=observe(r,1,'TLS: Initial packet')
    old=initial.projection_sha256
    observe(r,2,'VERIFY OK: depth=0, CN=first')
    later,_=observe(r,3,'Control Channel: TLSv1.3')
    assert initial.projection_sha256==old
    fresh=ProtocolReview(SOURCE);blank,_=observe(fresh,1,'Control Channel: TLSv1.3')
    assert later.projection_sha256!=blank.projection_sha256
    observe(r,4,'TLS: Initial packet')
    restarted,_=observe(r,5,'Control Channel: TLSv1.3')
    other=ProtocolReview(SOURCE);observe(other,1,'TLS: Initial packet',port=9999)
    observe(other,2,'VERIFY OK: depth=0, CN=first',port=9999)
    observe(other,3,'TLS: Initial packet')
    expected,_=observe(other,4,'Control Channel: TLSv1.3')
    assert restarted.projection_sha256==expected.projection_sha256


def test_idle_connection_state_expires_without_reusing_certificate_stages():
    a,b=ProtocolReview(SOURCE),ProtocolReview(SOURCE)
    for reader,port in [(a,10000),(b,9999)]:
        observe(reader,1,'TLS: Initial packet',port=port)
        observe(reader,2,'VERIFY OK: depth=0, CN=first',port=port)
    expired,_=observe(a,3,'Control Channel: TLSv1.3',at=301)
    never_connected,_=observe(b,3,'Control Channel: TLSv1.3',at=301)
    assert expired.projection_sha256==never_connected.projection_sha256


@pytest.mark.parametrize('failure',['TLS Error: TLS handshake failed','AUTH_FAILED',
    'VERIFY ERROR: depth=0, certificate has expired','payload /etc/shadow'])
def test_actual_adverse_event_survives_success_renegotiation_and_port_change(failure):
    r=ProtocolReview(SOURCE);bad,_=observe(r,1,failure)
    assert bad.protected
    success,_=observe(r,2,'TLS: Initial packet',at=1,port=10001)
    assert success.protected
    current,_=observe(r,3,'VERIFY OK: depth=0, CN=claimed',at=60,port=10001)
    assert current.protected
    expired,_=observe(r,4,'Control Channel: TLSv1.3',at=61,port=10001)
    assert not expired.protected


def test_unbound_failure_cannot_be_cleared_by_a_later_bound_success():
    r=ProtocolReview(SOURCE)
    raw=datetime.fromtimestamp(START,UTC).strftime('%Y-%m-%d %H:%M:%S')+' TLS Error: failed\n'
    bad=r.observe(1,raw,START,source_sha256=SOURCE)
    success,_=observe(r,2,'VERIFY KU OK',at=1)
    assert not bad.available and bad.protected and success.protected


@pytest.mark.parametrize('mode',['source','ordinal','regression','clock','missing_time','malformed_time'])
def test_ambiguous_source_order_or_clock_disables_lowering(mode):
    r=ProtocolReview(SOURCE);observe(r,1,'TLS: Initial packet',at=2)
    raw=line('VERIFY KU OK',at=3);ordinal=2;source=SOURCE;moment=START+3
    if mode=='source':source='f'*64
    if mode=='ordinal':ordinal=3
    if mode=='regression':raw=line('VERIFY KU OK',at=1);moment=START+1
    if mode=='clock':moment=START+4
    if mode=='missing_time':moment=None
    if mode=='malformed_time':raw='not a timestamp\n'
    result=r.observe(ordinal,raw,moment,source_sha256=source)
    assert not result.available and result.protected
    later,_=observe(r,3,'VERIFY KU OK',at=5)
    assert not later.available and later.protected


@pytest.mark.parametrize('normal,attack,lower',[(4,0,False),(5,0,True),(100,1,False)])
def test_frozen_training_support_attack_veto_and_review_retention(tmp_path,normal,attack,lower):
    obs,raw=observe(ProtocolReview(SOURCE),1,'VERIFY KU OK')
    head,_,_=trained(tmp_path,obs,normal,attack)
    previous=OperationDecision(.1,.99,True,True,'vpn_history_risk_review')
    after=head.refine(previous,LEGACY,obs,source_sha256=SOURCE,ordinal=1,raw=raw)
    assert after.alert is (not lower) and after.review and not after.automatic_enforcement_allowed


@pytest.mark.parametrize('reason,baseline',[('verified_current_execution_or_caller_denial',.1),
    ('vpn_verified_current_denial',.1),('vpn_strict_past_risk_retained',.95),('unknown',.1)])
def test_independent_and_explicit_risk_is_never_lowered(tmp_path,reason,baseline):
    obs,raw=observe(ProtocolReview(SOURCE),1,'VERIFY KU OK');head,_,_=trained(tmp_path,obs)
    previous=OperationDecision(baseline,.99,True,True,reason)
    assert head.refine(previous,LEGACY,obs,source_sha256=SOURCE,ordinal=1,raw=raw) is previous


def test_prior_adverse_cannot_be_overridden_even_by_a_supported_normal_cell(tmp_path):
    r=ProtocolReview(SOURCE);observe(r,1,'AUTH_FAILED')
    obs,raw=observe(r,2,'VERIFY KU OK',at=1)
    head,_,_=trained(tmp_path,obs,normal=100)
    previous=OperationDecision(.1,.99,True,True,'vpn_strict_past_risk_retained')
    assert head.refine(previous,LEGACY,obs,source_sha256=SOURCE,ordinal=2,raw=raw) is previous


def test_model_binding_observation_binding_and_frozen_state(tmp_path):
    obs,raw=observe(ProtocolReview(SOURCE),1,'VERIFY KU OK');head,path,pin=trained(tmp_path,obs)
    previous=OperationDecision(.1,.99,True,True,'vpn_history_risk_review')
    with pytest.raises(ValueError):ProtocolHead.load(path,'0'*64,MODELS)
    with pytest.raises(ValueError):ProtocolHead.load(path,pin,'0'*64)
    with pytest.raises(ValueError):head.add(LEGACY,obs,False)
    with pytest.raises(ValueError):head.refine(previous,LEGACY,replace(obs,line_sha256='f'*64),
        source_sha256=SOURCE,ordinal=1,raw=raw)
    value=json.loads(path.read_bytes());value['minimum_support']=True
    path.write_text(json.dumps(value),encoding='utf8')
    with pytest.raises(ValueError):ProtocolHead.load(path,hashlib.sha256(path.read_bytes()).hexdigest(),MODELS)


def test_invalid_scores_cannot_be_reported_as_success(tmp_path):
    obs,raw=observe(ProtocolReview(SOURCE),1,'VERIFY KU OK');head,_,_=trained(tmp_path,obs)
    with pytest.raises(ValueError):head.refine(OperationDecision(float('nan'),.99,True,True,
        'vpn_history_risk_review'),LEGACY,obs,source_sha256=SOURCE,ordinal=1,raw=raw)


class FixedVPN:
    def probability(self,_):return .99


class FixedLegacy:
    vpn_model=FixedVPN()

    def decide(self,_features,_case,_context):
        return OperationDecision(.1,.99,True,True,'vpn_history_risk_review')


def io_packet(tmp_path):
    raw=tmp_path/'raw';raw.mkdir()
    source=raw/'pair-0-raw.source';source.write_bytes((line('VERIFY KU OK')*6).encode())
    source_pin=sha(source);member='gather/vpn/logs/openvpn.log'
    manifest={'completed':True,'timestamp_basis':
        'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
        'pairs':[{'provenance':{'raw_member':member,'raw_sha256':source_pin,
            'simulation_start':START,'simulation_end':START+1000}},
            {'provenance':{'raw_member':'gather/web/logs/auth.log','raw_sha256':'d'*64,
                'simulation_start':START,'simulation_end':START+1000}}]}
    dump=lambda path,value:path.write_text(json.dumps(value),encoding='utf8')
    dump(raw/'audit.json',manifest)
    prep={'completed':True,'inputs_contain_truth':False,'source_manifest_sha256':sha(raw/'audit.json'),
        'pairs':[{'raw_member':member,'raw_sha256':source_pin,'rows':6},
            {'raw_member':'gather/web/logs/auth.log','raw_sha256':'d'*64,'rows':1}]}
    dump(tmp_path/'preparation.json',prep)
    rows=[]
    for index,pair in enumerate(prep['pairs']):
        for ordinal in range(1,pair['rows']+1):
            rows.append({'case_id':hashlib.sha256((pair['raw_sha256']+':'+str(ordinal)).encode()).hexdigest(),
                'source_index':index,'before':True,'after':True,'before_score':.99,'after_score':.99,
                'reason':'vpn_history_risk_review','error':None if index==0 else 'previous-error'})
    baseline=tmp_path/'baseline.jsonl'
    baseline.write_text(''.join(json.dumps(r)+'\n' for r in rows),encoding='utf8')
    truth=tmp_path/'truth.jsonl'
    truth.write_text(''.join(json.dumps({'case_id':r['case_id'],'malicious':False})+'\n' for r in rows),encoding='utf8')
    plan={'schema':'vpn-protocol-training-plan-1','scope':'observed_development','goal_qualified':False,
        'legacy_models':'unused-by-unit-stub','legacy_models_sha256':MODELS,
        'sources':[{'name':'arbitrary-training','role':'training','raw':str(raw),
            'preparation':str(tmp_path/'preparation.json'),'preparation_sha256':sha(tmp_path/'preparation.json'),
            'truth':str(truth),'truth_sha256':sha(truth)}]}
    dump(tmp_path/'plan.json',plan)
    return raw,prep,plan,baseline,truth,dump


def test_end_to_end_fit_replay_keeps_nonvpn_errors_population_and_explicit_denials(tmp_path,monkeypatch):
    raw,prep,_plan,baseline,_truth,_dump=io_packet(tmp_path)
    monkeypatch.setattr('scripts.train_vpn_protocol.legacy',lambda *_:(FixedLegacy(),MODELS))
    report=fit(tmp_path/'plan.json',sha(tmp_path/'plan.json'),tmp_path/'fit')
    assert report['training'][0]['population']==7 and report['training'][0]['vpn_available']==6
    head=ProtocolHead.load(tmp_path/'fit/model.json',report['model_sha256'],MODELS)
    output=tmp_path/'prediction.jsonl'
    result=predict(head,FixedLegacy(),prep,raw,baseline,sha(baseline),output)
    rows=[json.loads(r) for r in output.read_text().splitlines()]
    assert result['population']==7 and result['inference_errors']==1 and result['changed_alerts']==5
    assert result['protected_baseline_mismatches']==0 and result['validation_labels_opened'] is False
    assert rows[-1]['after'] is None and rows[-1]['error']=='previous-error'
    assert [r['case_id'] for r in rows]==[json.loads(r)['case_id'] for r in baseline.read_text().splitlines()]
    original=[json.loads(r) for r in baseline.read_text().splitlines()]
    original[1]['reason']='vpn_verified_current_denial'
    baseline.write_text(''.join(json.dumps(r)+'\n' for r in original),encoding='utf8')
    result=predict(head,FixedLegacy(),prep,raw,baseline,sha(baseline),tmp_path/'denial-prediction.jsonl')
    assert result['protected_baseline_mismatches']==1 and result['changed_alerts']==4
    assert json.loads((tmp_path/'denial-prediction.jsonl').read_text().splitlines()[1])['after'] is True


@pytest.mark.parametrize('fault',['evaluation_role','truth_case','raw_hash'])
def test_training_rejects_wrong_role_misaligned_labels_and_raw_drift(tmp_path,monkeypatch,fault):
    raw,_prep,plan,_baseline,truth,dump=io_packet(tmp_path)
    monkeypatch.setattr('scripts.train_vpn_protocol.legacy',lambda *_:(FixedLegacy(),MODELS))
    if fault=='evaluation_role':plan['sources'][0]['role']='evaluation'
    if fault=='truth_case':
        truth.write_text(truth.read_text().replace('case_id','not_case_id',1),encoding='utf8')
        plan['sources'][0]['truth_sha256']=sha(truth)
    if fault=='raw_hash':(raw/'pair-0-raw.source').write_text('tampered',encoding='utf8')
    dump(tmp_path/'plan.json',plan)
    with pytest.raises((ValueError,KeyError)):fit(tmp_path/'plan.json',sha(tmp_path/'plan.json'),tmp_path/'rejected')
