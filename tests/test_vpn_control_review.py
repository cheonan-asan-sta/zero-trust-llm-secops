import hashlib
import json
from dataclasses import replace

import pytest

from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.vpn_control_review import ControlHead, phase
from scripts.f1_lab.vpn_protocol_review import ProtocolReview
from scripts.run_vpn_protocol_review import predict, run
from tests.test_vpn_protocol_review import (
    MODELS,
    SOURCE,
    START,
    FixedLegacy,
    line,
    observe,
    trained,
)

BASE='c'*64
REQUEST="PUSH: Received control message: 'PUSH_REQUEST'"
REPLY="SENT CONTROL [alice]: 'PUSH_REPLY,redirect-gateway def1,block-outside-dns,route 10.9.0.1,topology net30,ping 10,ping-restart 120,ifconfig 10.9.0.6 10.9.0.5,peer-id 0,cipher AES-256-CBC' (status=1)"
STAGES=['TLS: Initial packet','VERIFY KU OK','VERIFY EKU OK','VERIFY OK: depth=0, CN=alice']


def session(*,omit=None,platform='linux',version='2.4.4',peer='192.0.2.1',at=0):
    reader=ProtocolReview(SOURCE);ordinal=0
    for body in [x for x in STAGES if x!=omit]+['peer info: IV_VER='+version,'peer info: IV_PLAT='+platform]:
        ordinal+=1;observe(reader,ordinal,body,peer=peer,at=at)
    return reader,ordinal


def head_for(tmp_path,obs,normal=5,attack=0):
    head=ControlHead(MODELS,BASE)
    for _ in range(normal):head.add(obs,False)
    for _ in range(attack):head.add(obs,True)
    path=tmp_path/'control.json';pin=head.save(path)
    return ControlHead.load(path,pin,MODELS,BASE),path,pin


def previous(reason='vpn_history_risk_review',baseline=.1):
    return OperationDecision(baseline,.99,True,True,reason)


def test_control_projection_ignores_client_claims_identifiers_and_absolute_time():
    a,n=session();one,raw=observe(a,n+1,REQUEST,name='alice')
    b,n=session(platform='win',version='9.0.0',peer='203.0.113.8',at=500)
    two,_=observe(b,n+1,REQUEST,name='other',peer='203.0.113.8',at=500)
    assert one.control.projection_sha256==two.control.projection_sha256
    assert one.control.line_sha256!=two.control.line_sha256
    assert phase(raw)=='request'


@pytest.mark.parametrize('missing',STAGES)
def test_control_requires_preceding_complete_handshake(missing):
    r,n=session(omit=missing);obs,_=observe(r,n+1,REQUEST,name='alice')
    assert obs.control is None


def test_restarted_different_or_expired_connection_cannot_borrow_a_handshake():
    for variant in ['restart','other','expired']:
        r,n=session()
        if variant=='restart':n+=1;observe(r,n,'TLS: Initial packet')
        obs,_=observe(r,n+1,REQUEST,name='alice',port=10001 if variant=='other' else 10000,
            at=301 if variant=='expired' else 0)
        assert obs.control is None


def test_request_and_reply_are_separate_cells_not_pooled_for_support(tmp_path):
    r,n=session();request,_=observe(r,n+1,REQUEST,name='alice');reply,raw=observe(r,n+2,REPLY,name='alice')
    assert request.control.projection_sha256!=reply.control.projection_sha256
    head,_,_=head_for(tmp_path,request.control,normal=5)
    before=previous()
    assert head.refine(before,reply.control,source_sha256=SOURCE,ordinal=n+2,raw=raw) is before


@pytest.mark.parametrize('normal,attack,lower',[(4,0,False),(5,0,True),(100,1,False)])
def test_minimum_support_attack_veto_and_advisory_only(tmp_path,normal,attack,lower):
    r,n=session();obs,raw=observe(r,n+1,REQUEST,name='alice')
    head,_,_=head_for(tmp_path,obs.control,normal,attack)
    result=head.refine(previous(),obs.control,source_sha256=SOURCE,ordinal=n+1,raw=raw)
    assert result.alert is (not lower) and result.review and result.automatic_enforcement_allowed is False
    if lower:assert result.reason=='learned_vpn_control_review'


@pytest.mark.parametrize('reason,baseline',[
    ('vpn_verified_current_denial',.1),('verified_current_execution_or_caller_denial',.1),
    ('learned_vpn_attack_evidence',.1),('vpn_attack_evidence_retained',.1),
    ('vpn_history_risk_review',.95),('unknown',.1)])
def test_current_denials_other_attack_reasons_and_intrinsic_risk_are_preserved(tmp_path,reason,baseline):
    r,n=session();obs,raw=observe(r,n+1,REQUEST,name='alice');head,_,_=head_for(tmp_path,obs.control)
    before=previous(reason,baseline)
    assert head.refine(before,obs.control,source_sha256=SOURCE,ordinal=n+1,raw=raw) is before


@pytest.mark.parametrize('at,protected',[(60,True),(61,False)])
def test_prior_failure_survives_control_success_until_original_expiry(tmp_path,at,protected):
    r,n=session();n+=1;observe(r,n,'AUTH_FAILED')
    obs,raw=observe(r,n+1,REQUEST,name='alice',at=at)
    assert obs.control.protected is protected
    head,_,_=head_for(tmp_path,obs.control);before=previous()
    after=head.refine(before,obs.control,source_sha256=SOURCE,ordinal=n+1,raw=raw)
    assert after.alert is protected


@pytest.mark.parametrize('fault',['source','ordinal','raw'])
def test_control_source_ordinal_and_bytes_must_match(tmp_path,fault):
    r,n=session();obs,raw=observe(r,n+1,REQUEST,name='alice');head,_,_=head_for(tmp_path,obs.control)
    args={'source_sha256':SOURCE,'ordinal':n+1,'raw':raw}
    if fault=='source':args['source_sha256']='f'*64
    if fault=='ordinal':args['ordinal']=n+2
    if fault=='raw':args['raw']=raw+'changed'
    with pytest.raises(ValueError):head.refine(previous(),obs.control,**args)


@pytest.mark.parametrize('bad',[
    REPLY.replace('[alice]','[bob]'),REPLY.replace('status=1','status=0'),
    REPLY.replace('ping 10','ping 0'),REPLY.replace('peer-id 0','peer-id -1'),
    REPLY.replace('10.9.0.1','999.9.0.1'),REPLY.replace('route 10.9.0.1','route 10.9.0.1 255.0.255.0'),
    REPLY.replace('cipher AES-256-CBC','script /tmp/payload'),
    REPLY.replace('ping 10','ping 10;echo bad'),REPLY.replace('ping 10','ping 10,ping 10'),
    REPLY.replace('ifconfig 10.9.0.6 10.9.0.5','ifconfig 10.9.0.6'),
    REPLY.replace('topology net30','topology unknown'),REQUEST+' trailing',
])
def test_malformed_unknown_or_ambiguous_control_messages_remain_unlowered(bad):
    r,n=session();obs,_=observe(r,n+1,bad,name='alice')
    assert obs.control is None


@pytest.mark.parametrize('fault',['pin','base','legacy','minimum','count_bool','negative','scope'])
def test_model_pins_scope_and_counts_are_strict(tmp_path,fault):
    r,n=session();obs,_=observe(r,n+1,REQUEST,name='alice');_,path,pin=head_for(tmp_path,obs.control)
    legacy,base=MODELS,BASE
    if fault=='pin':pin='f'*64
    elif fault=='base':base='f'*64
    elif fault=='legacy':legacy='f'*64
    else:
        value=json.loads(path.read_bytes());key=next(iter(value['rows']))
        if fault=='minimum':value['minimum_support']=4
        if fault=='count_bool':value['rows'][key][0]=True
        if fault=='negative':value['rows'][key][1]=-1
        if fault=='scope':value['automatic_enforcement_allowed']=True
        path.write_text(json.dumps(value),encoding='utf8');pin=sha(path)
    with pytest.raises(ValueError):ControlHead.load(path,pin,legacy,base)


def test_optional_model_pair_is_checked_before_reading_plan():
    with pytest.raises(ValueError,match='control_model_pair'):
        run('missing','missing','missing','missing','missing','missing','unused',control_model='missing')


def test_mutable_head_and_invalid_score_are_rejected(tmp_path):
    r,n=session();obs,raw=observe(r,n+1,REQUEST,name='alice');head,_,_=head_for(tmp_path,obs.control)
    with pytest.raises(ValueError):head.add(obs.control,False)
    with pytest.raises(ValueError):head.refine(replace(previous(),score=float('nan')),obs.control,
        source_sha256=SOURCE,ordinal=n+1,raw=raw)


def test_replay_default_is_unchanged_and_explicit_model_preserves_denial_and_error(tmp_path):
    raw=tmp_path/'raw';raw.mkdir();source=raw/'pair-0-raw.source'
    bodies=[*STAGES,REQUEST,REQUEST,REQUEST]
    source.write_bytes(''.join(line(b,name='alice' if n>=4 else '') for n,b in enumerate(bodies)).encode())
    pin=sha(source);member='gather/vpn/logs/openvpn.log'
    dump=lambda p,v:p.write_text(json.dumps(v),encoding='utf8')
    dump(raw/'audit.json',{'completed':True,'timestamp_basis':
        'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
        'pairs':[{'provenance':{'raw_member':member,'raw_sha256':pin,'simulation_start':START,'simulation_end':START+1000}}]})
    prep={'completed':True,'inputs_contain_truth':False,'source_manifest_sha256':sha(raw/'audit.json'),
        'pairs':[{'raw_member':member,'raw_sha256':pin,'rows':len(bodies)}]}
    reader=ProtocolReview(pin);observed=[]
    for n,b in enumerate(bodies,1):
        observed.append(reader.observe(n,line(b,name='alice' if n>=5 else ''),START,source_sha256=pin))
    head,_,_=trained(tmp_path,observed[0],normal=0,attack=5)
    control_path=tmp_path/'control-dir';control_path.mkdir()
    control,_,_=head_for(control_path,observed[4].control)
    rows=[{'case_id':hashlib.sha256((pin+':'+str(n)).encode()).hexdigest(),'source_index':0,
        'before':True,'after':True,'before_score':.99,'after_score':.99,
        'reason':'vpn_verified_current_denial' if n==6 else 'vpn_history_risk_review',
        'error':'preserved-error' if n==7 else None} for n in range(1,len(bodies)+1)]
    baseline=tmp_path/'baseline.jsonl';baseline.write_text(''.join(json.dumps(x)+'\n' for x in rows),encoding='utf8')
    for enabled in [False,True]:
        output=tmp_path/('enabled.jsonl' if enabled else 'default.jsonl')
        report=predict(head,FixedLegacy(),prep,raw,baseline,sha(baseline),output,control_head=control if enabled else None)
        actual=[json.loads(b) for b in output.read_bytes().splitlines()]
        assert len(actual)==7 and report['inference_errors']==1 and report['changed_alerts']==int(enabled)
        assert actual[4]['after'] is (not enabled)
        assert actual[5]['after'] and actual[5]['reason']=='vpn_verified_current_denial'
        assert actual[6]['error']=='preserved-error' and actual[6]['before'] is actual[6]['after'] is None
