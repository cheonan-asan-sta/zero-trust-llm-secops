import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from scripts.f1_lab.native_binary_tree import NativeBinaryTree
from scripts.f1_lab.native_heads import NativeHeads
from scripts.f1_lab.operation_context import ApacheContext, bound_contexts, canonical, core_features
from scripts.f1_lab.operation_refinement import (
    POLICY,
    OperationRefinement,
    load_operation_refinement,
)
from scripts.f1_lab.raw_semantics import PROFILE, semantic_observations
from scripts.f1_lab.vpn_context import PROFILE as VPN_PROFILE
from scripts.f1_lab.web_refinement import WebRefinement, fit_http_tree
from scripts.run_operation_refinement import bound_rows

SOURCE = 'a'*64


def warning(*, ip='192.0.2.1', message=None, module='php7', level='warn'):
    message = message or 'PHP Warning:  scandir(/var/cache/images/): failed to open dir: No such file or directory in /srv/app/cache.php on line 19'
    return f'[Tue Jan 18 10:07:23.284717 2022] [{module}:{level}] [pid 100] [client {ip}:12345] {message}\n'


def error(ip='192.0.2.1'):
    return warning(ip=ip, module='authz_core', level='error', message='AH01630: client denied by server configuration: /srv/app/.htaccess')


def feature(line):
    return {**core_features(line), **semantic_observations(line)}


def model(*, score=1., vpn_score=.987):
    return OperationRefinement(SimpleNamespace(probability=lambda _: score),
        SimpleNamespace(profile=VPN_PROFILE, probability=lambda _: vpn_score))


def context(line, *, moment=10, kind='apache_error', ordinal=1):
    return next(iter(bound_contexts([(ordinal, moment, line)], kind, SOURCE).values()))


def test_warning_is_narrowly_reclassified_without_grant_or_label_input():
    line = warning()
    observed = context(line)
    value = model().decide(feature(line), observed.case_id, observed)
    assert value.baseline_score == 1 and value.score == .05 and not value.alert and not value.review
    assert not value.automatic_enforcement_allowed
    assert value.reason == 'apache_missing_directory_warning'
    second = warning(message='PHP Warning:  scandir(): (errno 2): No such file or directory in /new/site/code.php on line 981')
    other = context(second)
    assert not model().decide(feature(second), other.case_id, other).alert


@pytest.mark.parametrize('changes', [
    {'level':'error'}, {'level':'notice'}, {'module':'authz_core'},
    {'message':'PHP Warning: file_get_contents(/tmp/missing): No such file or directory'},
    {'message':'PHP Fatal error: Uncaught exception'}, {'ip':'unknown'},
])
def test_other_errors_warning_functions_modules_or_unknown_peers_keep_baseline(changes):
    line = warning(**changes)
    observed = context(line)
    assert model().decide(feature(line), observed.case_id, observed).alert


@pytest.mark.parametrize('payload', ['/etc/passwd', '../secret', '%252e%252e%252fsecret',
    'eval%2528x%2529', 'shell_exec(x)', 'x;id', '$(id)', 'x&&id', 'sqlmap'])
def test_warning_text_cannot_hide_payload_or_double_encoded_execution(payload):
    line = warning(message=f'PHP Warning: scandir({payload}): failed to open dir: No such file or directory in /srv/app/cache.php on line 19')
    observed = context(line)
    assert observed.apache.payload_signal
    assert model().decide(feature(line), observed.case_id, observed).alert


def test_same_time_batch_sees_no_future_rows_and_strict_past_is_source_client_scoped():
    a, b = error(), warning()
    tied = bound_contexts([(2,10,b),(1,10,a)],'apache_error',SOURCE)
    assert not tied[context(b,ordinal=2).case_id].apache.recent_security_error
    before = bound_contexts([(1,9,a),(2,10,b)],'apache_error',SOURCE)
    current = before[context(b,ordinal=2).case_id]
    assert current.apache.recent_security_error and model().decide(feature(b),current.case_id,current).alert
    future = bound_contexts([(1,9,a),(2,10,b),(3,11,error())],'apache_error',SOURCE)
    assert before[current.case_id] == future[current.case_id]
    isolated = bound_contexts([(1,9,error('192.0.2.2')),(2,10,b)],'apache_error',SOURCE)
    assert not isolated[current.case_id].apache.recent_security_error
    assert not context(b).apache.recent_security_error


def test_error_lookback_is_inclusive_and_missing_time_is_not_benign():
    line = warning()
    values = bound_contexts([(1,0,error()),(2,60,line),(3,60.001,line)],'apache_error',SOURCE)
    assert values[context(line,ordinal=2).case_id].apache.recent_security_error
    assert not values[context(line,ordinal=3).case_id].apache.recent_security_error
    missing = context(line,moment=None)
    assert not missing.apache.time_available and model().decide(feature(line),missing.case_id,missing).alert


@pytest.mark.parametrize('records', [[(1,0,warning()),(1,1,warning())],[(0,0,warning())],[(1,float('nan'),warning())]])
def test_bad_context_records_fail_before_any_reclassification(records):
    with pytest.raises(ValueError):
        bound_contexts(records,'apache_error',SOURCE)


def test_context_binding_rejects_cross_case_and_feature_drift():
    line = warning()
    observed = context(line)
    with pytest.raises(ValueError,match='case_binding'):
        model().decide(feature(line),'b'*64,observed)
    changed = {**feature(line),'http_target_size':1}
    with pytest.raises(ValueError,match='feature_binding'):
        model().decide(changed,observed.case_id,observed)
    assert model().decide(feature(line),observed.case_id,None).alert


@pytest.mark.parametrize('score,alert,review',[(.989,True,True),(.9425,False,True),(.89,False,False)])
def test_vpn_alert_and_review_operating_points_do_not_rescale_model_scores(score,alert,review):
    line = '2022-01-21 00:00:01 192.0.2.1:12345 TLS: Initial packet from client\n'
    observed = context(line,kind='vpn')
    value = model(score=0.,vpn_score=score).decide(feature(line),observed.case_id,observed)
    assert (value.alert,value.review)==(alert,review) and value.score == score
    assert not value.automatic_enforcement_allowed


def test_vpn_missing_peer_keeps_existing_alarm_and_history_is_strictly_past():
    initial = '2022-01-21 00:00:01 192.0.2.1:12345 TLS: Initial packet from client\n'
    later = '2022-01-21 00:00:02 alice/192.0.2.1:12345 VERIFY OK\n'
    tied = bound_contexts([(1,1,initial),(2,1,later)],'vpn',SOURCE)
    assert not tied[context(later,kind='vpn',ordinal=2).case_id].vpn_features['vpn_peer_seen_before']
    ordered = bound_contexts([(1,1,initial),(2,2,later)],'vpn',SOURCE)
    assert ordered[context(later,kind='vpn',ordinal=2).case_id].vpn_features['vpn_peer_seen_before']
    no_peer = '2022-01-21 00:00:01 global daemon observation\n'
    missing = context(no_peer,kind='vpn')
    assert model().decide(feature(no_peer),missing.case_id,missing).alert
    assert model().decide(feature(no_peer),missing.case_id,missing).reason == 'vpn_context_unavailable'


def test_missing_apache_record_and_untargeted_inputs_preserve_baseline():
    line = warning()
    observed = context(line)
    unknown = replace(observed,apache=ApacheContext())
    assert model().decide(feature(line),unknown.case_id,unknown).alert
    assert model(score=.1).decide(feature(line),'x',None).score == .1


@pytest.fixture
def artifacts(tmp_path):
    normal = feature('192.0.2.1 - - [21/Jan/2022:00:00:00 +0000] "GET /asset.js HTTP/1.1" 200 10 "-" "Mozilla/5.0"')
    attack = {**normal,'sql_injection':True}
    baseline = NativeHeads(profile=PROFILE,tree_variant='ordered_binary')
    for _ in range(10):
        baseline.observe_training(normal,False)
        baseline.observe_training(attack,True)
    baseline.fit()
    tree,_ = fit_http_tree(iter([(normal,False)]*10+[(attack,True)]*10))
    heads=tmp_path/'heads.json'
    heads.write_bytes(canonical(baseline.export())+b'\n')
    h=hashlib.sha256(heads.read_bytes()).hexdigest()
    web=tmp_path/'web.json'
    web.write_bytes(canonical(WebRefinement(baseline,h,tree,'c'*64).export())+b'\n')
    line = '2022-01-21 00:00:01 192.0.2.1:12345 TLS: Initial packet\n'
    vpn_f=context(line,kind='vpn').vpn_features
    vpn=NativeBinaryTree(profile=VPN_PROFILE)
    for _ in range(10):
        vpn.observe_training(vpn_f,True)
        vpn.observe_training({**vpn_f,'vpn_peer_seen_before':True},False)
    vpn.fit()
    vpn_path=tmp_path/'vpn.json'
    vpn_path.write_bytes(canonical(vpn.export())+b'\n')
    hashes={name:hashlib.sha256(p.read_bytes()).hexdigest() for name,p in [('web',web),('heads',heads),('vpn',vpn_path)]}
    policy=tmp_path/'policy.json'
    policy.write_bytes(canonical({**POLICY,**{k+'_model_sha256':v for k,v in hashes.items()}})+b'\n')
    return policy,web,heads,vpn_path,hashes,normal


def test_pinned_policy_loader_rejects_rehashed_threshold_relaxation(artifacts):
    policy,web,heads,vpn,hashes,normal=artifacts
    def load():
        return load_operation_refinement(policy,hashlib.sha256(policy.read_bytes()).hexdigest(),web,hashes['web'],heads,hashes['heads'],vpn,hashes['vpn'])
    loaded=load()
    assert loaded.decide(normal,'x').score == loaded.web_model.probability(normal)
    changed=json.loads(policy.read_bytes())
    changed['vpn_review_threshold']=.1
    policy.write_bytes(canonical(changed))
    with pytest.raises(ValueError,match='policy_contract'):
        load()


def test_bound_rows_rejects_rehashed_cross_source_case_ids(tmp_path):
    case=hashlib.sha256((SOURCE+':1').encode()).hexdigest()
    contents={'inputs.jsonl':{'case_id':case,'features':None,'observation_error':'test'},
              'truth.jsonl':{'case_id':case,'malicious':True,'attack_labels':['test']}}
    preparation={'pairs':[{'raw_sha256':SOURCE,'rows':1}],'files':{}}
    for name,data in contents.items():
        p=tmp_path/name
        p.write_bytes(canonical(data)+b'\n')
        preparation['files'][name]={'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    parsed = list(bound_rows(tmp_path,preparation))  # Consume EOF to verify both file hashes.
    assert parsed[0][1] == case
    for name,data in contents.items():
        data['case_id']='f'*64
        p=tmp_path/name
        p.write_bytes(canonical(data)+b'\n')
        preparation['files'][name]={'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    with pytest.raises(ValueError,match='raw_case_binding'):
        list(bound_rows(tmp_path,preparation))


def test_vpn_history_cannot_be_mutated_or_attached_to_different_core_features():
    line = '2022-01-21 00:00:01 192.0.2.1:12345 TLS: Initial packet\n'
    observed = context(line,kind='vpn')
    observed.vpn_features['vpn_peer_seen_before'] = True
    with pytest.raises(ValueError,match='vpn_context_changed'):
        model(score=0.).decide(feature(line),observed.case_id,observed)
    observed.vpn_features['http_target_size'] = 1
    forged = replace(observed,vpn_feature_sha256=hashlib.sha256(canonical(observed.vpn_features)).hexdigest())
    with pytest.raises(ValueError,match='vpn_core_binding'):
        model(score=0.).decide(feature(line),forged.case_id,forged)


def test_source_row_cap_and_unknown_kinds_fail_explicitly(monkeypatch):
    monkeypatch.setattr('scripts.f1_lab.operation_context.MAX_EVENTS',2)
    with pytest.raises(ValueError,match='source_kind_or_rows'):
        bound_contexts([(i,float(i),warning()) for i in (1,2,3)],'apache_error',SOURCE)
    with pytest.raises(ValueError,match='source_kind_or_rows'):
        bound_contexts([(1,1.,warning())],'untrusted_unknown_kind',SOURCE)


def test_valid_case_ids_do_not_bypass_truth_file_eof_hash(tmp_path):
    case=hashlib.sha256((SOURCE+':1').encode()).hexdigest()
    files={'inputs.jsonl':{'case_id':case,'features':None,'observation_error':'test'},
           'truth.jsonl':{'case_id':case,'malicious':False,'attack_labels':[]}}
    preparation={'pairs':[{'raw_sha256':SOURCE,'rows':1}],'files':{}}
    for name,data in files.items():
        p=tmp_path/name
        p.write_bytes(canonical(data)+b'\n')
        preparation['files'][name]={'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
    truth=tmp_path/'truth.jsonl'
    truth.write_bytes(truth.read_bytes().replace(b'false',b'true '))
    with pytest.raises(ValueError,match='prepared_hash_or_rows'):
        list(bound_rows(tmp_path,preparation))
