import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.security import Principal, Role
from scripts.f1_lab.operation_refinement import OperationDecision, OperationRefinement
from scripts.f1_lab.vpn_context import PROFILE
from scripts.f1_lab.web_context_controls import NOW, OPERATOR, WebControls, arguments
from scripts.f1_lab.web_durable_risk import DurableWebRisk
from scripts.f1_lab.web_evidence_ledger import LedgerUnavailable, WebEvidenceLedger
from scripts.f1_lab.web_residual import WebResidualRefinement
from scripts.f1_lab.web_verified_context import (
    VerifiedWebRisk,
    WebContextDecision,
    WebTrustBridge,
    digest_raw,
)


@pytest.fixture
def lab(tmp_path):
    c = WebControls(tmp_path/'controls')
    baseline = WebResidualRefinement(OperationRefinement(SimpleNamespace(probability=lambda _:.02),
        SimpleNamespace(profile=PROFILE,probability=lambda _:.98)))
    verified = VerifiedWebRisk(baseline,c.bridge)
    store = WebEvidenceLedger(tmp_path/'events.sqlite',tmp_path/'witness')
    store.initialize()
    return c,verified,store,DurableWebRisk(verified,store)


def invoke(model,row):
    return model.decide(row['challenge'].request,**arguments(row))


def test_adverse_is_durable_deduplicated_and_recovered_after_bridge_restart(lab):
    c,v,s,model = lab
    row = c.build(permission='deny')
    first = invoke(model,row)
    assert first.alert and first.verified_adverse and first.storage_state == 'recorded'
    original = s.summary(row['challenge'].request,OPERATOR,now=NOW)
    assert original['events'] == 2 and original['attempts'] == 1
    v.bridge = WebTrustBridge(c.pinned)  # No pending nonce or positive proof cache survives.
    reopened = WebEvidenceLedger(s.database,s.control)
    row['now'] = NOW+timedelta(minutes=2)
    result = invoke(DurableWebRisk(v,reopened),row)
    assert result.alert and result.review and result.score == 1. and result.evidence_state == 'retained_adverse'
    assert result.storage_state == 'duplicate'
    assert reopened.summary(row['challenge'].request,OPERATOR,now=row['now'])['events'] == 2


@pytest.mark.parametrize('missing', [False,True])
def test_new_consistent_or_unavailable_proof_cannot_clear_prior_adverse(lab,missing):
    c,_v,s,model = lab
    row = c.build(permission='deny')
    assert invoke(model,row).alert
    later = c.build(index=1)  # Same exact request; a fresh challenge and different proof.
    if missing: later['bundle'] = None
    result = invoke(model,later)
    assert result.alert and result.verified_adverse and result.score == 1.
    assert result.evidence_state == 'retained_adverse'
    assert s.summary(later['challenge'].request,OPERATOR,now=NOW)['events'] == 4


def test_baseline_only_review_is_saved_once_without_inventing_verified_evidence(lab):
    c,_v,s,model = lab
    row = c.build()
    row['nonce'] = None
    value = invoke(model,row)
    assert not value.alert and value.review and not value.verified_adverse
    assert value.evidence_state == 'baseline_only'
    assert invoke(model,row).storage_state == 'duplicate'
    summary = s.summary(row['challenge'].request,OPERATOR,now=NOW)
    assert summary['events'] == 2 and not summary['verified_adverse']


def test_exact_concurrent_retries_verify_once_and_persist_one_result(lab,monkeypatch):
    c,v,s,model = lab
    row = c.build(permission='deny')
    actual,calls = v.bridge.check,[]
    def check(*args,**kwargs):
        calls.append(1)
        return actual(*args,**kwargs)
    monkeypatch.setattr(v.bridge,'check',check)
    with ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(lambda _:invoke(model,row),range(4)))
    assert all(r.alert for r in values) and len(calls) == 1
    assert sum(r.storage_state == 'recorded' for r in values) == 1
    assert s.summary(row['challenge'].request,OPERATOR,now=NOW)['events'] == 2


@pytest.mark.parametrize('field,value', [('body_sha256','b'*64),('session_version',1),('subject_id','other'),
    ('resource_id','other'),('session_id','other'),('case_id','b'*64)])
def test_same_request_id_with_different_content_cannot_rewrite_history(lab,field,value):
    c,v,s,model = lab
    row = c.build(permission='deny')
    invoke(model,row)
    request = row['challenge'].request.model_copy(update={field:value})
    baseline = v.baseline.decide(row['features'],row['case_id'],evidence=row['evidence'])
    with pytest.raises(LedgerUnavailable,match='identity_conflict'):
        s.begin(request,OPERATOR,'b'*64,baseline,deadline=NOW+timedelta(seconds=30),now=NOW)
    assert s.summary(row['challenge'].request,OPERATOR,now=NOW)['verified_adverse']


@pytest.mark.parametrize('principal', [Principal('other','web-lab',frozenset({Role.ANALYST}),'api_key'),
    Principal('viewer','web-lab',frozenset({Role.VIEWER}),'api_key'),
    Principal(OPERATOR.subject,'other',OPERATOR.roles,'oidc'),
    Principal(OPERATOR.subject,'web-lab',OPERATOR.roles,'disabled')])
def test_other_owner_tenant_viewer_or_disabled_auth_cannot_read_or_advance_clock(lab,principal):
    c,_v,s,model = lab
    row = c.build()
    invoke(model,row)
    with pytest.raises(LedgerUnavailable):
        s.summary(row['challenge'].request,principal,now=NOW+timedelta(hours=1))
    assert s.summary(row['challenge'].request,OPERATOR,now=NOW)['review']


def test_clock_high_water_and_configuration_binding_survive_restart(lab):
    c,_v,s,model = lab
    row = c.build()
    invoke(model,row)
    request = row['challenge'].request
    s.summary(request,OPERATOR,now=NOW+timedelta(seconds=5))
    with pytest.raises(LedgerUnavailable,match='clock_rollback'):
        WebEvidenceLedger(s.database,s.control).summary(request,OPERATOR,now=NOW)
    with pytest.raises(LedgerUnavailable,match='configuration'):
        WebEvidenceLedger(s.database,s.control,capacity=100).summary(request,OPERATOR,now=NOW+timedelta(seconds=5))


@pytest.mark.parametrize('damage', ['db_body','db_delete','witness','missing_witness','key','missing_key','corrupt_db'])
def test_database_or_independent_witness_damage_never_becomes_empty_healthy_history(lab,damage):
    c,_v,s,model = lab
    row = c.build(permission='deny')
    invoke(model,row)
    if damage in {'db_body','db_delete'}:
        with sqlite3.connect(s.database) as db:
            db.execute('UPDATE web_records SET body=? WHERE seq=2',('{}',)) if damage == 'db_body' else db.execute('DELETE FROM web_records WHERE seq=2')
    elif damage == 'witness':
        (s.control/'witness.json').write_text('{}')
    elif damage == 'missing_witness': (s.control/'witness.json').unlink()
    elif damage == 'key': (s.control/'witness.key').write_bytes(b'x'*32)
    elif damage == 'missing_key': (s.control/'witness.key').unlink()
    else: s.database.write_bytes(b'invalid database')
    with pytest.raises(LedgerUnavailable):
        s.summary(row['challenge'].request,OPERATOR,now=NOW)


def test_rolling_back_only_database_is_detected_by_newer_witness(lab):
    c,_v,s,model = lab
    before = s.database.read_bytes()
    row = c.build(permission='deny')
    invoke(model,row)
    s.database.write_bytes(before)
    with pytest.raises(LedgerUnavailable,match='rollback_or_witness_mismatch'):
        s.summary(row['challenge'].request,OPERATOR,now=NOW)


def test_completion_slots_are_reserved_for_all_pending_attempts(tmp_path,lab):
    c,v,_,_ = lab
    s = WebEvidenceLedger(tmp_path/'small.sqlite',tmp_path/'small-witness',capacity=4)
    s.initialize()
    rows = [c.build(index=i) for i in (1,2,3)]
    attempts = []
    for row in rows[:2]:
        before = v.baseline.decide(row['features'],row['case_id'],evidence=row['evidence'])
        attempts.append(s.begin(row['challenge'].request,OPERATOR,digest_raw(row['nonce']),before,
            deadline=row['challenge'].expires_at,now=NOW))
    with pytest.raises(LedgerUnavailable,match='capacity'):
        s.begin(rows[2]['challenge'].request,OPERATOR,'c'*64,before,deadline=NOW+timedelta(seconds=30),now=NOW)
    for row,attempt in zip(rows[:2],attempts,strict=True):
        result = v.decide(**arguments(row))
        s.finish(row['challenge'].request,OPERATOR,attempt,result,now=NOW)
        assert s.summary(row['challenge'].request,OPERATOR,now=NOW)['pending_attempts'] == 0


def test_completion_is_idempotent_but_conflicting_rewrite_is_rejected(lab):
    c,v,s,_ = lab
    row = c.build(permission='deny')
    before = v.baseline.decide(row['features'],row['case_id'],evidence=row['evidence'])
    a = s.begin(row['challenge'].request,OPERATOR,digest_raw(row['nonce']),before,deadline=row['challenge'].expires_at,now=NOW)
    result = v.decide(**arguments(row))
    s.finish(row['challenge'].request,OPERATOR,a,result,now=NOW)
    s.finish(row['challenge'].request,OPERATOR,a,result,now=NOW)
    with pytest.raises(LedgerUnavailable,match='completion_conflict'):
        s.finish(row['challenge'].request,OPERATOR,a,before,now=NOW)
    assert s.summary(row['challenge'].request,OPERATOR,now=NOW)['events'] == 2


def test_failure_after_verification_is_unacknowledged_and_recovers_as_uncertain_review(lab,monkeypatch):
    c,_v,s,model = lab
    row = c.build(permission='deny')
    def fail(*_args,**_kwargs): raise OSError('simulated storage failure')
    with monkeypatch.context() as patch:
        patch.setattr(s,'finish',fail)
        with pytest.raises(LedgerUnavailable): invoke(model,row)
    state = s.summary(row['challenge'].request,OPERATOR,now=NOW)
    assert state['pending_attempts'] == 1 and state['review'] and not state['verified_adverse']
    assert invoke(model,row).storage_state == 'pending'
    with pytest.raises(LedgerUnavailable,match='still_active'):
        s.recover_pending(row['challenge'].request,OPERATOR,now=NOW)
    recovered = s.recover_pending(row['challenge'].request,OPERATOR,now=NOW+timedelta(seconds=31))
    assert recovered['interrupted'] and recovered['review'] and not recovered['verified_adverse']


def test_storage_failure_precedes_proof_consumption_and_production_is_rejected(lab,monkeypatch):
    c,v,s,model = lab
    row = c.build(permission='deny')
    with monkeypatch.context() as patch:
        patch.setattr('scripts.f1_lab.web_evidence_ledger.get_settings',lambda:SimpleNamespace(app_environment='production'))
        with pytest.raises(LedgerUnavailable,match='local_test_only'): invoke(model,row)
    assert row['nonce'] in v.bridge.pending
    s.database.unlink()
    with pytest.raises(LedgerUnavailable): invoke(model,row)
    assert row['nonce'] in v.bridge.pending and not s.database.exists()


CHILD = r'''
import json,os,sys
from pathlib import Path
from datetime import datetime
from app.security import Principal,Role
from scripts.f1_lab.web_evidence_ledger import WebEvidenceLedger,Attempt
from scripts.f1_lab.web_verified_context import WebRequest,WebContextDecision
from scripts.f1_lab.operation_refinement import OperationDecision
spec=json.loads(Path(sys.argv[1]).read_text())
s=WebEvidenceLedger(spec['database'],spec['control'])
s._phase=lambda point: os._exit(74) if point==sys.argv[2] else None
r=WebRequest.model_validate(spec['request'])
p=Principal('web-control-operator','web-lab',frozenset({Role.ANALYST}),'api_key')
now=datetime.fromisoformat(spec['now'])
if spec['operation']=='begin':
    s.begin(r,p,'a'*64,OperationDecision(.02,.02,False,True,'existing_review'),deadline=datetime.fromisoformat(spec['deadline']),now=now)
else:
    s.finish(r,p,Attempt(**spec['attempt']),WebContextDecision(**spec['decision']),now=now)
raise SystemExit(3)
'''


@pytest.mark.parametrize('operation', ['begin','finish'])
@pytest.mark.parametrize('point,committed', [('after_prepare',False),('before_db_commit',False),
                                          ('after_db_commit',True),('after_publish',True)])
def test_actual_process_exit_at_durable_boundaries_recovers_without_false_success(lab,tmp_path,operation,point,committed):
    c,v,s,_ = lab
    row = c.build(permission='deny')
    spec = {'database':str(s.database),'control':str(s.control),'request':row['challenge'].request.model_dump(mode='json'),
        'now':NOW.isoformat(),'deadline':row['challenge'].expires_at.isoformat(),'operation':operation}
    if operation == 'finish':
        before = v.baseline.decide(row['features'],row['case_id'],evidence=row['evidence'])
        attempt = s.begin(row['challenge'].request,OPERATOR,'a'*64,before,deadline=row['challenge'].expires_at,now=NOW)
        result = v.decide(**arguments(row))
        spec.update(attempt=asdict(attempt),decision=asdict(result))
    path = tmp_path/'child.json'
    path.write_text(json.dumps(spec))
    process = subprocess.run([sys.executable,'-c',CHILD,str(path),point],cwd=Path(__file__).resolve().parents[1],
                             capture_output=True,text=True,timeout=30,check=False,
                             env={**os.environ,'AWS_EC2_METADATA_DISABLED':'true'})
    assert process.returncode == 74, process.stderr
    reopened = WebEvidenceLedger(s.database,s.control)
    summary = reopened.summary(row['challenge'].request,OPERATOR,now=NOW)
    if operation == 'begin' and not committed:
        assert summary is None
    else:
        assert summary['verified_adverse'] == (operation == 'finish' and committed)
        if summary['pending_attempts']:
            summary = reopened.recover_pending(row['challenge'].request,OPERATOR,now=NOW+timedelta(seconds=31))
            assert summary['review'] and summary['interrupted'] and not summary['verified_adverse']


def test_schema_and_missing_fields_cannot_record_fake_adverse_or_keys(lab):
    c,_v,s,model = lab
    row = c.build()
    before = OperationDecision(.02,.02,False,True,'existing_review')
    with pytest.raises(LedgerUnavailable):
        s.begin(row['challenge'].request,OPERATOR,'bad',before,deadline=row['challenge'].expires_at,now=NOW)
    invoke(model,row)
    with sqlite3.connect(s.database) as db:
        text = ''.join(r[0] for r in db.execute('SELECT body FROM web_records'))
    assert all(value not in text for value in [row['nonce'],'web-user','web-session','parameters=','192.0.2.1','BEGIN PRIVATE KEY'])
    assert (s.control/'witness.key').stat().st_size == 32  # Local integrity secret, not a signing/API key.


def test_nonce_cannot_be_reused_under_another_request_identity(lab):
    c,v,s,_ = lab
    rows = [c.build(index=i) for i in (1,2)]
    before = v.baseline.decide(rows[0]['features'],rows[0]['case_id'],evidence=rows[0]['evidence'])
    s.begin(rows[0]['challenge'].request,OPERATOR,'a'*64,before,deadline=rows[0]['challenge'].expires_at,now=NOW)
    with pytest.raises(LedgerUnavailable,match='nonce_scope_conflict'):
        s.begin(rows[1]['challenge'].request,OPERATOR,'a'*64,before,deadline=rows[1]['challenge'].expires_at,now=NOW)


def test_adverse_label_without_verified_result_shape_cannot_be_committed(lab):
    c,v,s,_ = lab
    row = c.build()
    before = v.baseline.decide(row['features'],row['case_id'],evidence=row['evidence'])
    a = s.begin(row['challenge'].request,OPERATOR,'a'*64,before,deadline=row['challenge'].expires_at,now=NOW)
    fake = WebContextDecision(.02,.02,False,True,'unverified_claim',evidence_state='adverse',evidence_sha256='a'*64)
    with pytest.raises(LedgerUnavailable,match='adverse_shape'):
        s.finish(row['challenge'].request,OPERATOR,a,fake,now=NOW)
    assert not s.summary(row['challenge'].request,OPERATOR,now=NOW)['verified_adverse']


def test_distinct_processes_claim_the_same_attempt_once(lab,tmp_path):
    c,_v,s,_model = lab
    row = c.build()
    spec = {'database':str(s.database),'control':str(s.control),'request':row['challenge'].request.model_dump(mode='json'),
        'now':NOW.isoformat(),'deadline':row['challenge'].expires_at.isoformat(),'operation':'begin'}
    path = tmp_path/'concurrent.json'
    path.write_text(json.dumps(spec))
    script = CHILD.replace('s.begin(r,','a=s.begin(r,').replace('raise SystemExit(3)','print(json.dumps({"duplicate":a.duplicate}))')
    def call(_):
        return subprocess.run([sys.executable,'-c',script,str(path),'no_crash'],cwd=Path(__file__).resolve().parents[1],
            capture_output=True,text=True,timeout=30,check=False)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(call,range(2)))
    assert all(p.returncode == 0 for p in results), [p.stderr for p in results]
    assert sum(json.loads(p.stdout)['duplicate'] for p in results) == 1
    summary = s.summary(row['challenge'].request,OPERATOR,now=NOW)
    assert summary['events'] == 1 and summary['pending_attempts'] == 1


def test_reinitialize_cannot_overwrite_history(lab):
    c,_v,s,model = lab
    row = c.build(permission='deny')
    invoke(model,row)
    with pytest.raises(LedgerUnavailable,match='fresh_storage'): s.initialize()
    assert s.summary(row['challenge'].request,OPERATOR,now=NOW)['verified_adverse']
