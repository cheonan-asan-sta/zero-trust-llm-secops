from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.models import AnalysisResult, PolicyDecision, SecurityAssessment
from app.response_workflow import (
    PlanRequest,
    ResponseWorkflow,
    TransitionRequest,
    WorkflowConflict,
    response_router,
)
from app.security import Principal, Role


def person(subject='requester', role=Role.ANALYST, tenant='a'):
    return Principal(subject, tenant, frozenset({role}), 'test')


def evidence():
    return AnalysisResult(event_id='event', analysis_id='analysis', tenant_id='a',
        analyzer='rule', latency_ms=1,
        assessment=SecurityAssessment(risk_score=90, risk_level='HIGH',
            violation_type='PRIVILEGE_ESCALATION', rationale='권한 불일치를 확인했습니다.',
            recommended_action='REDUCE_PRIVILEGE', confidence=.9, requires_human_review=True),
        policy_decision=PolicyDecision(action='REDUCE_PRIVILEGE', allowed=True,
            requires_human_review=True, reason='simulation'))


@pytest.fixture
def lab(tmp_path):
    service = ResponseWorkflow(tmp_path / 'actions.sqlite3')
    request = PlanRequest(event_id='event', analysis_id='analysis', request_key='key')
    record = evidence()
    plan = service.create(record, request, person(), now=1000)
    return service, request, record, plan


def change(version=1, note='checked scope'):
    return TransitionRequest(expected_version=version, note=note)


def test_restart_and_exactly_once_simulation(lab):
    service, _, _, plan = lab
    responder = person('reviewer', Role.RESPONDER)
    approved = service.transition(plan['id'], 'approve', change(), responder, now=1001)
    assert approved['version'] == 2
    restarted = ResponseWorkflow(service.path)
    with ThreadPoolExecutor(max_workers=4) as pool:
        receipts = list(pool.map(lambda _: restarted.transition(
            plan['id'], 'execute', change(2), responder, now=1002), range(8)))
    assert all(r == receipts[0] for r in receipts)
    assert receipts[0]['state'] == 'SIMULATED'
    assert len(receipts[0]['history']) == 3
    assert receipts[0]['result']['session_changes'] == 0
    assert receipts[0]['result']['external_calls'] == 0


@pytest.mark.parametrize('operation', ['approve', 'reject', 'execute'])
def test_self_action_refused(lab, operation):
    service, _, _, plan = lab
    with pytest.raises(WorkflowConflict):
        service.transition(plan['id'], operation, change(),
                           person('requester', Role.ADMIN), now=1001)


@pytest.mark.parametrize('operation', ['approve', 'reject', 'execute'])
def test_wrong_role_and_other_tenant(lab, operation):
    service, _, _, plan = lab
    with pytest.raises(PermissionError):
        service.transition(plan['id'], operation, change(), person('viewer', Role.VIEWER))
    with pytest.raises(LookupError):
        service.transition(plan['id'], operation, change(), person('other', Role.ADMIN, 'b'))


@pytest.mark.parametrize('at,version', [(1300, 1), (1001, 2)])
def test_expiry_and_stale_versions(lab, at, version):
    service, _, _, plan = lab
    with pytest.raises(WorkflowConflict):
        service.transition(plan['id'], 'approve', change(version),
                           person('reviewer', Role.RESPONDER), now=at)
    assert service.get(plan['id'], person())['state'] == 'PENDING'


def test_execute_requires_approval_and_rejected_is_terminal(lab):
    service, _, _, plan = lab
    actor = person('reviewer', Role.RESPONDER)
    with pytest.raises(WorkflowConflict):
        service.transition(plan['id'], 'execute', change(), actor, now=1001)
    service.transition(plan['id'], 'reject', change(), actor, now=1001)
    with pytest.raises(WorkflowConflict):
        service.transition(plan['id'], 'execute', change(2), actor, now=1002)


def test_idempotency_scope_and_changed_evidence(lab):
    service, request, record, plan = lab
    assert service.create(record, request, person(), now=1001) == plan
    with pytest.raises(WorkflowConflict):
        service.create(record, request, person('other'), now=1001)
    changed = record.model_copy(update={'assessment': record.assessment.model_copy(
        update={'risk_score': 99})})
    with pytest.raises(WorkflowConflict):
        service.create(changed, request, person(), now=1001)
    with pytest.raises(LookupError):
        service.create(record, request, person(tenant='b'))


def test_allow_cannot_be_used_as_response_plan(lab):
    service, request, record, _ = lab
    record.policy_decision.action = 'ALLOW'
    # A validated replacement preserves enum types.
    record.policy_decision = PolicyDecision(action='ALLOW', allowed=True,
        requires_human_review=False, reason='normal')
    with pytest.raises(WorkflowConflict):
        service.create(record, request, person())


def test_foreign_or_corrupt_database_is_not_reinitialized(tmp_path):
    import sqlite3
    path = tmp_path / 'foreign.sqlite3'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE important (value TEXT)')
    with pytest.raises(sqlite3.DatabaseError):
        ResponseWorkflow(path).get('missing', person())
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT count(*) FROM important').fetchone()[0] == 0


def test_production_workflow_unavailable(tmp_path):
    class Store:
        def integrity(self):
            raise AssertionError('production must not read local evidence')
    app = FastAPI()
    app.include_router(response_router(Settings(app_environment='production', auth_mode='api_key',
        api_key_sha256='0' * 64, response_workflow_db_path=tmp_path / 'never'), Store()))
    # Authentication may reject first; the service itself is never reached.
    assert TestClient(app).get('/response/plans/missing').status_code in {401, 404}
    assert not (tmp_path / 'never').exists()


def test_http_approval_flow_and_untrusted_action_rejected(tmp_path, monkeypatch):
    from hashlib import sha256

    current = {'subject': 'requester', 'roles': 'analyst'}
    def settings():
        return Settings(auth_mode='api_key', api_key_sha256=sha256(b'test-key').hexdigest(),
                        api_key_subject=current['subject'], api_key_roles=current['roles'],
                        api_key_tenant_id='a')
    monkeypatch.setattr('app.security.get_settings', settings)
    class Store:
        def integrity(self):
            return {'ok': True}

        def get(self, event_id, tenant):
            return evidence() if event_id == 'event' and tenant == 'a' else None
    app = FastAPI()
    app.include_router(response_router(Settings(response_workflow_db_path=tmp_path / 'ledger'),
                                       Store()))
    client = TestClient(app)
    headers = {'X-API-Key': 'test-key'}
    payload = {'event_id': 'event', 'analysis_id': 'analysis', 'request_key': 'key'}
    assert client.post('/response/plans', json=payload | {'action': 'ALLOW'},
                       headers=headers).status_code == 422
    created = client.post('/response/plans', json=payload, headers=headers)
    assert created.status_code == 201
    url = '/response/plans/' + created.json()['id']
    transition = {'expected_version': 1, 'note': 'reviewed evidence'}
    assert client.post(url + '/approve', json=transition, headers=headers).status_code == 403
    current.update(subject='reviewer', roles='responder')
    assert client.post(url + '/approve', json=transition, headers=headers).status_code == 200
    execution = transition | {'expected_version': 2}
    result = client.post(url + '/execute', json=execution, headers=headers)
    assert result.status_code == 200
    assert result.json()['state'] == 'SIMULATED'
    assert client.post(url + '/execute', json=execution, headers=headers).json() == result.json()
