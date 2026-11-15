import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import SecurityEvent
from app.scenarios import synthetic_events
from app.security import Principal, Role, get_principal
from app.services.zero_trust import (
    JournalUnavailable,
    SessionConflict,
    SessionMissing,
    ZeroTrustOperations,
)
from app.zero_trust_models import (
    ProtectedAccessRequest,
    SessionEvaluationRequest,
    SessionRevocationRequest,
)

NOW = datetime.now(UTC)
PRINCIPAL = Principal("operator-a", "tenant-a", frozenset({Role.ADMIN}), "api_key")


def event(event_id="zt-event-1", *, when=NOW, **updates):
    data = synthetic_events()[0].model_dump(mode="json", exclude={"ground_truth"})
    data.update(event_id=event_id, timestamp=when)
    data["user"].update(role="employee", active=True)
    data["resource"].update(resource_id="zt-demo-documents", required_role=None)
    data["auth_context"].update(authentication_result="success", mfa="success")
    for key, value in updates.items():
        if isinstance(value, dict):
            data[key].update(value)
        else:
            data[key] = value
    return SecurityEvent.model_validate(data)


def evaluate(service, e=None, version=0, session_id="session-a", principal=PRINCIPAL, now=NOW):
    return service.evaluate(SessionEvaluationRequest(
        session_id=session_id, expected_version=version, event=e or event(),
    ), principal, now=now)


def access(service, token, *, principal=PRINCIPAL, now=NOW, resource="zt-demo-documents"):
    return service.access(ProtectedAccessRequest(
        session_id="session-a", resource_id=resource, action="READ", grant_token=token,
    ), principal, now=now)


@pytest.fixture
def service(tmp_path):
    return ZeroTrustOperations(tmp_path / "zt.sqlite3")


def test_allow_is_scoped_single_use_and_only_hash_is_persisted(service):
    result = evaluate(service)
    assert result.session.decision == "ALLOW"
    assert result.session.grant_expires_at <= NOW + timedelta(seconds=60)
    assert not access(service, result.grant_token, resource="zt-demo-vault").allowed
    assert access(service, result.grant_token).allowed
    assert not access(service, result.grant_token).allowed
    with sqlite3.connect(service.path) as conn:
        assert all(result.grant_token not in row[0] for row in conn.execute("SELECT payload FROM journal"))


def test_risk_change_revokes_previous_unconsumed_grant_and_cannot_self_reset(service):
    first = evaluate(service)
    second = evaluate(service, event("zt-event-2", when=NOW + timedelta(seconds=1),
                                    device={"security_posture": "compromised"}), version=1)
    assert second.session.status == "REVOKED"
    assert second.grant_token is None
    assert not access(service, first.grant_token).allowed
    recovered = evaluate(service, event("zt-event-3", when=NOW + timedelta(seconds=2)), version=2)
    assert recovered.session.decision == "DENY"
    assert "SESSION_ALREADY_REVOKED" in recovered.session.reason_codes


@pytest.mark.parametrize("updates,decision,reason", [
    ({"auth_context": {"mfa": "unknown"}}, "STEP_UP", "FRESH_MFA_REQUIRED"),
    ({"auth_context": {"authentication_result": "unknown"}}, "HOLD", "SIGNAL_INCOMPLETE"),
    ({"auth_context": {"authentication_result": "failure"}}, "DENY", "IDENTITY_DENIED"),
    ({"user": {"active": False}}, "DENY", "IDENTITY_DENIED"),
    ({"device": {"managed": False}}, "DENY", "MANAGED_DEVICE_REQUIRED"),
    ({"device": {"security_posture": "unknown"}}, "HOLD", "SIGNAL_INCOMPLETE"),
    ({"user": {"role": "guest"}}, "DENY", "RESOURCE_SCOPE_DENIED"),
    ({"action": "ADMIN"}, "DENY", "RESOURCE_SCOPE_DENIED"),
    ({"resource": {"resource_id": "not-registered"}}, "DENY", "RESOURCE_NOT_REGISTERED"),
])
def test_explicit_policy_checks_fail_closed(service, updates, decision, reason):
    result = evaluate(service, event(**updates))
    assert result.session.decision == decision
    assert reason in result.session.reason_codes
    assert result.grant_token is None


def test_client_cannot_lower_server_resource_sensitivity_or_requirements(service):
    result = evaluate(service, event(resource={"resource_id": "zt-demo-vault", "sensitivity": "public",
                                             "required_role": "employee"}))
    assert result.session.decision == "DENY"
    assert "RESOURCE_SCOPE_DENIED" in result.session.reason_codes
    assert "resource.sensitivity" in result.session.evidence


@pytest.mark.parametrize("offset", [-301, 31])
def test_stale_or_future_signals_do_not_authorize(service, offset):
    result = evaluate(service, event(when=NOW + timedelta(seconds=offset)))
    assert result.session.decision == "HOLD"
    assert result.grant_token is None


def test_ip_change_forces_step_up_even_on_office_network(service):
    first = evaluate(service)
    second = evaluate(service, event("zt-event-2", when=NOW + timedelta(seconds=1),
                                    network={"ip": "192.0.2.45", "access_method": "office"}), version=1)
    assert second.session.decision == "STEP_UP"
    assert not access(service, first.grant_token).allowed


def test_duplicate_is_idempotent_without_reissuing_grant_and_changed_replay_conflicts(service):
    first = evaluate(service)
    replay = evaluate(service)
    assert replay.duplicate and replay.session.version == 1 and replay.grant_token is None
    assert service.integrity()["verified_entries"] == 1
    with pytest.raises(SessionConflict):
        evaluate(service, event(user={"active": False}), version=1)
    assert access(service, first.grant_token).allowed


def test_order_identity_version_and_cross_session_replay_conflicts(service):
    evaluate(service)
    bad = [
        (event("old", when=NOW - timedelta(seconds=1)), 1, "session-a"),
        (event("wrong-version", when=NOW + timedelta(seconds=1)), 0, "session-a"),
        (event("other-device", when=NOW + timedelta(seconds=1), device={"device_id": "other"}), 1, "session-a"),
        (event(), 0, "session-b"),
    ]
    for item, version, session_id in bad:
        with pytest.raises(SessionConflict):
            evaluate(service, item, version=version, session_id=session_id)
    assert service.history("session-a", PRINCIPAL)[-1].version == 1


def test_tenant_and_operator_binding_and_restart(service):
    first = evaluate(service)
    other_tenant = Principal("operator-a", "tenant-b", PRINCIPAL.roles, "api_key")
    other_operator = Principal("operator-b", "tenant-a", PRINCIPAL.roles, "api_key")
    assert service.sessions(other_tenant) == []
    with pytest.raises(SessionMissing):
        service.history("session-a", other_tenant)
    assert not access(service, first.grant_token, principal=other_tenant).allowed
    assert not access(service, first.grant_token, principal=other_operator).allowed
    restored = ZeroTrustOperations(service.path)
    assert access(restored, first.grant_token).allowed


def test_expired_grant_cannot_access_and_policy_change_invalidates_grant(service):
    first = evaluate(service)
    assert not access(service, first.grant_token, now=NOW + timedelta(seconds=61)).allowed
    service.policy_digest = "0" * 64
    assert not access(service, first.grant_token).allowed


def test_operator_revocation_and_audit_round_trip(service):
    first = evaluate(service)
    result = service.revoke("session-a", SessionRevocationRequest(expected_version=1, note="검토 후 회수"),
                            PRINCIPAL, now=NOW + timedelta(seconds=1))
    assert result.version == 2 and result.status == "REVOKED"
    assert not access(service, first.grant_token).allowed
    assert len(ZeroTrustOperations(service.path).history("session-a", PRINCIPAL)) == 2


def test_journal_tampering_blocks_evaluation_access_and_readiness(service):
    first = evaluate(service)
    with sqlite3.connect(service.path) as conn:
        conn.execute("UPDATE journal SET payload=replace(payload,'POLICY_SATISFIED','TAMPERED') WHERE seq=1")
    assert not service.integrity()["ok"]
    with pytest.raises(JournalUnavailable):
        access(service, first.grant_token)
    with pytest.raises(JournalUnavailable):
        evaluate(service, event("second", when=NOW + timedelta(seconds=1)), version=1)


def test_concurrent_access_consumes_grant_once(service):
    token = evaluate(service).grant_token
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: access(service, token), range(2)))
    assert sum(item.allowed for item in results) == 1


def test_fresh_mfa_recovers_challenge_but_never_reuses_old_capability(service):
    first = evaluate(service)
    challenged = evaluate(service, event("mfa-missing", when=NOW + timedelta(seconds=1),
                                        auth_context={"mfa": "unknown"}), version=1)
    assert challenged.session.decision == "STEP_UP"
    assert not access(service, first.grant_token).allowed
    recovered = evaluate(service, event("mfa-verified", when=NOW + timedelta(seconds=2)), version=2)
    assert recovered.session.decision == "ALLOW"
    assert recovered.grant_token != first.grant_token
    assert access(service, recovered.grant_token).allowed


def test_concurrent_evaluations_do_not_overwrite_each_other(service):
    evaluate(service)
    def update(index):
        try:
            return evaluate(service, event(f"concurrent-{index}", when=NOW + timedelta(seconds=1)), version=1)
        except SessionConflict:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(update, range(2)))
    assert sum(result is not None for result in results) == 1
    assert len(service.history("session-a", PRINCIPAL)) == 2


def test_sigma_high_severity_is_included_in_access_decision(service):
    result = evaluate(service, event(
        action="DOWNLOAD", user={"role": "administrator"},
        resource={"resource_id": "zt-demo-vault", "sensitivity": "public"},
        behavior={"download_volume_mb": 700},
    ))
    assert result.session.matched_rule_ids
    assert result.session.risk_score >= 50
    assert result.session.decision == "DENY"


def test_missing_journal_table_fails_closed(service):
    first = evaluate(service)
    with sqlite3.connect(service.path) as conn:
        conn.execute("DROP TABLE journal")
    with pytest.raises(JournalUnavailable):
        access(service, first.grant_token)
    assert not service.integrity()["ok"]


def test_production_simulation_routes_are_unavailable():
    from fastapi import FastAPI

    from app.zero_trust_api import zero_trust_router

    isolated = FastAPI()
    isolated.include_router(zero_trust_router(None))
    isolated.dependency_overrides[get_principal] = lambda: PRINCIPAL
    with TestClient(isolated) as client:
        assert client.get("/zero-trust/policies").status_code == 404
        assert client.get("/zero-trust/sessions").status_code == 404


def test_api_closed_loop_and_viewer_cannot_evaluate():
    from uuid import uuid4

    key = "api-" + uuid4().hex
    current = datetime.now(UTC)
    with TestClient(app) as client:
        response = client.post("/zero-trust/sessions/evaluate", json={
            "session_id": key, "expected_version": 0,
            "event": event(key, when=current).model_dump(mode="json"),
        })
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        token = response.json()["grant_token"]
        revoke = client.post(f"/zero-trust/sessions/{key}/revoke", json={
            "expected_version": 1, "note": "manual revocation",
        })
        assert revoke.status_code == 200
        denied = client.post("/zero-trust/protected-access", json={
            "session_id": key, "resource_id": "zt-demo-documents", "action": "READ", "grant_token": token,
        })
        assert denied.status_code == 403 and denied.json()["content"] is None
        try:
            app.dependency_overrides[get_principal] = lambda: Principal(
                "viewer", "local", frozenset({Role.VIEWER}), "api_key",
            )
            assert client.post("/zero-trust/sessions/evaluate", json={
                "session_id": key, "expected_version": 0,
                "event": event().model_dump(mode="json"),
            }).status_code == 403
        finally:
            app.dependency_overrides.pop(get_principal, None)
