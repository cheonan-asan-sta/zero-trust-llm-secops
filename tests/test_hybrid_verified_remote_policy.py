import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient

import scripts.local_session_analysis_lab as session_lab
from app import main
from app.analyzers.hybrid import HybridAnalyzer
from app.config import Settings
from app.models import SecurityAssessment, ViolationType
from app.security import get_principal
from app.services.session_analysis_evidence import collect_session_evidence
from app.services.sqlite_audit import SQLiteAuditStore
from app.zero_trust_models import ProtectedAccessRequest, SessionRevocationRequest
from scripts.local_session_analysis_lab import SCENARIOS, LocalSessionAnalysisLab


def assessment(violation=ViolationType.NORMAL):
    return SecurityAssessment(
        risk_score=10,
        risk_level="LOW",
        violation_type=violation,
        rationale="Local replay",
        evidence=["action"],
        recommended_action="ALLOW",
        confidence=0.8,
        requires_human_review=True,
    )


@pytest.fixture
def lab(tmp_path):
    return LocalSessionAnalysisLab(tmp_path / "authority")


def analyze(signed, context, response):
    llm = AsyncMock()
    if response is None:
        llm.analyze_with_evidence.side_effect = RuntimeError("provider unavailable")
    else:
        llm.analyze_with_evidence.return_value = response
    result = asyncio.run(
        HybridAnalyzer(Settings(), llm).analyze_with_evidence(signed.event, context)
    )
    llm.analyze_with_evidence.assert_awaited_once_with(signed.event, context)
    return result


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[row[0] for row in SCENARIOS])
def test_verified_remote_policy_with_a_normal_model_output(lab, scenario):
    signed, context = lab.create(scenario)
    before = lab.service.history(signed.session_id, lab.principal)
    result = analyze(signed, context, assessment())
    assert result.violation_type == (
        ViolationType.ACCESS_POLICY_VIOLATION if scenario[1] else ViolationType.NORMAL
    )
    if signed.event.action == "REMOTE_ACCESS":
        assert result.recommended_action == "HOLD_FOR_REVIEW"
        assert result.requires_human_review
        assert any(path.startswith("verified_session.") for path in result.evidence)
    assert lab.service.history(signed.session_id, lab.principal) == before


def test_generic_step_up_never_suppresses_model_threat(lab):
    signed, context = lab.create(next(row for row in SCENARIOS if row[0] == "permitted_team"))
    result = analyze(signed, context, assessment(ViolationType.CREDENTIAL_ANOMALY))
    assert result.violation_type == ViolationType.CREDENTIAL_ANOMALY
    assert result.recommended_action == "HOLD_FOR_REVIEW"


def test_generic_step_up_never_suppresses_observed_fanout(lab):
    signed, _ = lab.create(next(row for row in SCENARIOS if row[0] == "permitted_team"))
    event = signed.event.model_copy(
        update={
            "event_id": "fanout-control",
            "behavior": signed.event.behavior.model_copy(update={"distinct_resources_10m": 8}),
        }
    )
    signal = lab.sign(event, "fanout-control")
    lab.service.evaluate_signed(signal, lab.principal)
    context = collect_session_evidence(lab.service, signal, lab.principal)
    result = analyze(signal, context, assessment())
    assert result.violation_type == ViolationType.LATERAL_MOVEMENT
    assert "behavior.distinct_resources_10m" in result.evidence


def test_verified_denial_survives_model_unavailability(lab):
    signed, context = lab.create(next(row for row in SCENARIOS if row[0] == "required_mfa_unknown"))
    result = analyze(signed, context, None)
    assert result.violation_type == ViolationType.ACCESS_POLICY_VIOLATION
    assert "verified_session.policy.mfa_required" in result.evidence
    assert result.recommended_action == "HOLD_FOR_REVIEW"


def test_outstanding_signed_challenge_does_not_clear_generic_rule(lab):
    signed, _ = lab.create(next(row for row in SCENARIOS if row[0] == "permitted_team"))
    event = signed.event.model_copy(
        update={
            "event_id": "outstanding-challenge",
            "timestamp": max(datetime.now(UTC), signed.event.timestamp + timedelta(microseconds=1)),
        }
    )
    signed = lab.sign(event, signed.session_id, expected_version=1)
    issued = lab.service.evaluate_signed(signed, lab.principal)
    assert "SIGNED_MFA_CHALLENGE_REQUIRED" in issued.session.reason_codes
    context = collect_session_evidence(lab.service, signed, lab.principal)
    result = analyze(signed, context, assessment())
    assert result.violation_type == ViolationType.ACCESS_POLICY_VIOLATION
    assert "verified_session.session.challenge_pending" in result.evidence


def test_generic_step_up_without_model_output_is_reviewed_as_unknown(lab):
    signed, context = lab.create(next(row for row in SCENARIOS if row[0] == "permitted_team"))
    result = analyze(signed, context, None)
    assert result.violation_type == ViolationType.UNKNOWN
    assert result.recommended_action == "HOLD_FOR_REVIEW"
    assert result.requires_human_review


def test_verified_policy_and_model_rationale_fit_the_response_contract(lab):
    signed, context = lab.create(next(row for row in SCENARIOS if row[0] == "permitted_team"))
    response = assessment().model_copy(update={"rationale": "x" * 1000})
    result = analyze(signed, context, response)
    assert (
        SecurityAssessment.model_validate(result.model_dump()).violation_type
        == ViolationType.NORMAL
    )


READ_CONTROLS = (
    ("permitted_vpn_read", True, {}, None),
    ("permitted_office_read", True, {"network": {"access_method": "office"}}, None),
    (
        "inactive_account",
        False,
        {"user": {"active": False}},
        "user.active",
    ),
    (
        "failed_authentication",
        False,
        {"auth_context": {"authentication_result": "failure"}},
        "verified_session.signal.authentication_observation",
    ),
    (
        "required_mfa_unknown",
        False,
        {"auth_context": {"mfa": "unknown"}},
        "verified_session.policy.mfa_required",
    ),
    (
        "compromised_device",
        False,
        {"device": {"security_posture": "compromised"}},
        "device.security_posture",
    ),
    (
        "revoked_request",
        False,
        {},
        "verified_session.session.status",
    ),
    (
        "role_denied_by_server",
        False,
        {"user": {"role": "administrator"}, "resource": {"required_role": "administrator"}},
        "verified_session.policy.role_permitted",
    ),
)


def signed_read_control(lab, name, allowed, updates):
    signed, context = lab.create(
        (name, not allowed, "remote-read", "employee", "success", True, "READ")
    )
    if not updates:
        return signed, context
    event = signed.event.model_copy(
        update={
            "event_id": "read-" + name,
            **{
                field: getattr(signed.event, field).model_copy(update=values)
                for field, values in updates.items()
            },
        }
    )
    signed = lab.sign(event, "read-" + name)
    lab.service.evaluate_signed(signed, lab.principal)
    return signed, collect_session_evidence(lab.service, signed, lab.principal)


@pytest.mark.parametrize(
    "name,allowed,updates,required_evidence", READ_CONTROLS, ids=[row[0] for row in READ_CONTROLS]
)
def test_verified_read_reports_confirmed_policy_failure(
    lab, name, allowed, updates, required_evidence
):
    signed, context = signed_read_control(lab, name, allowed, updates)
    before = lab.service.history(signed.session_id, lab.principal)
    result = analyze(signed, context, assessment())
    if allowed:
        assert result.violation_type == ViolationType.NORMAL
    else:
        assert result.violation_type == ViolationType.ACCESS_POLICY_VIOLATION
        assert required_evidence in result.evidence
        assert result.recommended_action == "HOLD_FOR_REVIEW"
        assert result.requires_human_review
        fallback = analyze(signed, context, None)
        assert fallback.violation_type == result.violation_type
    assert lab.service.history(signed.session_id, lab.principal) == before


def contradictory_policy_response():
    return assessment(ViolationType.ACCESS_POLICY_VIOLATION).model_copy(
        update={
            "evidence": ["verified_session.policy.action_permitted"],
        }
    )


def test_verified_allow_corrects_contradicted_policy_only_claim(lab):
    signed, context = signed_read_control(lab, "permitted_read", True, {})
    before = lab.service.history(signed.session_id, lab.principal)
    result = analyze(signed, context, contradictory_policy_response())
    assert result.violation_type == ViolationType.NORMAL
    assert result.recommended_action == "HOLD_FOR_REVIEW" and result.requires_human_review
    assert "verified_session.session.approval_currently_usable" in result.evidence
    assert lab.service.history(signed.session_id, lab.principal) == before


def test_verified_allow_preserves_a_model_finding_with_separate_evidence(lab):
    signed, context = signed_read_control(lab, "permitted_read", True, {})
    response = contradictory_policy_response()
    response = response.model_copy(
        update={"evidence": [*response.evidence, "network.access_method"]}
    )
    assert (
        analyze(signed, context, response).violation_type == ViolationType.ACCESS_POLICY_VIOLATION
    )


def test_consumed_approval_does_not_clear_model_policy_finding(lab):
    signed, _ = signed_read_control(lab, "permitted_read", True, {})
    event = signed.event.model_copy(update={"event_id": "approval-consumption-check"})
    signed = lab.sign(event, "approval-consumption-check")
    issued = lab.service.evaluate_signed(signed, lab.principal)
    assert issued.grant_token
    access = ProtectedAccessRequest(
        session_id=signed.session_id,
        resource_id=event.resource.resource_id,
        action=event.action,
        grant_token=issued.grant_token,
    )
    assert lab.service.access(access, lab.principal).allowed
    current = collect_session_evidence(lab.service, signed, lab.principal)
    assert current.for_event(event)["session"]["approval_currently_usable"] is False
    assert analyze(signed, current, contradictory_policy_response()).violation_type == (
        ViolationType.ACCESS_POLICY_VIOLATION
    )


def admin_lab(directory, monkeypatch):
    policy = session_lab.remote_policy_bundle()
    admin = next(
        resource for resource in policy["resources"] if resource["resource_id"] == "remote-admin"
    )
    admin["actions"].append("ADMIN")
    monkeypatch.setattr(session_lab, "remote_policy_bundle", lambda: policy)
    return LocalSessionAnalysisLab(directory)


ADMIN_CONTROLS = (
    (
        "approved_admin",
        "administrator",
        "success",
        True,
        ViolationType.NORMAL,
        ViolationType.NORMAL,
    ),
    (
        "approved_with_policy_error",
        "administrator",
        "success",
        True,
        ViolationType.ACCESS_POLICY_VIOLATION,
        ViolationType.NORMAL,
    ),
    (
        "denied_employee",
        "employee",
        "success",
        True,
        ViolationType.NORMAL,
        ViolationType.PRIVILEGE_ESCALATION,
    ),
    (
        "approved_with_model_threat",
        "administrator",
        "success",
        True,
        ViolationType.CREDENTIAL_ANOMALY,
        ViolationType.CREDENTIAL_ANOMALY,
    ),
    (
        "required_mfa_unconfirmed",
        "administrator",
        "unknown",
        True,
        ViolationType.NORMAL,
        ViolationType.PRIVILEGE_ESCALATION,
    ),
)


@pytest.mark.parametrize(
    "name,role,mfa,managed,model_finding,expected",
    ADMIN_CONTROLS,
    ids=[row[0] for row in ADMIN_CONTROLS],
)
def test_verified_admin_preserves_only_grounded_findings(
    tmp_path, monkeypatch, name, role, mfa, managed, model_finding, expected
):
    lab = admin_lab(tmp_path / "admin-authority", monkeypatch)
    signed, context = lab.create(
        (name, expected != ViolationType.NORMAL, "remote-admin", role, mfa, managed, "ADMIN")
    )
    before = lab.service.history(signed.session_id, lab.principal)
    decision = {"denied_employee": "DENY", "required_mfa_unconfirmed": "STEP_UP"}.get(name, "ALLOW")
    assert before[-1].decision == decision
    response = (
        contradictory_policy_response()
        if model_finding == ViolationType.ACCESS_POLICY_VIOLATION
        else assessment(model_finding)
    )
    result = analyze(signed, context, response)
    assert result.violation_type == expected
    assert result.recommended_action == "HOLD_FOR_REVIEW"
    assert lab.service.history(signed.session_id, lab.principal) == before


def test_verified_admin_cannot_clear_a_server_action_denial(tmp_path, monkeypatch):
    lab = admin_lab(tmp_path / "admin-authority", monkeypatch)
    signed, context = lab.create(
        ("denied_admin_action", True, "remote-team", "administrator", "success", True, "ADMIN")
    )
    current = context.for_event(signed.event)["session"]
    assert current["decision"] == "DENY" and "RESOURCE_SCOPE_DENIED" in current["reason_codes"]
    result = analyze(signed, context, assessment())
    assert result.violation_type == ViolationType.PRIVILEGE_ESCALATION
    assert "verified_session.policy.action_permitted" in result.evidence


@pytest.mark.parametrize(
    "role, observed_required_role, matches_in_verified_response",
    [
        ("administrator", None, False),
        ("administrator", "employee", True),
        ("employee", None, True),
    ],
)
def test_verified_http_admin_sigma_uses_only_current_confirmed_scope(
    tmp_path, monkeypatch, role, observed_required_role, matches_in_verified_response
):
    lab = admin_lab(tmp_path / "admin-authority", monkeypatch)
    original, _ = lab.create(("admin-read", False, "remote-admin", role, "success", True, "ADMIN"))
    event = original.event.model_copy(
        update={
            "event_id": "http-admin-scope-check",
            "resource": original.event.resource.model_copy(
                update={"required_role": observed_required_role}
            ),
        }
    )
    signed = lab.sign(event, "http-admin-scope-check")
    lab.service.evaluate_signed(signed, lab.principal)
    settings = Settings(analyzer_mode="hybrid", openai_prompt_mode="grounded")
    hybrid = HybridAnalyzer(
        settings, llm=Mock(analyze_with_evidence=AsyncMock(return_value=assessment()))
    )
    audit = SQLiteAuditStore(tmp_path / "verified-admin.sqlite3")
    monkeypatch.setattr(main, "zero_trust_operations", lab.service)
    monkeypatch.setattr(main, "get_analyzer", lambda: hybrid)
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "audit_store", audit)
    monkeypatch.setitem(main.app.dependency_overrides, get_principal, lambda: lab.principal)

    client = TestClient(main.app)
    raw = client.post("/detections/evaluate", json=event.model_dump(mode="json"))
    verified = client.post("/analysis/verified-session", json=signed.model_dump(mode="json"))
    assert raw.status_code == verified.status_code == 200
    assert any("attack.t1098" in row["tags"] for row in raw.json()["detection"]["matches"])
    detection = verified.json()["detection"]
    assert (
        any("attack.t1098" in row["tags"] for row in detection["matches"])
        is matches_in_verified_response
    )
    saved = audit.get(event.event_id, tenant_id=lab.principal.tenant_id)
    assert saved.detection.model_dump(mode="json") == detection
    if not matches_in_verified_response:
        assert detection["highest_level"] != "high"


@pytest.mark.parametrize(
    "kind", ["confirmed_denial", "contradicted_claim", "revoked_during_review"]
)
def test_verified_http_returns_and_audits_current_policy_classification(
    lab, monkeypatch, tmp_path, kind
):
    denied = kind == "confirmed_denial"
    updates = {"auth_context": {"mfa": "unknown"}} if denied else {}
    signed, _ = signed_read_control(lab, kind, not denied, updates)
    before = lab.service.history(signed.session_id, lab.principal)
    response = assessment() if denied else contradictory_policy_response()

    async def model(_event, _context):
        if kind == "revoked_during_review":
            lab.service.revoke(
                signed.session_id,
                SessionRevocationRequest(
                    expected_version=before[-1].version, note="Local review test withdrawal"
                ),
                lab.principal,
            )
        return response

    settings = Settings(analyzer_mode="hybrid", openai_prompt_mode="grounded")
    llm = Mock(analyze_with_evidence=AsyncMock(side_effect=model))
    hybrid = HybridAnalyzer(settings, llm=llm)
    audit = SQLiteAuditStore(tmp_path / "verified-analysis.sqlite3")
    monkeypatch.setattr(main, "zero_trust_operations", lab.service)
    monkeypatch.setattr(main, "get_analyzer", lambda: hybrid)
    monkeypatch.setattr(main, "get_settings", lambda: settings)
    monkeypatch.setattr(main, "audit_store", audit)
    monkeypatch.setitem(main.app.dependency_overrides, get_principal, lambda: lab.principal)

    result = TestClient(main.app).post(
        "/analysis/verified-session", json=signed.model_dump(mode="json")
    )
    llm.analyze_with_evidence.assert_awaited_once()
    if kind == "revoked_during_review":
        assert result.status_code == 502
        assert audit.integrity()["verified_lines"] == 0
        assert lab.service.history(signed.session_id, lab.principal)[-1].status == "REVOKED"
    else:
        assert result.status_code == 200, result.text
        payload = result.json()
        expected = ViolationType.ACCESS_POLICY_VIOLATION if denied else ViolationType.NORMAL
        assert payload["assessment"]["violation_type"] == expected
        assert payload["assessment"]["requires_human_review"]
        saved = audit.get(signed.event.event_id, tenant_id=lab.principal.tenant_id)
        assert audit.integrity()["verified_lines"] == 1
        assert saved.assessment.violation_type == expected
        assert saved.verification_context == payload["verification_context"]
        assert lab.service.history(signed.session_id, lab.principal) == before


def signed_mfa_read_control(lab, *, bind_challenge):
    signed, _ = lab.create(
        ("reading-challenge", True, "remote-read", "employee", "unknown", True, "READ")
    )
    first = lab.service.history(signed.session_id, lab.principal)[-1]
    assert first.challenge_id
    event = signed.event.model_copy(
        update={
            "event_id": "follow-up-" + signed.event.event_id,
            "timestamp": max(datetime.now(UTC), first.observed_at + timedelta(microseconds=1)),
            "auth_context": signed.event.auth_context.model_copy(update={"mfa": "success"}),
        }
    )
    next_signal = lab.sign(
        event,
        signed.session_id,
        expected_version=first.version,
        challenge_id=first.challenge_id if bind_challenge else None,
    )
    result = lab.service.evaluate_signed(next_signal, lab.principal)
    context = collect_session_evidence(lab.service, next_signal, lab.principal)
    return next_signal, context, result.session


@pytest.mark.parametrize("bind_challenge", [False, True])
def test_success_observation_cannot_replace_server_required_challenge(lab, bind_challenge):
    signed, context, session = signed_mfa_read_control(lab, bind_challenge=bind_challenge)
    assert context.for_event(signed.event)["signal"]["mfa_observation"] == "success"
    assert session.decision == ("ALLOW" if bind_challenge else "STEP_UP")
    result = analyze(signed, context, assessment())
    if bind_challenge:
        assert result.violation_type == ViolationType.NORMAL
    else:
        assert result.violation_type == ViolationType.ACCESS_POLICY_VIOLATION
        assert "verified_session.session.challenge_pending" in result.evidence
        assert result.recommended_action == "HOLD_FOR_REVIEW"
        assert session.challenge_id not in result.model_dump_json()


@pytest.mark.parametrize(
    "variant,expected,verified",
    [
        ("same_scope", ViolationType.NORMAL, True),
        ("absent_challenge", ViolationType.ACCESS_POLICY_VIOLATION, False),
        ("different_resource", ViolationType.LATERAL_MOVEMENT, False),
        ("changed_network", ViolationType.LATERAL_MOVEMENT, False),
        ("fanout", ViolationType.LATERAL_MOVEMENT, True),
        ("model_threat", ViolationType.CREDENTIAL_ANOMALY, True),
        ("model_unavailable", ViolationType.UNKNOWN, True),
    ],
)
def test_verified_remote_followup_limits_generic_alarm_only(lab, variant, expected, verified):
    initial, _ = lab.create(
        ("remote-mfa-followup", False, "remote-team", "employee", "unknown", True, "REMOTE_ACCESS")
    )
    previous = lab.service.history(initial.session_id, lab.principal)[-1]
    assert previous.decision == "STEP_UP" and previous.challenge_id
    event = initial.event.model_copy(
        update={
            "event_id": "followup-" + initial.event.event_id,
            "timestamp": max(datetime.now(UTC), previous.observed_at + timedelta(microseconds=1)),
            "auth_context": initial.event.auth_context.model_copy(update={"mfa": "success"}),
        }
    )
    if variant == "different_resource":
        event.resource = event.resource.model_copy(update={"resource_id": "remote-no-mfa"})
    if variant == "changed_network":
        event.network = event.network.model_copy(update={"ip": "198.51.100.14"})
    if variant == "fanout":
        event.behavior = event.behavior.model_copy(update={"distinct_resources_10m": 8})
    signed = lab.sign(
        event,
        initial.session_id,
        expected_version=previous.version,
        challenge_id=None if variant == "absent_challenge" else previous.challenge_id,
    )
    evaluation = lab.service.evaluate_signed(signed, lab.principal)
    assert evaluation.session.decision == "STEP_UP" and evaluation.grant_token is None
    context = collect_session_evidence(lab.service, signed, lab.principal)
    facts = context.for_event(event)["session"]
    assert facts["same_scope_mfa_response_verified"] is verified
    assert facts["challenge_pending"] and not facts["approval_currently_usable"]
    history = lab.service.history(signed.session_id, lab.principal)
    response = assessment()
    if variant == "model_threat":
        response = assessment(ViolationType.CREDENTIAL_ANOMALY)
    if variant == "model_unavailable":
        response = None
    result = analyze(signed, context, response)
    assert result.violation_type == expected
    if variant in {"same_scope", "model_threat", "model_unavailable"}:
        assert "verified_session.session.same_scope_mfa_response_verified" in result.evidence
        assert result.recommended_action == "HOLD_FOR_REVIEW"
        assert result.requires_human_review
    assert previous.challenge_id not in context.facts_json.decode()
    assert lab.service.history(signed.session_id, lab.principal) == history
