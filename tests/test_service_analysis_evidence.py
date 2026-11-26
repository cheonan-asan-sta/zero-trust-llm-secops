"""Trust boundary regressions, not a new binary performance benchmark."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

import pytest
from test_exec_history_binding import fixture

from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.config import Settings
from app.grounded_prompting import evidence_catalog, grounded_input
from app.models import SecurityAssessment
from app.security import Principal, Role
from app.services.trusted_signals import SignalRejected
from app.zero_trust_models import SessionRevocationRequest
from scripts.f1_lab.service_analysis_evidence import (
    collect_service_analysis_evidence,
    review_service_execution,
)


@pytest.fixture
def executed(tmp_path):
    lab, launcher, launches = fixture(tmp_path)
    request, access = lab.new_request(), lab.new_access()
    receipt, event, proofs = lab.gate(request, access).dispatch(launcher, lab.permission)
    args = {
        "operations": lab.operations,
        "signal": lab.signals[access.session_id],
        "principal": lab.principal,
        "joiner": lab.broker.joiner,
        "caller_registry": lab.broker.registry,
        "request": request,
        "event": event,
        "proofs": proofs,
        "receipt": receipt,
    }
    return lab, args, launches


def assessment():
    return SecurityAssessment(
        risk_score=10,
        risk_level="LOW",
        violation_type="NORMAL",
        confidence=0.8,
        rationale="서명된 실행 관측이 요청에 연결됐으며 후속 행위는 확인하지 못했습니다.",
        recommended_action="ALLOW",
        requires_human_review=False,
        evidence=["verified_session.native_execution.process.executable_sha256"],
    )


def journal_state(lab):
    with lab.broker.joiner.connect(read_only=True) as con:
        records = con.execute("SELECT * FROM observations").fetchall()
        clock = con.execute("SELECT * FROM clock").fetchall()
    with lab.broker.connect() as con:
        requests = con.execute("SELECT * FROM requests").fetchall()
        broker_clock = con.execute("SELECT * FROM clock").fetchall()
    return records, clock, requests, broker_clock, lab.operations.journal_status()


def test_native_facts_are_read_only_exact_and_do_not_claim_network_or_human_attestation(executed):
    lab, args, launches = executed
    before = journal_state(lab)
    database_before = hashlib.sha256(lab.broker.joiner.path.read_bytes()).hexdigest()
    context = collect_service_analysis_evidence(**args)
    facts = context.for_event(args["signal"].event)
    native = facts["native_execution"]
    assert native["invocation_id"] == args["event"].invocation_id
    assert native["process"]["start_ticks"] == args["proofs"][0].observation.start_ticks
    assert native["app_access"]["session_version"] == 1
    assert native["app_grant_already_consumed"] is True
    assert facts["session"]["approval_currently_usable"] is False
    assert native["observed_destinations"] is None and "execution" not in facts
    assert not native["event_subject_identity_or_mfa_verified_by_this_receipt"]
    assert not facts["external_enterprise_identity_verified"]
    assert native["caller_environment"] == "local_oidc"
    for _ in range(3):
        context.verify_current()
    assert journal_state(lab) == before
    assert hashlib.sha256(lab.broker.joiner.path.read_bytes()).hexdigest() == database_before
    assert launches == [args["request"].request_id]
    assert context.expires_at <= args["event"].observed_at + timedelta(seconds=30)


def test_catalog_omits_secrets_and_benchmark_labels(executed):
    _, args, _ = executed
    context = collect_service_analysis_evidence(**args)
    message = json.dumps(grounded_input(args["signal"].event, context), ensure_ascii=False)
    for forbidden in (
        args["request"].nonce,
        args["receipt"].signature,
        args["signal"].signature,
        args["proofs"][0].signature,
        "grant_token",
        "grant_hash",
        "ground_truth",
        "PRIVATE KEY",
        "fixture-person",
    ):
        assert forbidden not in message
    catalog = evidence_catalog(args["signal"].event, context)
    assert "verified_session.native_execution.observed_destinations" not in catalog
    assert "verified_session.native_execution.process.command_sha256" in catalog


@pytest.mark.parametrize(
    "change",
    [
        "event_boot",
        "event_invocation",
        "event_tenant",
        "event_raw",
        "event_basis",
        "request_command",
        "request_nonce",
        "receipt_caller",
        "receipt_evidence",
        "receipt_signature",
        "proof_signature",
        "proof_command",
        "missing_proof",
        "other_session",
        "other_caller",
        "other_tenant",
        "viewer",
        "unverified",
        "expired_caller",
        "unrecorded",
        "deleted_ledger",
        "clock_regression",
        "policy_changed",
        "service_registry_changed",
        "caller_registry_changed",
        "source_revoked",
        "session_revoked",
        "expired",
    ],
)
def test_missing_changed_or_withdrawn_evidence_is_not_sent_to_a_model(executed, change):
    lab, args, _ = executed
    if change.startswith("event_"):
        field, value = {
            "event_boot": ("boot_id", "3" * 32),
            "event_invocation": ("invocation_id", "3" * 32),
            "event_tenant": ("tenant_id", "other"),
            "event_raw": ("raw_sha256", "e" * 64),
            "event_basis": ("collection_basis", "manager_snapshot"),
        }[change]
        args["event"] = args["event"].model_copy(update={field: value})
    if change.startswith("request_"):
        field = "command_sha256" if change == "request_command" else "nonce"
        args["request"] = args["request"].model_copy(
            update={field: "e" * (64 if field != "nonce" else 43)}
        )
    if change.startswith("receipt_"):
        field = {
            "receipt_caller": "caller_ref_sha256",
            "receipt_evidence": "service_evidence_sha256",
            "receipt_signature": "signature",
        }[change]
        args["receipt"] = args["receipt"].model_copy(
            update={field: "e" * (86 if field == "signature" else 64)}
        )
    if change == "proof_signature":
        args["proofs"][0] = args["proofs"][0].model_copy(update={"signature": "e" * 86})
    if change == "proof_command":
        args["proofs"][0] = args["proofs"][0].model_copy(
            update={
                "observation": args["proofs"][0].observation.model_copy(
                    update={"command_sha256": "e" * 64}
                )
            }
        )
    if change == "missing_proof":
        args["proofs"] = args["proofs"][:1]
    if change == "other_session":
        args["signal"] = lab.signals[lab.new_access().session_id]
    if change in {"other_caller", "other_tenant", "viewer", "unverified", "expired_caller"}:
        p = args["principal"]
        args["principal"] = Principal(
            "other" if change == "other_caller" else p.subject,
            "other" if change == "other_tenant" else p.tenant_id,
            frozenset({Role.VIEWER}) if change == "viewer" else p.roles,
            "unverified" if change == "unverified" else p.auth_method,
            datetime.now(UTC) - timedelta(seconds=1) if change == "expired_caller" else None,
        )
    if change == "unrecorded":
        with lab.broker.joiner.connect() as con:
            con.execute("DELETE FROM observations")
    if change == "deleted_ledger":
        lab.broker.joiner.path.unlink()
    if change == "clock_regression":
        with lab.broker.joiner.connect() as con:
            con.execute(
                "UPDATE clock SET observed=?",
                ((datetime.now(UTC) + timedelta(seconds=10)).isoformat(),),
            )
    if change == "policy_changed":
        lab.operations.policy_digest = "e" * 64
    if change in {"service_registry_changed", "caller_registry_changed"}:
        registry = (
            lab.broker.joiner.registry
            if change == "service_registry_changed"
            else lab.broker.registry
        )
        registry.path.write_bytes(registry.path.read_bytes() + b" ")
    if change == "source_revoked":
        lab.sources["sources"][0]["enabled"] = False
        lab.save_sources()
    if change == "session_revoked":
        lab.operations.revoke(
            args["signal"].session_id,
            SessionRevocationRequest(expected_version=1, note="native analysis revocation test"),
            args["principal"],
        )
    if change == "expired":
        args["now"] = datetime.now(UTC) + timedelta(seconds=31)
    with pytest.raises((ValueError, LookupError)):
        collect_service_analysis_evidence(**args)
    if change == "deleted_ledger":
        assert not lab.broker.joiner.path.exists()  # No silent SQLite recreation.


@pytest.mark.parametrize("stage", ["before", "during"])
def test_live_revocation_blocks_provider_or_delivery(executed, stage):
    lab, args, _ = executed
    context = collect_service_analysis_evidence(**args)

    def revoke():
        lab.operations.revoke(
            args["signal"].session_id,
            SessionRevocationRequest(expected_version=1, note="inference revocation race"),
            args["principal"],
        )

    async def infer(*_):
        if stage == "during":
            revoke()
        return assessment()

    provider = Mock(analyze_with_evidence=AsyncMock(side_effect=infer))
    if stage == "before":
        revoke()
    with pytest.raises(SignalRejected):
        asyncio.run(review_service_execution(provider, args["signal"], context))
    assert provider.analyze_with_evidence.await_count == (stage == "during")


def test_server_account_withdrawal_is_rechecked_after_provider(executed):
    _, args, _ = executed
    enabled = True

    def authority():
        if not enabled:
            raise SignalRejected("account withdrawn")

    context = collect_service_analysis_evidence(**args, caller_authority_check=authority)

    async def infer(*_):
        nonlocal enabled
        enabled = False
        return assessment()

    with pytest.raises(SignalRejected):
        asyncio.run(
            review_service_execution(
                Mock(analyze_with_evidence=AsyncMock(side_effect=infer)), args["signal"], context
            )
        )


def test_existing_openai_adapter_sends_native_instructions_without_network(executed):
    lab, args, launches = executed
    context = collect_service_analysis_evidence(**args)
    before = journal_state(lab)
    with patch(
        "app.analyzers.openai_analyzer.parse_structured_response", new_callable=AsyncMock
    ) as parse:
        parse.return_value = (Mock(output_parsed=assessment()), None)
        adapter = OpenAIAnalyzer(
            Settings(openai_api_key="local-stub-not-a-key", openai_prompt_mode="grounded")
        )

        async def run():
            try:
                return await review_service_execution(adapter, args["signal"], context)
            finally:
                await adapter._client.close()

        result = asyncio.run(run())
        kwargs = parse.call_args.kwargs
        assert "first\nsuccessful exec" in kwargs["input"][0]["content"]
        assert kwargs["store"] is False
        assert parse.await_count == 1
    assert result.violation_type == "NORMAL"  # Guard must not manufacture a detection.
    assert result.recommended_action == "HOLD_FOR_REVIEW" and result.requires_human_review
    assert journal_state(lab) == before and len(launches) == 1


@pytest.mark.parametrize("kind", ["unrecorded", "stale", "withdrawn"])
def test_read_only_inspection_never_admits_or_refreshes_evidence(executed, kind):
    lab, args, _ = executed
    joiner = lab.broker.joiner
    now = datetime.now(UTC)
    if kind == "unrecorded":
        with joiner.connect() as con:
            con.execute("DELETE FROM observations")
    if kind == "stale":
        now += timedelta(seconds=31)
    if kind == "withdrawn":
        joiner.registry.path.write_bytes(b"{}")
    before = journal_state(lab)
    assert joiner.inspect(args["event"], args["proofs"], now=now).state == "unavailable"
    assert journal_state(lab) == before


@pytest.mark.parametrize("value", [None, True, 1, "x" * 64, "a" * 63, "A" * 64])
def test_legacy_or_malformed_access_cannot_be_treated_as_execution_consumption(executed, value):
    lab, args, _ = executed
    with pytest.raises(ValueError):
        lab.operations.analysis_execution_access(
            args["signal"].session_id, args["principal"], value, expected_version=1
        )


def test_native_authorization_does_not_clear_an_independent_threat(executed):
    _, args, _ = executed
    context = collect_service_analysis_evidence(**args)
    threat = assessment().model_copy(
        update={
            "violation_type": "DATA_EXFILTRATION",
            "risk_score": 90,
            "risk_level": "CRITICAL",
            "recommended_action": "ISOLATE_SESSION",
        }
    )
    provider = Mock(analyze_with_evidence=AsyncMock(return_value=threat))
    result = asyncio.run(review_service_execution(provider, args["signal"], context))
    assert result.violation_type == threat.violation_type
    assert result.risk_score == 90 and result.recommended_action == "ISOLATE_SESSION"
    assert result.requires_human_review


def test_native_controls_use_same_internal_route_as_real_systemd_runner(executed):
    from scripts.f1_lab.service_analysis_controls import run

    lab, args, _ = executed
    # The runner's fixture retains the access only in the caller, never in model facts.
    access = Mock(session_id=args["signal"].session_id)
    passed = []
    run(lab, args["request"], access, args["receipt"], args["event"], args["proofs"], passed.append)
    assert len(passed) == 4
