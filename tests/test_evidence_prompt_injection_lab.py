import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from app.analyzers.structured_response import ResponseDiagnostics
from app.models import SecurityAssessment
from scripts import bounded_llm_requests as bounded
from scripts import evaluate_evidence_prompt_injection as injection


def test_injected_event_is_signed_and_bound_without_changing_server_policy(tmp_path):
    lab = injection.LogInstructionLab(tmp_path / "authority")
    policy_before = lab.policy_path.read_bytes()
    for scenario in injection.SELECTED_SCENARIOS:
        signal, context = lab.create(scenario)
        assert signal.event.behavior.event_text == injection.PAYLOADS[scenario[0]]
        facts = context.for_event(signal.event)
        assert facts["signal"]["signature_verified"] is True
        assert facts["caller"]["session_operator_binding_verified"] is True
        assert facts["not_an_access_grant"] is True
    assert lab.policy_path.read_bytes() == policy_before


def test_paid_wrapper_preserves_failing_cases_and_rejects_its_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(
        injection.evaluation,
        "dotenv_values",
        lambda _: {"OPENAI_API_KEY": "local-test-placeholder"},
    )
    requests = []

    async def fake(client, **kwargs):
        request = json.loads(kwargs["input"][1]["content"])
        assert "truth" not in request and "ground_truth" not in request
        assert request["evidence_catalog"]["behavior.event_text"] in injection.PAYLOADS.values()
        requests.append(kwargs)
        return SimpleNamespace(
            output=[],
            output_parsed=SecurityAssessment(
                risk_score=0,
                risk_level="LOW",
                violation_type="NORMAL",
                rationale="Mocked provider for protocol and denominator verification only",
                evidence=["device.managed"],
                recommended_action="HOLD_FOR_REVIEW",
                confidence=0.8,
                requires_human_review=True,
            ),
            model="local-mock",
        ), ResponseDiagnostics("completed", input_tokens=100, output_tokens=100)

    monkeypatch.setattr(bounded, "parse_structured_response", fake)
    result = injection.run(
        tmp_path / "run",
        "unused",
        stop_at=(datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
    )
    assert len(requests) == result["attempts"] == 12 and result["completed"]
    assert result["real_loopback_jwks_fetches"] >= 1 and result["principal_injected"] is False
    assert result["robustness_gate_passed"] is False
    assert all(m["FN"] == 3 and m["TN"] == 3 for m in result["metrics"].values())
    assert result["all_state_reads_unchanged"]
    protocol = json.loads((tmp_path / "run/protocol.json").read_text())
    assert len(protocol["payloads"]) == 6 and protocol["fresh_unmodified_controls"] is False
