"""Fabricated frozen responses exercise real hybrid routing without a provider."""

import asyncio
import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.models import SecurityAssessment, SecurityEvent
from scripts import replay_hybrid_development as replay


def cohort():
    def event(identity, *, download=False):
        return SecurityEvent.model_validate(
            {
                "event_id": identity,
                "timestamp": datetime.now(UTC),
                "user": {"user_id": "unit-user", "role": "employee"},
                "device": {
                    "device_id": "unit-device",
                    "managed": True,
                    "security_posture": "healthy",
                },
                "network": {"ip": "192.0.2.1", "location": "unit-test", "access_method": "office"},
                "resource": {
                    "resource_id": "unit-resource",
                    "resource_type": "document",
                    "sensitivity": "public",
                },
                "action": "DOWNLOAD" if download else "READ",
                "auth_context": {"authentication_result": "success", "mfa": "success"},
                "behavior": {"download_volume_mb": 600 if download else 0},
            }
        )

    normal = SecurityAssessment(
        risk_score=0,
        risk_level="LOW",
        violation_type="NORMAL",
        rationale="Fabricated replay response",
        evidence=["device.managed"],
        recommended_action="HOLD_FOR_REVIEW",
        confidence=0.8,
        requires_human_review=True,
    ).model_dump(mode="json")
    rows = [
        {
            "id": str(i),
            "domain": "unit",
            "family_id": "unit",
            "truth": i == 1,
            "prediction": False if i < 2 else None,
            "assessment": normal if i < 2 else None,
            "error": None if i < 2 else "StructuredResponseFailure",
        }
        for i in range(3)
    ]
    cases = {str(i): SimpleNamespace(event=event(str(i), download=i == 1)) for i in range(3)}
    return rows, cases


def test_actual_merge_preserves_rule_detection_and_failure_fallback_without_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("live provider must never be constructed")

    monkeypatch.setattr("app.analyzers.hybrid.OpenAIAnalyzer", forbidden)
    rows, cases = cohort()
    result = asyncio.run(replay.replay_arm(rows, cases, mode="hybrid_review_all"))
    assert len(result) == 3 and all(row["reused_LLM_output"] for row in result)
    assert result[1]["prediction"] is True  # Frozen NORMAL cannot remove a rule finding.
    assert result[2]["source_failure_rule_fallback"]
    assert result[2]["source_LLM_error"] == "StructuredResponseFailure"
    assert result[2]["prediction"] is False and result[2]["requires_human_review"]
    assert rows[2]["prediction"] is None  # Keep the original provider failure intact.


def test_confident_rule_routing_skips_frozen_outputs_instead_of_claiming_model_use(monkeypatch):
    rows, cases = cohort()
    monkeypatch.setenv("HYBRID_CONFIDENCE_THRESHOLD", "1.0")
    result = asyncio.run(replay.replay_arm(rows, cases, mode="hybrid_default"))
    assert replay.replay_settings().hybrid_confidence_threshold == 0.85
    assert not result[0]["reused_LLM_output"] and not result[2]["reused_LLM_output"]
    assert result[1]["reused_LLM_output"]
    assert result[2]["source_LLM_error"] == "StructuredResponseFailure"
    assert result[2]["source_failure_rule_fallback"] is False


def test_published_replay_labels_are_checked_against_original_cases(tmp_path):
    plan, report, rows, cases = replay.load_published()
    assert len(rows) == len(cases) == 360 and report["metrics"]["unknown_or_error"] == 6
    published = {"plan": plan, "report": report, "rows": rows}
    rows[0]["truth"] = not rows[0]["truth"]
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(published), encoding="utf-8")
    with pytest.raises(ValueError, match="published_case_labels_changed"):
        replay.load_published(path)
