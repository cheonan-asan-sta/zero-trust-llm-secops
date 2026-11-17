import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.analyzers.structured_response import ResponseDiagnostics, StructuredResponseFailure
from app.models import SecurityAssessment
from scripts import evaluate_llm_development as evaluation


def test_all_development_variants_are_frozen_without_holdout_population():
    cases = evaluation.development_cases(
        Path(__file__).resolve().parents[1] / "app/data/benchmark/cases.jsonl"
    )
    assert len(cases) == 360 and len({c.family_id for c in cases}) == 36
    assert all(c.split == "development" for c in cases)
    assert sum(c.threat for c in cases) == 180


@pytest.mark.parametrize("budget", [0, -1, float("nan"), float("inf"), 2.01])
def test_bad_budget_never_reaches_credentials_or_network(tmp_path, budget):
    with pytest.raises(ValueError, match="evaluation_options"):
        asyncio.run(evaluation.run(tmp_path / "absent", max_budget=budget))
    assert not (tmp_path / "absent").exists()


def test_settled_usage_releases_unused_reservations_without_extra_requests(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "local-test-placeholder")
    attempts = []

    async def fake(client, **kwargs):
        attempts.append(kwargs)
        assert kwargs["store"] is False and kwargs["max_output_tokens"] == 2400
        catalog = json.loads(kwargs["input"][1]["content"])["evidence_catalog"]
        assert "ground_truth" not in json.dumps(kwargs["input"])
        assessment = SecurityAssessment(
            risk_score=0,
            risk_level="LOW",
            violation_type="NORMAL",
            rationale="로컬 예산 동작 시험",
            evidence=[next(iter(catalog))],
            recommended_action="HOLD_FOR_REVIEW",
            confidence=0.5,
            requires_human_review=True,
        )
        return SimpleNamespace(output_parsed=assessment, model="local-test"), ResponseDiagnostics(
            status="completed",
            input_tokens=100,
            output_tokens=100,
        )

    monkeypatch.setattr(evaluation, "parse_structured_response", fake)
    result = asyncio.run(evaluation.run(tmp_path / "run", max_budget=0.25))
    assert result["completed"] and result["attempts"] == len(attempts) == 360
    assert result["metrics"]["TP"] + result["metrics"]["FN"] == 180
    assert result["known_usage_estimated_usd"] < 0.25
    assert result["unknown_usage_attempts"] == 0
    checkpoint = json.loads((tmp_path / "run/cost-checkpoint.json").read_bytes())
    assert checkpoint["pending_request"] is None
    assert checkpoint["charged_or_reserved_usd"] == result["known_usage_estimated_usd"]


def test_unknown_usage_keeps_full_reservation_and_all_unattempted_cases(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "local-test-placeholder")

    async def fake(*args, **kwargs):
        raise StructuredResponseFailure(
            "structured_output_invalid", ResponseDiagnostics("completed")
        )

    monkeypatch.setattr(evaluation, "parse_structured_response", fake)
    result = asyncio.run(evaluation.run(tmp_path / "run", max_budget=0.05))
    assert not result["completed"] and result["fatal"] == "budget_limit"
    assert 0 < result["attempts"] < 360
    assert result["attempts"] + result["unattempted"] == 360
    assert result["unknown_usage_attempts"] == result["attempts"]
    assert 0 < result["unknown_usage_reserved_usd"] <= 0.05
    assert result["metrics"]["unknown_or_error"] == 360
    assert result["metrics"]["FP"] == result["metrics"]["FN"] == 180
