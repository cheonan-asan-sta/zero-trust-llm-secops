"""Fabricated provider/source outcomes validate provenance and conservative scoring."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.analyzers.structured_response import ResponseDiagnostics
from app.grounded_prompting import GROUNDED_INSTRUCTIONS, grounded_input
from app.models import SecurityAssessment
from scripts import bounded_llm_requests as bounded
from scripts import evaluate_download_arithmetic_llm as evaluation
from scripts.evaluate_llm_development import development_cases, write_json
from scripts.evaluate_llm_grounded import metrics
from tests.test_incomplete_evaluation_provenance import source as replay_fixture


@pytest.fixture(scope="module")
def arithmetic_source(tmp_path_factory):
    directory, rows, _, plan, report = replay_fixture.__wrapped__(
        tmp_path_factory.mktemp("arithmetic-source")
    )
    cases_path = Path(__file__).resolve().parents[1] / "app/data/benchmark/cases.jsonl"
    cases = development_cases(cases_path)
    inputs = []
    for case in cases:
        identity = hashlib.sha256(case.case_id.encode()).hexdigest()
        event = case.event.model_copy(update={"event_id": identity, "ground_truth": None})
        inputs.append(
            {
                "id": identity,
                "messages": [
                    {"role": "system", "content": GROUNDED_INSTRUCTIONS},
                    *grounded_input(event),
                ],
            }
        )
    payload = b"".join((json.dumps(row, ensure_ascii=False) + "\n").encode() for row in inputs)
    (directory / "private/inputs.jsonl").write_bytes(payload)
    plan["inputs_sha256"] = hashlib.sha256(payload).hexdigest()
    write_json(directory / "plan.json", plan)
    report.update(
        metrics=metrics(rows),
        plan_sha256=hashlib.sha256((directory / "plan.json").read_bytes()).hexdigest(),
    )
    write_json(directory / "report.json", report)
    return directory, rows


def test_changed_input_partition_is_complete_and_other_300_predictions_are_explicit_replay(
    arithmetic_source, tmp_path, monkeypatch
):
    source, original = arithmetic_source
    frozen = (source / "private/predictions.jsonl").read_bytes()
    requests = []

    async def fake(client, **kwargs):
        requests.append(kwargs)
        data = json.loads(kwargs["input"][1]["content"])
        assert data["evidence_catalog"]["action"] == "DOWNLOAD"
        assert data["download_volume_arithmetic"]
        assert "ground_truth" not in json.dumps(kwargs["input"])
        result = SecurityAssessment(
            risk_score=0,
            risk_level="LOW",
            violation_type="NORMAL",
            rationale="Fabricated provider only",
            evidence=["behavior.download_volume_mb"],
            recommended_action="HOLD_FOR_REVIEW",
            confidence=0.8,
            requires_human_review=True,
        )
        return SimpleNamespace(output_parsed=result), ResponseDiagnostics(
            "completed", input_tokens=100, output_tokens=100
        )

    monkeypatch.setattr(
        evaluation, "dotenv_values", lambda _: {"OPENAI_API_KEY": "local-mock-placeholder"}
    )
    monkeypatch.setattr(bounded, "parse_structured_response", fake)
    report = asyncio.run(
        evaluation.run(
            source,
            tmp_path / "out",
            "unused",
            max_budget=0.1,
            stop_at=(datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
        )
    )
    assert report["completed"] and report["attempts"] == len(requests) == 60
    assert report["reused_predictions"] == 300 and report["fresh_360_pipeline_test"] is False
    assert (
        report["runtime_adoption"] is False and report["development_candidate_gate_passed"] is False
    )
    assert report["replayed_360_comparison"][
        "lost_TP_ids"
    ]  # The fake NORMAL-only model loses threats.
    candidate = json.loads((tmp_path / "out/replayed-predictions.json").read_bytes())
    assert len(candidate) == 360
    for before, after in zip(original, candidate, strict=True):
        assert after["truth"] is before["truth"]
        if after["prediction_reused"]:
            assert after["prediction"] is before["prediction"] and after["error"] == before["error"]
    assert (source / "private/predictions.jsonl").read_bytes() == frozen


def test_budget_stop_counts_unattempted_changed_inputs_without_reusing_their_previous_answers(
    arithmetic_source, tmp_path, monkeypatch
):
    source, _ = arithmetic_source
    monkeypatch.setattr(
        evaluation, "dotenv_values", lambda _: {"OPENAI_API_KEY": "local-mock-placeholder"}
    )

    async def forbidden(*args, **kwargs):
        raise AssertionError("paid call forbidden")

    monkeypatch.setattr(bounded, "parse_structured_response", forbidden)
    report = asyncio.run(
        evaluation.run(
            source,
            tmp_path / "out",
            "unused",
            max_budget=0.00001,
            stop_at=(datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
        )
    )
    assert not report["completed"] and report["attempts"] == 0
    assert report["changed_input_metrics"]["unknown_or_error"] == 60
    assert report["changed_input_metrics"]["FN"] == report["changed_input_metrics"]["FP"] == 30
    assert report["reused_predictions"] == 300 and not report["development_candidate_gate_passed"]


def test_arithmetic_experiments_cannot_be_mixed():
    case = development_cases(
        Path(__file__).resolve().parents[1] / "app/data/benchmark/cases.jsonl"
    )[0]
    with pytest.raises(ValueError, match="mutually_exclusive"):
        grounded_input(case.event, include_comparisons=True, download_volume_arithmetic=True)
