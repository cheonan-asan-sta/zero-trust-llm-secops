"""Replay integrity on fabricated test artifacts; no paid provider requests."""

import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.analyzers.structured_response import ResponseDiagnostics
from app.grounded_prompting import GROUNDED_INSTRUCTIONS, grounded_input
from app.models import SecurityAssessment
from scripts import retry_incomplete_evaluation as retry
from scripts.evaluate_llm_development import development_cases, write_json
from scripts.evaluate_llm_grounded import MODEL, metrics


def save_rows(directory, rows):
    (directory / "private/predictions.jsonl").write_bytes(
        b"".join((json.dumps(row) + "\n").encode() for row in rows)
    )


@pytest.fixture
def source(tmp_path):
    directory = tmp_path / "source"
    (directory / "private").mkdir(parents=True)
    cases_path = Path(__file__).resolve().parents[1] / "app/data/benchmark/cases.jsonl"
    cases = development_cases(cases_path)
    selected = next(case.case_id for case in cases if not case.threat)
    inputs, rows = [], []
    for case in cases:
        identity = hashlib.sha256(case.case_id.encode()).hexdigest()
        event = case.event.model_copy(update={"event_id": identity, "ground_truth": None})
        messages = [
            {"role": "system", "content": "test-only source fixture"},
            {"role": "user", "content": "{}"},
        ]
        row = {
            "id": identity,
            "truth": case.threat,
            "prediction": case.threat,
            "domain": case.domain,
            "family_id": case.family_id,
            "error": None,
        }
        if case.case_id == selected:
            messages = [
                {"role": "system", "content": GROUNDED_INSTRUCTIONS},
                *grounded_input(event),
            ]
            row.update(
                prediction=None,
                error="StructuredResponseFailure",
                error_code="response_not_completed",
                response_diagnostics={
                    "status": "incomplete",
                    "incomplete_reason": "max_output_tokens",
                    "input_tokens": 100,
                    "output_tokens": 2400,
                },
            )
        inputs.append({"id": identity, "messages": messages})
        rows.append(row)
    payload = b"".join((json.dumps(row, ensure_ascii=False) + "\n").encode() for row in inputs)
    (directory / "private/inputs.jsonl").write_bytes(payload)
    save_rows(directory, rows)
    plan = {
        "model": MODEL,
        "max_output_tokens": 2400,
        "reasoning_effort": "low",
        "inputs_sha256": hashlib.sha256(payload).hexdigest(),
        "cases_sha256": hashlib.sha256(cases_path.read_bytes()).hexdigest(),
    }
    write_json(directory / "plan.json", plan)
    report = {
        "completed": True,
        "attempts": 360,
        "unattempted": 0,
        "metrics": metrics(rows),
        "plan_sha256": hashlib.sha256((directory / "plan.json").read_bytes()).hexdigest(),
    }
    write_json(directory / "report.json", report)
    return directory, rows, inputs, plan, report


def test_natural_retry_replays_other_359_unchanged_and_never_overwrites_source(
    source, tmp_path, monkeypatch
):
    directory, rows, _, _, _ = source
    before = {p.relative_to(directory): p.read_bytes() for p in directory.rglob("*") if p.is_file()}
    calls = []

    async def fake(client, **kwargs):
        calls.append(kwargs)
        assert client.max_retries == 0 and kwargs["max_output_tokens"] == 4000
        assessment = SecurityAssessment(
            risk_score=0,
            risk_level="LOW",
            violation_type="NORMAL",
            rationale="Fixture retry",
            evidence=["device.managed"],
            recommended_action="HOLD_FOR_REVIEW",
            confidence=0.8,
            requires_human_review=True,
        )
        return SimpleNamespace(output_parsed=assessment), ResponseDiagnostics(
            "completed", input_tokens=100, output_tokens=100
        )

    monkeypatch.setattr(
        retry, "dotenv_values", lambda _: {"OPENAI_API_KEY": "local-mock-placeholder"}
    )
    monkeypatch.setattr(retry, "parse_structured_response", fake)
    result = asyncio.run(retry.run(directory, tmp_path / "out", "unused"))
    assert result["completed"] and result["attempts"] == len(calls) == 1
    assert result["fresh_360_pipeline_test"] is False and result["source_overwritten"] is False
    assert result["source_first_attempt_metrics"]["FP"] == 1
    assert result["replayed_pipeline_metrics"]["FP"] == 0
    replayed = json.loads((tmp_path / "out/replayed-predictions.json").read_bytes())
    for old, new in zip(rows, replayed, strict=True):
        if old["error"] is None:
            assert new == old
        else:
            assert new["first_attempt"] == old and new["actual_retry"]["prediction"] is False
    assert before == {
        p.relative_to(directory): p.read_bytes() for p in directory.rglob("*") if p.is_file()
    }


@pytest.mark.parametrize(
    "change",
    [
        "plan",
        "metric",
        "label",
        "family",
        "prediction",
        "duplicate_input",
        "duplicate_row",
        "error_with_prediction",
    ],
)
def test_changed_source_is_rejected_before_credentials_or_paid_calls(
    source, tmp_path, monkeypatch, change
):
    directory, rows, inputs, plan, report = source
    if change == "plan":
        plan["reasoning_effort"] = "none"
        write_json(directory / "plan.json", plan)
    elif change == "metric":
        report["metrics"]["TP"] += 1
        write_json(directory / "report.json", report)
    elif change == "duplicate_input":
        inputs.append(inputs[0])
        payload = b"".join((json.dumps(row) + "\n").encode() for row in inputs)
        (directory / "private/inputs.jsonl").write_bytes(payload)
        plan["inputs_sha256"] = hashlib.sha256(payload).hexdigest()
        write_json(directory / "plan.json", plan)
        report["plan_sha256"] = hashlib.sha256((directory / "plan.json").read_bytes()).hexdigest()
        write_json(directory / "report.json", report)
    else:
        row = next(r for r in rows if r["error"] is not None)
        if change == "label":
            row["truth"] = not row["truth"]
        elif change == "family":
            row["family_id"] = "wrong-family"
        elif change == "prediction":
            row["error"] = None
            row["prediction"] = 1
        elif change == "duplicate_row":
            rows.append(rows[0])
        elif change == "error_with_prediction":
            row["prediction"] = False
        save_rows(directory, rows)
    monkeypatch.setattr(
        retry, "dotenv_values", lambda _: pytest.fail("credentials must not be read")
    )
    with pytest.raises(ValueError):
        asyncio.run(retry.run(directory, tmp_path / "out", "unused"))
    assert not (tmp_path / "out").exists()


def test_incomplete_eligibility_uses_status_reason_and_error_not_class_label(source):
    directory, rows, _, _, report = source
    threat = next(r for r in rows if r["truth"])
    first = next(r for r in rows if r["error"] is not None)
    threat.update(
        prediction=None,
        error=first["error"],
        error_code=first["error_code"],
        response_diagnostics=first["response_diagnostics"],
    )
    save_rows(directory, rows)
    report["metrics"] = metrics(rows)
    write_json(directory / "report.json", report)
    eligible = retry.load_source(directory)[-1]
    assert len(eligible) == 2 and {r["truth"] for r in eligible} == {True, False}
