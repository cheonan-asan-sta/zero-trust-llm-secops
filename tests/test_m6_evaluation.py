import asyncio
import hashlib
import json
import shutil
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

import pytest

from app.services.detection_benchmark import DetectionBenchmark
from scripts.evaluate_m6 import CONTRACT, main, run_m7_development, run_pilot, write_report
from scripts.prepare_m7 import SOURCE as M7_SOURCE

SOL = "gpt-6.1-sol"
SONNET = "claude-sonnet-5-5"
RULE = "rule-frozen-v0.17.0"
M7_PILOT = M7_SOURCE.parent / "pilot"


@pytest.fixture(scope="module")
def benchmark():
    return DetectionBenchmark()


@pytest.fixture
def contract():
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


def response(request, label, **extra):
    return json.dumps({"case_id": request["case_id"], "predicted_label": label, **extra})


def test_candidates_share_identical_blind_development_cases_and_aggregate_separately(
    benchmark, contract
):
    calls = defaultdict(dict)
    source = {case.event.event_id: case for case in benchmark.cases}

    async def dispatch(model_id, payload, timeout):
        request = json.loads(payload)
        case = source[request["event"]["event_id"]]
        assert isinstance(payload, bytes)
        assert case.split == "development"
        assert set(request) == {"case_id", "event", "evidence_ids", "question", "labels"}
        assert request["event"] == case.event.model_dump(mode="json", exclude={"ground_truth"})
        assert case.family_id.encode() not in payload
        assert request["labels"] == ["normal", "threat", "unknown"]
        assert 0 < timeout <= contract["budget_proposal"]["per_request_timeout_seconds"]
        calls[model_id][request["case_id"]] = payload
        return response(request, "normal" if model_id == SOL else "threat")

    result = asyncio.run(run_pilot(benchmark, contract, dispatch=dispatch))

    assert list(calls) == [SOL, SONNET]
    assert calls[SOL] == calls[SONNET] and len(calls[SOL]) == 24
    assert set(result["models"]) == {RULE, SOL, SONNET}
    assert Counter(case["expected_label"] for case in result["cases"]) == {"normal": 12, "threat": 12}
    assert len({case["benchmark_case_id"] for case in result["cases"]}) == 24
    hashes = {
        case_id: hashlib.sha256(payload).hexdigest()
        for case_id, payload in calls[SOL].items()
    }
    assert {case["case_id"]: case["input_sha256"] for case in result["cases"]} == hashes
    for model in result["models"].values():
        assert {row["case_id"]: row["input_sha256"] for row in model["results"]} == hashes
        assert model["summary"]["case_count"] == 24
    sol = result["models"][SOL]["summary"]
    sonnet = result["models"][SONNET]["summary"]
    assert sol["confusion"] == {"tp": 0, "fp": 0, "fn": 12, "tn": 12}
    assert sonnet["confusion"] == {"tp": 12, "fp": 12, "fn": 0, "tn": 0}
    assert sol["coverage"] == sonnet["coverage"] == 1
    assert sol["metrics"]["precision"] is None
    assert sonnet["metrics"]["precision"] == 0.5
    assert result["budget"]["requests_used"] == 48


def test_timeout_retries_once_and_remains_unknown_in_conservative_recall(benchmark, contract):
    source = {case.event.event_id: case.threat for case in benchmark.cases}
    failed_id = None
    calls = Counter()

    async def dispatch(model_id, payload, timeout):
        nonlocal failed_id
        request = json.loads(payload)
        case_id = request["case_id"]
        is_threat = source[request["event"]["event_id"]]
        calls[model_id, case_id] += 1
        if model_id == SOL and is_threat and (failed_id is None or case_id == failed_id):
            failed_id = case_id
            raise TimeoutError("raw timeout details")
        return response(request, "threat" if is_threat else "normal")

    result = asyncio.run(run_pilot(benchmark, contract, dispatch=dispatch))
    assert calls[SOL, failed_id] == 2
    assert result["budget"]["requests_used"] == 49
    model = result["models"][SOL]
    timed_out = next(row for row in model["results"] if row["case_id"] == failed_id)
    assert timed_out["status"] == "timeout"
    assert timed_out["predicted_label"] == "unknown"
    assert [attempt["status"] for attempt in timed_out["attempts"]] == ["timeout", "timeout"]
    assert "raw timeout details" not in json.dumps(result)

    summary = model["summary"]
    assert summary["case_count"] == 24
    assert summary["normal_count"] == summary["threat_count"] == 12
    assert summary["coverage"] == pytest.approx(23 / 24)
    assert summary["status_counts"]["timeout"] == 1
    assert summary["metrics"]["recall"] == 1
    assert summary["conservative_recall"] == pytest.approx(11 / 12)


def test_request_limit_is_shared_across_models_and_preserves_unattempted_cases(
    benchmark, contract
):
    calls = Counter()

    async def dispatch(model_id, payload, timeout):
        calls[model_id] += 1
        return response(json.loads(payload), "normal")

    result = asyncio.run(run_pilot(benchmark, contract, dispatch=dispatch, max_requests=25))

    assert calls == {SOL: 24, SONNET: 1}
    assert result["budget"]["requests_used"] == 25
    sonnet = result["models"][SONNET]
    assert len(sonnet["results"]) == sonnet["summary"]["case_count"] == 24
    assert sonnet["summary"]["status_counts"]["request_limit"] == 23
    assert sonnet["summary"]["coverage"] == pytest.approx(1 / 24)
    assert all(
        row["predicted_label"] == "unknown" and not row["attempts"]
        for row in sonnet["results"] if row["status"] == "request_limit"
    )


@pytest.mark.parametrize("failure,expected_status", [
    ("wrong_case", "response_error"),
    ("unknown_evidence", "response_error"),
    ("malformed", "response_error"),
    ("duplicate_field", "response_error"),
    ("transport", "response_error"),
    ("forbidden_field", "response_error"),
    ("abstain", "abstained"),
])
def test_invalid_or_unknown_response_is_never_counted_as_normal(
    benchmark, contract, failure, expected_status
):
    failed_id = None

    async def dispatch(model_id, payload, timeout):
        nonlocal failed_id
        request = json.loads(payload)
        if model_id == SOL and failed_id is None:
            failed_id = request["case_id"]
            if failure == "wrong_case":
                return json.dumps({"case_id": "different-case", "predicted_label": "normal"})
            if failure == "unknown_evidence":
                return response(request, "normal", evidence_ids=["unlisted-evidence"])
            if failure == "malformed":
                return "{raw response details"
            if failure == "duplicate_field":
                raw = response(request, "normal")
                return raw[:-1] + ', "predicted_label": "threat"}'
            if failure == "transport":
                raise OSError("raw response details")
            if failure == "forbidden_field":
                return response(request, "normal", access_token="raw response details")
            return response(request, "unknown")
        return response(request, "normal")

    result = asyncio.run(run_pilot(benchmark, contract, dispatch=dispatch))
    model = result["models"][SOL]
    failed = next(row for row in model["results"] if row["case_id"] == failed_id)

    assert failed["status"] == expected_status
    assert failed["predicted_label"] == "unknown"
    assert len(failed["attempts"]) == 1
    assert model["summary"]["status_counts"][expected_status] == 1
    assert model["summary"]["coverage"] == pytest.approx(23 / 24)
    assert sum(model["summary"]["confusion"].values()) == 23
    assert "raw response details" not in json.dumps(result)


def test_runner_enforces_an_async_dispatch_deadline(benchmark, contract):
    contract["budget_proposal"]["per_request_timeout_seconds"] = 0.02
    cancelled = False

    async def dispatch(model_id, payload, timeout):
        nonlocal cancelled
        try:
            await asyncio.Event().wait()
        finally:
            cancelled = True

    async def evaluate():
        return await asyncio.wait_for(
            run_pilot(benchmark, contract, dispatch=dispatch, max_requests=1), timeout=3
        )

    result = asyncio.run(evaluate())
    row = next(row for row in result["models"][SOL]["results"] if row["attempts"])
    assert cancelled
    assert row["status"] == "timeout"
    assert row["predicted_label"] == "unknown"
    assert row["budget_stop"] == "request_limit"
    assert result["budget"]["requests_used"] == 1


def test_cost_cap_retains_the_reservation_of_an_unreconciled_timeout(benchmark, contract):
    budget = contract["budget_proposal"]
    prices = next(
        candidate["standard_usd_per_million"]
        for candidate in contract["candidates"] if candidate["id"] == SOL
    )
    one_request = (
        Decimal(str(prices["input"])) * budget["max_input_tokens_per_provider"]
        + Decimal(str(prices["output"])) * budget["max_billed_output_tokens"]
    ) / 1_000_000
    budget["aggregate_usd"] = str(one_request)
    calls = Counter()

    async def dispatch(model_id, payload, timeout):
        calls[model_id] += 1
        raise TimeoutError

    result = asyncio.run(run_pilot(benchmark, contract, dispatch=dispatch))
    first, *remaining = result["models"][SOL]["results"]

    assert calls == {SOL: 1}
    assert first["status"] == "timeout" and first["budget_stop"] == "cost_limit"
    assert len(first["attempts"]) == 1
    assert Decimal(first["attempts"][0]["reserved_usd"]) == one_request
    assert all(row["status"] == "cost_limit" and not row["attempts"] for row in remaining)
    assert result["models"][SONNET]["summary"]["status_counts"] == {"cost_limit": 24}
    assert result["budget"]["requests_used"] == 1
    assert Decimal(result["budget"]["simulated_reserved_usd"]) == one_request


@pytest.mark.parametrize("limit", [0, 2])
def test_cli_writes_an_offline_report_without_git(tmp_path, monkeypatch, limit):
    output = tmp_path / "m6" / "pilot.json"
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(
        sys, "argv", ["evaluate_m6", "--output", str(output), "--max-requests", str(limit)]
    )

    assert main() == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["mode"] == "offline_mock_pilot"
    assert report["source_commit"] is None
    assert report["split"] == "development"
    assert len(report["cases"]) == 24
    assert report["budget"]["request_limit"] == report["budget"]["requests_used"] == limit
    assert report["budget"]["actual_provider_requests"] == 0


def test_explanations_are_checked_separately_from_classification(benchmark, contract):
    async def dispatch(model_id, payload, timeout):
        request = json.loads(payload)
        detail = {
            "case_id": request["case_id"],
            "summary": "raw explanation text",
            "limitations": "mock",
            "evidence_ids": request["evidence_ids"] if model_id == SOL else ["unlisted-evidence"],
        }
        return response(request, "normal", explanation=detail)

    result = asyncio.run(run_pilot(benchmark, contract, dispatch=dispatch))
    assert result["models"][SOL]["summary"]["explanation_status_counts"] == {"ok": 24}
    sonnet = result["models"][SONNET]["summary"]
    assert sonnet["explanation_status_counts"] == {"response_error": 24}
    assert sonnet["status_counts"] == {"ok": 24}
    assert "raw explanation text" not in json.dumps(result)


def test_wall_limit_blocks_dispatch_before_reservation(benchmark, contract):
    times = iter([0, 1201])
    calls = []

    def clock():
        return next(times, 1201)

    async def dispatch(model_id, payload, timeout):
        calls.append(model_id)

    result = asyncio.run(run_pilot(benchmark, contract, dispatch=dispatch, clock=clock))
    assert calls == []
    assert result["budget"]["requests_used"] == 0
    assert result["budget"]["simulated_reserved_usd"] == "0"
    for model_id in (SOL, SONNET):
        assert result["models"][model_id]["summary"]["status_counts"] == {"wall_limit": 24}


def test_concurrent_report_writes_publish_one_complete_report(tmp_path):
    output = tmp_path / "pilot.json"
    reports = [{"data": char * 100_000} for char in "abcd"]
    with ThreadPoolExecutor(max_workers=4) as executor:
        tasks = [executor.submit(write_report, output, report) for report in reports]
        for task in tasks:
            task.result()

    assert json.loads(output.read_text(encoding="utf-8")) in reports
    assert list(tmp_path.iterdir()) == [output]


def test_m7_candidates_receive_identical_ordered_development_observations(contract):
    observations = [
        json.loads(line) for line in (M7_PILOT / "development.jsonl").read_bytes().splitlines()
    ]
    source = {row["session_id"]: row for row in observations}
    development_truth = {
        row["session_id"]: row["expected_label"]
        for row in map(json.loads, (M7_PILOT / "labels.jsonl").read_bytes().splitlines())
        if row["split"] == "development"
    }
    calls = defaultdict(dict)

    async def dispatch(model_id, payload, timeout):
        request = json.loads(payload)
        assert set(request) == {"case_id", "events", "evidence_ids", "question", "labels"}
        session = source[request["case_id"]]
        assert request["events"] == session["events"]
        assert request["evidence_ids"] == [event["evidence_id"] for event in session["events"]]
        assert request["labels"] == ["normal", "threat", "unknown"]
        case_id = request["case_id"]
        calls[model_id][case_id] = payload
        return response(
            request, "normal" if model_id == SOL else "threat", evidence_ids=request["evidence_ids"]
        )

    result = asyncio.run(run_m7_development(M7_PILOT, contract, dispatch=dispatch))

    assert result["split"] == "development"
    assert set(result["models"]) == set(calls) == {SOL, SONNET}
    assert calls[SOL] == calls[SONNET] and len(calls[SOL]) == 24
    assert sum(len(json.loads(payload)["events"]) for payload in calls[SOL].values()) == 146
    assert {case["case_id"]: case["expected_label"] for case in result["cases"]} == development_truth
    assert {case["case_id"]: case["event_count"] for case in result["cases"]} == {
        session_id: len(session["events"]) for session_id, session in source.items()
    }
    hashes = {case_id: hashlib.sha256(payload).hexdigest() for case_id, payload in calls[SOL].items()}
    assert {case["case_id"]: case["input_sha256"] for case in result["cases"]} == hashes
    for model in result["models"].values():
        assert {row["case_id"]: row["input_sha256"] for row in model["results"]} == hashes
        assert model["summary"]["case_count"] == 24
    assert result["models"][SOL]["summary"]["confusion"] == {"tp": 0, "fp": 0, "fn": 12, "tn": 12}
    assert result["models"][SONNET]["summary"]["confusion"] == {"tp": 12, "fp": 12, "fn": 0, "tn": 0}
    assert result["budget"]["requests_used"] == 48
    assert result["budget"]["actual_provider_requests"] == 0


def test_m7_failure_and_request_budget_accounting_keeps_all_sessions(contract):
    calls = []

    async def dispatch(model_id, payload, timeout):
        request = json.loads(payload)
        calls.append((model_id, request["case_id"]))
        if len(calls) <= 2:
            raise TimeoutError
        if len(calls) == 3:
            return response(request, "normal", evidence_ids=["unlisted-evidence"])
        return response(request, "unknown" if len(calls) == 4 else "normal")

    result = asyncio.run(run_m7_development(M7_PILOT, contract, dispatch=dispatch, max_requests=5))

    assert len(calls) == result["budget"]["requests_used"] == 5
    assert calls[0] == calls[1] and {model for model, _ in calls} == {SOL}
    sol = result["models"][SOL]
    sonnet = result["models"][SONNET]
    assert sol["summary"]["status_counts"] == {
        "timeout": 1, "response_error": 1, "abstained": 1, "ok": 1, "request_limit": 20,
    }
    assert sonnet["summary"]["status_counts"] == {"request_limit": 24}
    for model in (sol, sonnet):
        assert len(model["results"]) == 24
        assert all(
            row["predicted_label"] == "unknown"
            for row in model["results"] if row["status"] != "ok"
        )


def test_m7_rejects_substituted_evaluation_split_even_if_file_hash_matches(tmp_path, contract):
    pilot = shutil.copytree(M7_PILOT, tmp_path / "pilot")
    development = (pilot / "evaluation.jsonl").read_bytes()
    (pilot / "development.jsonl").write_bytes(development)
    manifest_path = pilot / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["files"]["development.jsonl"] = hashlib.sha256(development).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError):
        asyncio.run(run_m7_development(pilot, contract))


def test_m7_cli_writes_the_development_report(tmp_path, monkeypatch):
    pilot = tmp_path / "pilot"
    pilot.mkdir()
    for filename in ("development.jsonl", "labels.jsonl", "manifest.json"):
        shutil.copyfile(M7_PILOT / filename, pilot / filename)
    output = tmp_path / "m7" / "pilot.json"
    monkeypatch.setattr(sys, "argv", [
        "evaluate_m6", "--m7-development", str(pilot),
        "--output", str(output), "--max-requests", "0",
    ])

    assert main() == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["mode"] == "offline_mock_pilot"
    assert report["schema"] == "m6-m7-development-pilot-1"
    assert report["split"] == "development"
    for key, filename in {
        "dataset_sha256": "development.jsonl",
        "labels_sha256": "labels.jsonl",
        "split_manifest_sha256": "manifest.json",
    }.items():
        assert report[key] == hashlib.sha256((pilot / filename).read_bytes()).hexdigest()
    assert len(report["cases"]) == 24
    assert set(report["models"]) == {SOL, SONNET}
    assert report["budget"]["actual_provider_requests"] == 0


@pytest.mark.parametrize("filename", [
    "development.jsonl", "evaluation.jsonl", "labels.jsonl", "manifest.json",
])
def test_m7_cli_cannot_overwrite_pilot_artifacts(tmp_path, monkeypatch, filename):
    pilot = shutil.copytree(M7_PILOT, tmp_path / "pilot")
    output = pilot / filename
    original = output.read_bytes()
    monkeypatch.setattr(sys, "argv", [
        "evaluate_m6", "--m7-development", str(pilot), "--output", str(output),
    ])

    async def unexpected_run(*args, **kwargs):
        pytest.fail("pilot artifacts must be protected before running the mock evaluation")

    monkeypatch.setattr("scripts.evaluate_m6.run_m7_development", unexpected_run)
    with pytest.raises(SystemExit) as error:
        main()

    assert error.value.code == 1
    assert output.read_bytes() == original
