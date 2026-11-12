import asyncio
import hashlib
import json
from collections import Counter, defaultdict
from decimal import Decimal

import httpx
import pytest
from test_m7_local_capture import declared_captures, write_bundle

from scripts import evaluate_m6_live, prepare_m7_local
from scripts.evaluate_m6 import MAX_RESPONSE_BYTES, result
from scripts.m6_live_providers import MODELS

CREDENTIALS = {model: f"fixture-key-{index}" for index, model in enumerate(MODELS)}


@pytest.fixture
def local_bundle(tmp_path):
    plan = prepare_m7_local.create_plan()
    files, _ = prepare_m7_local.build_bundle(plan, declared_captures(plan), ())
    directory = tmp_path / "local-bundle"
    write_bundle(directory, files)
    return directory, plan


@pytest.fixture
def prepared(local_bundle):
    directory, _ = local_bundle
    return evaluate_m6_live.prepare_cases(directory, prior_paths=())


def test_live_cases_bind_observations_and_labels_without_sending_truth(local_bundle):
    directory, plan = local_bundle
    inputs, cases, _ = evaluate_m6_live.prepare_cases(directory, prior_paths=())
    assert len(inputs) == len(cases) == 200
    expected = {row["session_id"]: row["expected_label"] for row in plan}
    assert {case["case_id"]: case["expected_label"] for case in cases} == expected
    assert Counter(expected.values()) == {"normal": 100, "threat": 100}
    assert {request["case_id"] for request, _, _ in inputs} == expected.keys()
    for request, payload, case in inputs:
        assert json.loads(payload) == request | {"labels": ["normal", "threat", "unknown"]}
        assert set(request) == {"case_id", "events", "evidence_ids", "question", "labels"}
        assert request["case_id"] == case["case_id"]
        assert case["input_sha256"] == hashlib.sha256(payload).hexdigest()
        assert b"expected_label" not in payload
        assert b"authenticated_subject" not in payload


def test_live_preflight_rejects_rehashed_swapped_scoring_labels(local_bundle):
    directory, _ = local_bundle
    labels_path = directory / "private/scoring-labels.jsonl"
    rows = [json.loads(line) for line in labels_path.read_bytes().splitlines()]
    normal = next(row for row in rows if row["expected_label"] == "normal")
    threat = next(row for row in rows if row["expected_label"] == "threat")
    normal["expected_label"], threat["expected_label"] = "threat", "normal"
    labels = "".join(json.dumps(row) + "\n" for row in rows).encode()
    labels_path.write_bytes(labels)
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["files"]["private/scoring-labels.jsonl"] = hashlib.sha256(labels).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="m7_local_bundle_mismatch"):
        evaluate_m6_live.prepare_cases(directory, prior_paths=())


def test_live_summary_separates_unresolved_cases_from_binary_metrics():
    examples = [
        ("threat", "ok", "threat"),
        ("threat", "ok", "normal"),
        ("normal", "ok", "threat"),
        ("normal", "ok", "normal"),
        ("threat", "abstained", "unknown"),
        ("threat", "refusal", "unknown"),
        ("normal", "response_error", "unknown"),
        ("normal", "not_run", "unknown"),
    ]
    cases = [
        {"case_id": str(index), "expected_label": truth}
        for index, (truth, _, _) in enumerate(examples)
    ]
    rows = [
        result(str(index), "a" * 64, status=status, label=label)
        for index, (_, status, label) in enumerate(examples)
    ]

    summary = evaluate_m6_live.summarize_live(rows, cases)

    assert summary["case_count"] == 8
    assert summary["coverage"] == 0.5
    assert summary["confusion"] == {"tp": 1, "fp": 1, "fn": 1, "tn": 1}
    assert summary["metrics"] == {
        "precision": 0.5, "recall": 0.5, "f1": 0.5, "false_positive_rate": 0.5,
    }
    assert summary["conservative_recall"] == 0.25
    assert summary["status_counts"] == {
        "ok": 4, "abstained": 1, "refusal": 1, "response_error": 1, "not_run": 1,
    }
    assert summary["abstained_count"] == 1
    assert summary["failed_count"] == 2
    assert summary["not_run_count"] == 1
    assert summary["unresolved_by_label"] == {"normal": 2, "threat": 2}
    assert summary["operational_false_positive_rate_bounds"] == [0.25, 0.75]


@pytest.mark.parametrize(("raw", "reason"), [
    pytest.param(None, "invalid_response_text", id="missing-text"),
    pytest.param("\ud800", "invalid_response_text", id="invalid-unicode"),
    pytest.param("가" * (MAX_RESPONSE_BYTES // 3 + 1), "response_too_large", id="oversized-text"),
    pytest.param("{private-model-output", "invalid_json", id="malformed-json"),
    pytest.param(
        '{"case_id":"case","case_id":"private-model-output","predicted_label":"normal","evidence_ids":[]}',
        "invalid_json", id="duplicate-json-key",
    ),
    pytest.param('["private-model-output"]', "invalid_response_fields", id="array"),
    pytest.param(
        '{"case_id":"case","predicted_label":"normal"}',
        "invalid_response_fields", id="missing-field",
    ),
    pytest.param(
        '{"case_id":"case","predicted_label":"normal","evidence_ids":[],"extra":"private-model-output"}',
        "invalid_response_fields", id="extra-field",
    ),
    pytest.param(
        '{"case_id":"case","predicted_label":"private-model-output","evidence_ids":[]}',
        "invalid_field_value", id="invalid-label",
    ),
    pytest.param(
        '{"case_id":"private-model-output","predicted_label":"normal","evidence_ids":[]}',
        "case_id_mismatch", id="wrong-case",
    ),
    pytest.param(
        '{"case_id":"case","predicted_label":"normal","evidence_ids":["private-model-output"]}',
        "evidence_id_mismatch", id="unknown-evidence",
    ),
])
def test_live_response_validation_records_only_safe_failure_reasons(raw, reason):
    case = {"case_id": "case", "input_sha256": "a" * 64}
    request = {"case_id": "case", "evidence_ids": ["known-evidence"]}

    row = evaluate_m6_live.result_for(request, case, {"status": "completed", "raw": raw}, {})

    assert row["status"] == "response_error"
    assert row["attempts"][0]["validation_error"] == reason
    assert "private-model-output" not in json.dumps(row)


def test_live_response_validation_distinguishes_provider_error_from_abstention():
    case = {"case_id": "case", "input_sha256": "a" * 64}
    request = {"case_id": "case", "evidence_ids": ["known-evidence"]}
    raw = '{"case_id":"case","predicted_label":"unknown","evidence_ids":["known-evidence"]}'

    provider_error = evaluate_m6_live.result_for(request, case, {"status": "response_error"}, {})
    abstention = evaluate_m6_live.result_for(request, case, {"status": "completed", "raw": raw}, {})

    assert provider_error["status"] == "response_error"
    assert provider_error["attempts"][0]["validation_error"] == "provider_response_invalid"
    assert abstention["status"] == "abstained"
    assert "validation_error" not in abstention["attempts"][0]


def test_live_runner_keeps_identical_inputs_and_separates_provider_failures(prepared, tmp_path):
    inputs, cases, provenance = prepared
    truth = {case["case_id"]: case["expected_label"] for case in cases}
    normal = next(case_id for case_id, label in truth.items() if label == "normal")
    threat = next(case_id for case_id, label in truth.items() if label == "threat")
    sent = defaultdict(list)

    def respond(request):
        body = json.loads(request.content)
        model = body["model"]
        openai = model == MODELS[0]
        assert request.url.host == ("api.openai.com" if openai else "api.anthropic.com")
        payload = body["input" if openai else "messages"][0]["content"].encode()
        assert b"expected_label" not in payload
        case = json.loads(payload)
        case_id = case["case_id"]
        counting = request.url.path.endswith(("/input_tokens", "/count_tokens"))
        sent[model, counting].append(payload)
        if counting:
            return httpx.Response(200, json={"input_tokens": 300})
        answer = {
            "case_id": case_id, "predicted_label": truth[case_id],
            "evidence_ids": case["evidence_ids"][:1],
        }
        usage = {"input_tokens": 300, "output_tokens": 20}
        if openai:
            assert body["store"] is False
            if case_id == normal:
                answer["predicted_label"] = "unknown"
            elif case_id == threat:
                answer["case_id"] = "invalid-private-case"
            return httpx.Response(200, json={
                "model": model, "status": "completed", "usage": usage,
                "output": [{"type": "message", "role": "assistant", "content": [{
                    "type": "output_text", "text": json.dumps(answer),
                }]}],
            })
        if case_id == threat:
            return httpx.Response(200, json={
                "model": model, "stop_reason": "refusal", "usage": usage, "content": [],
            })
        if case_id == normal:
            answer["predicted_label"] = "threat"
        return httpx.Response(200, json={
            "model": model, "stop_reason": "end_turn", "usage": usage,
            "content": [{"type": "text", "text": json.dumps(answer)}],
        })

    output_dir = tmp_path / "output"
    report = asyncio.run(evaluate_m6_live.run_live(
        output_dir, inputs, cases, provenance,
        credentials=CREDENTIALS, max_usd=Decimal(20), max_requests=800,
        transport=httpx.MockTransport(respond),
    ))

    assert sent[MODELS[0], False] == sent[MODELS[1], False] == [row[1] for row in inputs]
    for model in MODELS:
        assert sent[model, True] == sent[model, False]
    sol, sonnet = (report["models"][model]["summary"] for model in MODELS)
    assert sol["confusion"] == {"tp": 99, "fp": 0, "fn": 0, "tn": 99}
    assert sol["abstained_count"] == sol["failed_count"] == 1
    assert sol["status_counts"]["response_error"] == 1
    assert sol["validation_failure_counts"] == {"case_id_mismatch": 1}
    assert sonnet["confusion"] == {"tp": 99, "fp": 1, "fn": 0, "tn": 99}
    assert sonnet["failed_count"] == 1
    assert sonnet["abstained_count"] == 0
    assert sol["conservative_recall"] == sonnet["conservative_recall"] == 0.99
    assert report["budget"]["actual_provider_requests"] == 400
    assert report["budget"]["token_count_requests"] == 400
    ledger_text = (output_dir / "requests.jsonl").read_text()
    ledger = [json.loads(line) for line in ledger_text.splitlines()]
    assert [row["kind"] for row in ledger] == ["reserved", "result"] * 400
    failure = next(row for row in ledger if row["kind"] == "result"
                   and row["result"]["status"] == "response_error")
    assert failure["result"]["attempts"][0]["validation_error"] == "case_id_mismatch"
    for persisted in ((output_dir / "report.json").read_text(), ledger_text):
        assert "invalid-private-case" not in persisted
        assert all(key not in persisted for key in CREDENTIALS.values())


@pytest.mark.parametrize("issue", ["credentials", "requests", "cost"])
def test_live_budget_and_credentials_guards_block_transport(prepared, tmp_path, issue):
    inputs, cases, provenance = prepared
    options = {"credentials": CREDENTIALS, "max_usd": Decimal(20), "max_requests": 800}
    if issue == "credentials":
        options["credentials"] = {MODELS[0]: CREDENTIALS[MODELS[0]]}
    elif issue == "requests":
        options["max_requests"] = 1
    else:
        options["max_usd"] = Decimal(0)

    def unexpected(_request):
        pytest.fail("blocked live preflight attempted a provider request")

    with pytest.raises(ValueError):
        asyncio.run(evaluate_m6_live.run_live(
            tmp_path / "output", inputs, cases, provenance,
            transport=httpx.MockTransport(unexpected), **options,
        ))


def test_live_failed_token_preflight_never_dispatches_inference(prepared, tmp_path):
    inputs, cases, provenance = prepared
    calls = []

    def denied(request):
        calls.append(request.url.path)
        assert request.url.path.endswith(("/input_tokens", "/count_tokens"))
        return httpx.Response(401, json={"error": "private provider message"})

    report = asyncio.run(evaluate_m6_live.run_live(
        tmp_path / "output", inputs, cases, provenance,
        credentials=CREDENTIALS, max_usd=Decimal(20), max_requests=800,
        transport=httpx.MockTransport(denied),
    ))

    assert calls
    assert report["stop_reason"] == "token_count_unavailable"
    assert report["budget"]["actual_provider_requests"] == 0
    for model in MODELS:
        assert report["models"][model]["summary"]["not_run_count"] == 200
        assert report["models"][model]["summary"]["metrics"]["precision"] is None
    assert "private provider message" not in json.dumps(report)
