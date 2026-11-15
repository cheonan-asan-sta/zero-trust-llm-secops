import asyncio
import hashlib
import json
import sys
from collections import defaultdict

import pytest

from scripts import prepare_m7
from scripts.evaluate_m6 import CONTRACT, MOCK_MODELS, main, run_m7_development


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    source_contract = json.loads(prepare_m7.SOURCE.read_bytes())
    attack_families = {
        "development": ("attack", "protocol_fixture", "scenario-0"),
        "evaluation": ("attack", "protocol_fixture", "scenario-4"),
    }

    rows = []
    for split, day, start in (("development", "02-01", 0), ("evaluation", "03-02", 24)):
        for index in range(start, start + 24):
            label, category, subcategory = attack_families[split] if index % 2 else (
                "benign", "login" if split == "development" else "account", None,
            )
            base = {
                "trace_id": f"private-trace-{index}",
                "label": label,
                "category": category,
                "subcategory": subcategory,
                "module": "auth",
                "http_method": "POST",
                "level": "INFO",
                "duration_ms": 120,
                "user_id": f"private-account-{index}",
                "action_by": f"private-actor-{index}",
                "client_ip": f"198.51.100.{index + 1}",
                "uri": "/private-uri",
                "message": "private-message" if split == "development" else "held-out-sentinel",
                "payload": {"token": "private-payload"},
            }
            events = (
                (f"2026-{day}T00:00:00.003100+00:00", 401, "auth_login_failed_user_not_found", {}),
                (f"2026-{day}T09:00:00+09:00", 400, "private-unknown-type", {}),
                (f"2026-{day}T00:00:00+00:00", 200 + index, None, {}),
                (f"2026-{day}T09:00:00.001900+09:00", 401, "auth_access_log_failed", {}),
                (
                    f"2026-{day}T00:00:00.004100+00:00", 403, "rp_unregistration_failed",
                    {"module": "rp", "payload": {"error": "protected_client"}},
                ),
                (
                    f"2026-{day}T00:00:00.005100+00:00", 403, "rp_unregistration_failed",
                    {"module": "rp", "payload": {"error": "private-unknown-payload-error"}},
                ),
            )
            for timestamp, status, event_type, extra in events:
                row = {**base, "timestamp": timestamp, "http_status": status, **extra}
                if event_type is not None:
                    row["event_type"] = event_type
                rows.append(row)

    raw = "".join(json.dumps(row) + "\n" for row in rows).encode()
    source = tmp_path / "publisher.jsonl"
    source.write_bytes(raw)
    source_contract.update({
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "source_counts": {"rows": len(rows), "sessions": {"benign": 24, "attack": 24}},
    })
    contract_path = tmp_path / "source-contract.json"
    contract_path.write_text(json.dumps(source_contract), encoding="utf-8")
    monkeypatch.setattr(prepare_m7, "SOURCE", contract_path)
    pilot = tmp_path / "pilot"
    prepare_m7.prepare(source, pilot, source_contract)
    (pilot / "evaluation.jsonl").unlink()
    return pilot, source


def rewrite_labels(pilot, labels):
    data = "".join(json.dumps(label) + "\n" for label in labels).encode()
    (pilot / "labels.jsonl").write_bytes(data)
    manifest_path = pilot / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest["files"]["labels.jsonl"] = hashlib.sha256(data).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def test_enriched_development_projects_ordered_safe_events_to_both_candidates(bundle):
    pilot, source = bundle
    contract = json.loads(CONTRACT.read_bytes())
    original = {
        row["session_id"]: row["events"]
        for row in map(json.loads, (pilot / "development.jsonl").read_bytes().splitlines())
    }
    calls = defaultdict(dict)

    async def dispatch(model_id, payload, timeout):
        request = json.loads(payload)
        case_id = request["case_id"]
        events = request["events"]
        assert set(request) == {"case_id", "events", "evidence_ids", "question", "labels"}
        assert [event["since_previous_ms"] for event in events] == [None, 0, 1, 1, 1, 1]
        assert [event["auth_stage"] for event in events] == [
            "unknown", "unknown", "access", "login", "account_management", "account_management",
        ]
        assert [event["failure_reason"] for event in events] == [
            None, None, None, "user_not_found", "protected_client", None,
        ]
        for enriched, observed in zip(events, original[case_id], strict=True):
            assert set(enriched) == set(observed) | {
                "auth_stage", "failure_reason", "since_previous_ms",
            }
            assert {key: enriched[key] for key in observed} == observed
        assert request["evidence_ids"] == [event["evidence_id"] for event in original[case_id]]
        assert b"private-" not in payload and b"198.51.100." not in payload
        assert b"held-out-sentinel" not in payload and b"2026-02-" not in payload
        assert b"auth_login_failed_user_not_found" not in payload
        assert b"auth_access_log_failed" not in payload
        assert case_id not in calls[model_id]
        calls[model_id][case_id] = payload
        return json.dumps({
            "case_id": case_id,
            "predicted_label": "normal",
            "evidence_ids": request["evidence_ids"],
        })

    report = asyncio.run(run_m7_development(pilot, contract, source=source, dispatch=dispatch))
    assert set(calls) == set(MOCK_MODELS)
    assert calls[MOCK_MODELS[0]] == calls[MOCK_MODELS[1]]
    assert calls[MOCK_MODELS[0]].keys() == original.keys()
    assert report["schema"] == "m6-m7-enriched-development-pilot-1"
    assert report["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert report["base_dataset_sha256"] == hashlib.sha256(
        (pilot / "development.jsonl").read_bytes()
    ).hexdigest()
    assert report["split"] == "development"
    assert sum(case["event_count"] for case in report["cases"]) == 144
    assert {case["case_id"]: case["input_sha256"] for case in report["cases"]} == {
        case_id: hashlib.sha256(payload).hexdigest()
        for case_id, payload in calls[MOCK_MODELS[0]].items()
    }
    assert report["budget"]["requests_used"] == 48
    assert report["budget"]["actual_provider_requests"] == 0


def test_enrichment_rejects_digest_change_outside_selected_development_rows(bundle):
    pilot, source = bundle
    raw = source.read_bytes()
    tampered = raw.replace(b"held-out-sentinel", b"HELD-OUT-SENTINEL", 1)
    assert len(raw) == len(tampered) and raw != tampered
    source.write_bytes(tampered)

    async def unexpected_dispatch(*args):
        pytest.fail("unverified source reached mock dispatch")

    contract = json.loads(CONTRACT.read_bytes())
    with pytest.raises(ValueError, match="m7_source_digest"):
        asyncio.run(run_m7_development(pilot, contract, source=source, dispatch=unexpected_dispatch))


def test_enrichment_rejects_changed_selected_record_hash_even_with_matching_manifest(bundle):
    pilot, source = bundle
    labels = [json.loads(line) for line in (pilot / "labels.jsonl").read_bytes().splitlines()]
    development = next(label for label in labels if label["split"] == "development")
    development["records"][0]["sha256"] = "0" * 64
    rewrite_labels(pilot, labels)

    async def unexpected_dispatch(*args):
        pytest.fail("unverified selected row reached mock dispatch")

    contract = json.loads(CONTRACT.read_bytes())
    with pytest.raises(ValueError, match="m7_development_source_record_digest"):
        asyncio.run(run_m7_development(pilot, contract, source=source, dispatch=unexpected_dispatch))


def test_enrichment_rejects_balanced_sidecar_label_swap(bundle):
    pilot, source = bundle
    labels = [json.loads(line) for line in (pilot / "labels.jsonl").read_bytes().splitlines()]
    development = [label for label in labels if label["split"] == "development"]
    normal = next(label for label in development if label["source_label"] == "benign")
    threat = next(label for label in development if label["source_label"] == "attack")
    for field in ("source_label", "expected_label", "category", "subcategory"):
        normal[field], threat[field] = threat[field], normal[field]
    rewrite_labels(pilot, labels)

    async def unexpected_dispatch(*args):
        pytest.fail("unverified labels reached mock dispatch")

    contract = json.loads(CONTRACT.read_bytes())
    with pytest.raises(ValueError, match="m7_development_source_label_mismatch"):
        asyncio.run(run_m7_development(pilot, contract, source=source, dispatch=unexpected_dispatch))


def test_enriched_cli_writes_mock_report(bundle, tmp_path, monkeypatch):
    pilot, source = bundle
    output = tmp_path / "m6" / "enriched.json"
    monkeypatch.setattr(sys, "argv", [
        "evaluate_m6", "--m7-development", str(pilot), "--m7-source", str(source),
        "--output", str(output), "--max-requests", "0",
    ])

    assert main() == 0
    report = json.loads(output.read_bytes())
    assert report["schema"] == "m6-m7-enriched-development-pilot-1"
    assert report["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert len(report["cases"]) == 24
    assert report["budget"]["requests_used"] == 0


def test_enriched_cli_cannot_overwrite_publisher_source(bundle, monkeypatch):
    pilot, source = bundle
    original = source.read_bytes()
    monkeypatch.setattr(sys, "argv", [
        "evaluate_m6", "--m7-development", str(pilot), "--m7-source", str(source),
        "--output", str(source),
    ])

    async def unexpected_run(*args, **kwargs):
        pytest.fail("publisher source must be protected before running the mock evaluation")

    monkeypatch.setattr("scripts.evaluate_m6.run_m7_development", unexpected_run)
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1
    assert source.read_bytes() == original
