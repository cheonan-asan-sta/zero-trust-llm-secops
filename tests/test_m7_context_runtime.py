"""Verify actual signed intake and paired context evaluation, without scoring labels."""

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from scripts.m7_context_runtime import run_case


def _identifier(prefix):
    return "x-" + uuid4().hex


def _spec():
    base = datetime(2026, 11, 10, 12, tzinfo=UTC)
    actor = _identifier("a")
    resources = [_identifier("o") for _ in range(25)]

    def sample(offset):
        connection = _identifier("k")
        return {
            "capture_id": _identifier("c"), "session_id": _identifier("s"),
            "activity": {
                "source": "cloudtrail", "original_group_id": _identifier("g"),
                "events": [{
                    "id": _identifier("e"), "timestamp": (base + timedelta(seconds=offset)).isoformat(),
                    "kind": "AwsApiCall", "api_service": "s3.amazonaws.com", "api_action": "PutObject",
                    "connection_id": connection, "principal_hash": actor,
                    "resource_hashes": [resources[index % 25]], "outcome": "success",
                } for index in range(100)],
            },
        }

    return {
        "case_id": _identifier("c"), "base_time": base.isoformat(), "tenant_id": _identifier("t"),
        "scope": {"source": "cloudtrail", "user_id": _identifier("u"),
                  "device_id": _identifier("d"), "resource_id": "zt-demo-documents", "action": "READ",
                  "principal_hash": actor},
        "baseline_samples": [sample(index) for index in range(3)], "target": sample(10),
        "baseline": {"id": _identifier("b"), "enabled": True, "revoked": False},
        "approval": {"id": _identifier("a"), "mode": "valid", "max_uses": 1},
        "observation": {"id": _identifier("o"), "kind": "none", "scope": "same",
                        "signature": "valid", "posture": "compromised"},
        "session_revoke": False, "prior_use": None,
    }


def test_legacy_runtime_without_execution_evidence_holds_reviewed_work(tmp_path):
    spec = _spec()
    row = run_case(spec, tmp_path / "case")
    assert row["rule_only"]["verdict"] == "unknown"
    assert row["with_context"]["verdict"] == "unknown"
    assert row["with_context"]["reason"] == "EXECUTION_POLICY_REQUIRED"
    assert row["rule_input_sha256"] == row["context_activity_sha256"] == row["activity_sha256"]
    assert row["policy_journal_unchanged_by_evaluation"] is True
    assert row["with_context"]["enforcement_eligible"] is False
    records = row["provenance"]["context_records"]
    assert len([record for record in records if record["kind"] == "capture"]) == 4
    assert {record["kind"] for record in records} == {"capture", "baseline", "approval"}
    encoded = json.dumps(row)
    assert '"signature"' not in encoded
    assert '"grant_token"' not in encoded
    assert "PRIVATE KEY" not in encoded
    assert "PRIVATE KEY" not in (tmp_path / "case" / "registry.json").read_text()


@pytest.mark.parametrize("kind", ["device", "guardduty"])
def test_committed_adverse_signal_is_used_by_real_context_service(tmp_path, kind):
    spec = _spec()
    spec["observation"]["kind"] = kind
    row = run_case(spec, tmp_path / "case")
    assert row["rule_only"]["verdict"] == "unknown"
    assert row["with_context"]["verdict"] == "threat"
    assert row["provenance"]["observation_intake"]["state"] == "completed"
    markers = row["provenance"]["observations"]
    assert len(markers) == 1
    assert markers[0]["event_id"] == spec["observation"]["id"]
    assert markers[0]["restriction"] == "DENY"
    intake = row["provenance"]["observation_intake"]
    assert intake["request"]["observation"] == markers[0]["observation"]
    assert intake["input_sha256"] == markers[0]["input_digest_sha256"]
    assert "signature" not in intake["request"]
    assert row["with_context"]["trusted_evidence"][0]["event_id"] == markers[0]["event_id"]
    assert row["provenance"]["session_history"][-1]["status"] == "REVOKED"


@pytest.mark.parametrize("control", ["invalid", "other"])
def test_untrusted_or_other_scope_report_does_not_taint_approved_work(tmp_path, control):
    spec = _spec()
    spec["observation"]["kind"] = "device"
    spec["observation"]["signature" if control == "invalid" else "scope"] = control
    row = run_case(spec, tmp_path / "case")
    assert row["with_context"]["verdict"] == "unknown"
    assert row["with_context"]["reason"] == "EXECUTION_POLICY_REQUIRED"
    assert row["with_context"]["trusted_evidence"] == []
    if control == "invalid":
        assert row["provenance"]["observations"] == []
        assert row["provenance"]["observation_intake"]["state"] == "rejected"
        assert "signature" not in row["provenance"]["observation_intake"]["request"]
    else:
        assert row["provenance"]["observations"][0]["matched_sessions"] == 0


@pytest.mark.parametrize("mode", ["missing", "expired", "revoked", "future"])
def test_unusable_approval_does_not_produce_normal_or_threat_claim(tmp_path, mode):
    spec = _spec()
    spec["approval"]["mode"] = mode
    row = run_case(spec, tmp_path / "case")
    assert row["with_context"]["verdict"] == "unknown"
    assert row["with_context"]["trusted_evidence"] == []


def test_missing_execution_evidence_does_not_fabricate_prior_approval_consumption(tmp_path):
    spec = _spec()
    prior = deepcopy(spec["target"])
    prior["capture_id"], prior["session_id"] = _identifier("c"), _identifier("s")
    prior["activity"]["original_group_id"] = _identifier("g")
    connection = _identifier("k")
    for event in prior["activity"]["events"]:
        event["id"], event["connection_id"] = _identifier("e"), connection
        event["timestamp"] = (datetime.fromisoformat(spec["base_time"]) + timedelta(seconds=5)).isoformat()
    spec["prior_use"], spec["approval"]["mode"] = prior, "exhausted"
    row = run_case(spec, tmp_path / "case")
    assert row["with_context"]["verdict"] == "unknown"
    earlier = [record for record in row["provenance"]["context_records"] if record["kind"] == "evaluation"]
    assert len(earlier) == 1
    assert earlier[0]["payload"]["verdict"] == "unknown"
    assert earlier[0]["payload"]["reason"] == "EXECUTION_POLICY_REQUIRED"
    assert earlier[0]["payload"]["approval_id"] is None
    assert earlier[0]["payload"]["capture_id"] == prior["capture_id"]


def test_manual_isolation_is_not_a_compromise_claim(tmp_path):
    spec = _spec()
    spec["session_revoke"] = True
    row = run_case(spec, tmp_path / "case")
    assert row["with_context"]["verdict"] == "unknown"
    assert row["with_context"]["trusted_evidence"] == []


def test_scoring_fields_are_rejected_before_runtime(tmp_path):
    spec = _spec()
    spec["expected_label"] = "normal"
    with pytest.raises(ValueError):
        run_case(spec, tmp_path / "case")
    assert not (tmp_path / "case").exists()
