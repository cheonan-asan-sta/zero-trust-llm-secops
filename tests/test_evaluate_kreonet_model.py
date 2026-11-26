import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from scripts import evaluate_kreonet_model as evaluation


def test_model_observations_ignore_evaluation_labels_and_raw_feature_values(monkeypatch, tmp_path):
    start = datetime(2026, 3, 16, tzinfo=UTC)
    trace = hashlib.sha256(b"source-trace").hexdigest()
    members = {trace: ("holdout", False)}
    projections = []
    for value in ("first raw identity", "second raw identity"):
        rows = [
            {
                "trace_id": "source-trace",
                "timestamp": (start + timedelta(seconds=i)).isoformat(),
                "module": "auth",
                "http_method": "POST",
                "http_status": status,
                "duration_ms": 32,
                "user_id": value,
                "client_ip": value,
                "user_agent": value,
                "ref_id": value,
                "event_type": value,
                "category": value,
                "payload": {"classified_as": value},
            }
            for i, status in enumerate((200, 401))
        ]
        contents = b"\n".join(json.dumps(row).encode() for row in rows)
        source = tmp_path / "source.jsonl"
        source.write_bytes(contents)
        monkeypatch.setattr(evaluation, "SOURCE_SIZE", len(contents))
        monkeypatch.setattr(evaluation, "SOURCE_HASH", hashlib.sha256(contents).hexdigest())
        events, labels = evaluation.read_observations(source, members)
        assert labels == {}
        features = evaluation.project(events[trace], "timing")
        assert all(value not in key for key in features)
        projections.append(features)
    assert projections[0] == projections[1]
    assert projections[0]["edge_context|auth:POST:200|auth:POST:401|user_id|same"] == 1


def test_model_calibration_respects_false_positive_buffer():
    np = pytest.importorskip("numpy")
    start = datetime(2026, 3, 1, tzinfo=UTC)
    benign_keys = [f"normal-{i}" for i in range(25)]
    keys = [*benign_keys, "high", "lower"]
    events = {key: [(start, ("auth", "POST", 200), ("",) * 5, None)] for key in keys}
    labels = {**dict.fromkeys(benign_keys, "benign"), "high": "attack", "lower": "attack"}
    probabilities = np.array([0.05] * 23 + [0.80, 0.85, 0.99, 0.70])
    guard, cutoffs, target = evaluation.calibrate(
        events, keys, probabilities, labels, {"attack": 25, "benign": 0}
    )
    assert guard == 0.85
    assert cutoffs == {}
    assert sum(probability > target for probability in probabilities[:25]) <= 1
    assert probabilities[25] > target > probabilities[26]
