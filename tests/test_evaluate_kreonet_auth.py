import hashlib
import json
from collections import Counter

import pytest

from scripts import evaluate_kreonet_auth as evaluation


def test_auth_flow_uses_only_observation_fields(monkeypatch, tmp_path):
    base = {"timestamp": "2026-03-20T01:02:03Z", "http_method": "POST", "module": "idp"}
    events = [
        {**base, "trace_id": "one", "http_status": 401},
        {**base, "trace_id": "one", "http_status": 400},
        {**base, "trace_id": "two", "http_status": 200},
        {**base, "trace_id": "three", "http_status": 302},
        {**base, "trace_id": "three", "http_status": 400},
    ]
    snapshots = []
    for label in ("attack", "benign"):
        source = tmp_path / f"{label}.jsonl"
        raw = b"".join(
            json.dumps(
                {
                    **event,
                    "label": label,
                    "category": label,
                    "event_type": label,
                    "message": label,
                    "payload": {"classification": label},
                }
            ).encode()
            + b"\n"
            for event in events
        )
        source.write_bytes(raw)
        monkeypatch.setattr(evaluation, "SOURCE_HASH", hashlib.sha256(raw).hexdigest())
        monkeypatch.setattr(evaluation, "SOURCE_SIZE", len(raw))
        output = tmp_path / label
        evaluation.capture(output, source, include_protocol_flow=True)
        snapshots.append(evaluation.read(output / "predictions.json")["prediction_rows"])

    assert snapshots[0] == snapshots[1]
    assert snapshots[0][hashlib.sha256(b"one").hexdigest()]["prediction"] is True
    assert snapshots[0][hashlib.sha256(b"two").hexdigest()]["prediction"] is False
    projected = snapshots[0][hashlib.sha256(b"three").hexdigest()]
    assert projected["previous_auth_flow_prediction"] is False
    assert projected["prediction"] is True


@pytest.mark.parametrize(
    "responses, expected",
    [
        ([(302, "GET", "rp"), (404, "GET", "op")], False),
        ([(304, "GET", "rp"), (400, "GET", "op")], False),
        ([(401, "GET", "op"), (500, "POST", "op")], False),
        ([(401, "GET", "op"), (500, "POST", "idp")], True),
        ([(401, "GET", "op"), (403, "GET", "idp")], True),
        ([(401, "GET", "op"), (403, "GET", "request")], False),
        ([(401, "GET", "idp"), (302, "GET", "rp"), (404, "GET", "op")], True),
    ],
)
def test_protocol_flow_requires_specific_correlated_evidence(responses, expected):
    statuses = Counter(code for code, _, _ in responses)
    assert bool(evaluation.protocol_flow_signals(statuses, responses)) is expected
