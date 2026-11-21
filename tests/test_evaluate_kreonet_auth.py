import hashlib
import json

from scripts import evaluate_kreonet_auth as evaluation


def test_auth_flow_uses_only_observation_fields(monkeypatch, tmp_path):
    base = {"timestamp": "2026-03-20T01:02:03Z", "http_method": "POST", "module": "idp"}
    events = [
        {**base, "trace_id": "one", "http_status": 401},
        {**base, "trace_id": "one", "http_status": 400},
        {**base, "trace_id": "two", "http_status": 200},
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
        evaluation.capture(output, source, include_auth_flow=True)
        snapshots.append(evaluation.read(output / "predictions.json")["prediction_rows"])

    assert snapshots[0] == snapshots[1]
    assert snapshots[0][hashlib.sha256(b"one").hexdigest()]["prediction"] is True
    assert snapshots[0][hashlib.sha256(b"two").hexdigest()]["prediction"] is False
