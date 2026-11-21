import hashlib
import json
from collections import Counter
from datetime import UTC, datetime, timedelta

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
        {**base, "trace_id": "four", "http_status": 200, "user_agent": "synthetic client A"},
        {**base, "trace_id": "four", "http_status": 302, "user_agent": "synthetic client B"},
        {**base, "trace_id": "five", "http_status": 200},
        {**base, "trace_id": "five", "http_status": 200},
        {**base, "trace_id": "five", "http_status": 302, "module": "sp"},
        {
            **base,
            "trace_id": "six",
            "http_status": 200,
            "http_method": "GET",
            "user_agent": "synthetic client A",
        },
        {
            **base,
            "trace_id": "six",
            "http_status": 302,
            "module": "sp",
            "user_agent": "synthetic client B",
        },
        {**base, "trace_id": "six", "http_status": 200, "http_method": "GET", "user_agent": " "},
        {**base, "trace_id": "six", "http_status": 200, "user_agent": "synthetic client C"},
        {**base, "trace_id": "seven", "http_status": 200, "module": "op"},
        {
            **base,
            "trace_id": "seven",
            "http_status": 302,
            "module": "rp",
            "http_method": "GET",
            "timestamp": "2026-03-20T01:02:04Z",
        },
        {
            **base,
            "trace_id": "seven",
            "http_status": 302,
            "module": "rp",
            "http_method": "GET",
            "timestamp": "2026-03-20T01:02:05Z",
        },
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
                    "subcategory": label,
                    "event_type": label,
                    "uri": f"/{label}",
                    "client_ip": label,
                    "user_id": label,
                    "ref": label,
                    "duration_ms": len(label),
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
        evaluation.capture(output, source, include_sequence_flow=True)
        packet = output / "predictions.json"
        assert b"synthetic client" not in packet.read_bytes()
        snapshots.append(evaluation.read(packet)["prediction_rows"])

    assert snapshots[0] == snapshots[1]
    assert snapshots[0][hashlib.sha256(b"one").hexdigest()]["prediction"] is True
    assert snapshots[0][hashlib.sha256(b"two").hexdigest()]["prediction"] is False
    projected = snapshots[0][hashlib.sha256(b"three").hexdigest()]
    assert projected["previous_auth_flow_prediction"] is False
    assert projected["prediction"] is True
    switched = snapshots[0][hashlib.sha256(b"four").hexdigest()]
    assert switched["previous_protocol_flow_prediction"] is False
    assert switched["success_flow_signals"] == ["client_agent_changed_at_same_protocol_stage"]
    assert switched["prediction"] is True
    repeated = snapshots[0][hashlib.sha256(b"five").hexdigest()]
    assert repeated["success_flow_signals"] == ["repeated_idp_post_with_sp_post"]
    assert repeated["prediction"] is True
    assert snapshots[0][hashlib.sha256(b"six").hexdigest()]["prediction"] is False
    ordered = snapshots[0][hashlib.sha256(b"seven").hexdigest()]
    assert ordered["previous_success_flow_prediction"] is False
    assert ordered["sequence_flow_signals"] == ["consecutive_rp_redirects_at_end"]
    assert ordered["prediction"] is True


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


def test_success_flow_requires_both_statuses_and_no_other_response():
    counts = Counter({("idp", "POST"): 2, ("sp", "POST"): 1})
    agents = {("idp", "POST"): {"a", "b"}}
    assert evaluation.success_flow_signals(Counter([200]), counts, agents) == []
    assert evaluation.success_flow_signals(Counter([200, 302, 401]), counts, agents) == []
    idp_only = Counter({("idp", "POST"): 2})
    assert evaluation.success_flow_signals(Counter([200, 302]), idp_only, {}) == []


RP_REDIRECT = ("rp", "GET", 302)
OP_LOOKUP = ("op", "GET", 200)
OP_SUBMIT = ("op", "POST", 200)
SP_REDIRECT = ("sp", "GET", 302)
IDP_READ = ("idp", "GET", 200)
IDP_SUBMIT = ("idp", "POST", 200)


@pytest.mark.parametrize(
    "observed, expected",
    [
        (
            [(6, OP_SUBMIT), (0, RP_REDIRECT), (1, OP_LOOKUP)],
            ["delayed_op_submission_after_rp_redirect"],
        ),
        ([(0, RP_REDIRECT), (1, OP_LOOKUP), (5, OP_SUBMIT)], []),
        ([(0, RP_REDIRECT), (0, OP_LOOKUP), (6, OP_SUBMIT)], []),
        ([(0, RP_REDIRECT), (1, OP_SUBMIT), (6, OP_LOOKUP)], []),
        ([(0, OP_LOOKUP), (1, RP_REDIRECT), (1, RP_REDIRECT)], []),
        ([(0, OP_LOOKUP), (1, RP_REDIRECT), (2, RP_REDIRECT), (3, OP_LOOKUP)], []),
        (
            [(0, SP_REDIRECT), (1, IDP_READ), (2, IDP_READ), (3, IDP_READ)],
            ["repeated_idp_reads_after_sp_redirect_at_end"],
        ),
        ([(0, SP_REDIRECT), (1, IDP_READ), (2, IDP_READ), (3, IDP_READ), (4, IDP_SUBMIT)], []),
    ],
)
def test_sequence_flow_checks_relative_order_bounds_and_terminal_stages(observed, expected):
    start = datetime(2026, 3, 20, tzinfo=UTC)
    events = [(start + timedelta(seconds=offset), *stage) for offset, stage in observed]
    statuses = Counter(event[-1] for event in events)
    assert evaluation.sequence_flow_signals(statuses, events) == expected
    assert evaluation.sequence_flow_signals(statuses + Counter({401: 1}), events) == []
