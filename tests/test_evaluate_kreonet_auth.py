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
        {**base, "trace_id": "eight", "http_status": 302},
        {
            **base,
            "trace_id": "eight",
            "timestamp": "2026-03-20T01:02:04Z",
            "module": "request",
            "http_status": 200,
            "user_id": "synthetic subject",
            "client_ip": "192.0.2.10",
            "user_agent": "synthetic client A",
        },
        {
            **base,
            "trace_id": "eight",
            "timestamp": "2026-03-20T01:02:05Z",
            "module": "request",
            "http_status": 200,
            "user_id": "synthetic subject",
            "client_ip": "192.0.2.20",
            "user_agent": "synthetic client B",
        },
        {**base, "trace_id": "nine", "module": "rp", "http_status": 302},
        {
            **base,
            "trace_id": "nine",
            "module": "op",
            "http_status": 200,
            "timestamp": "2026-03-20T01:02:04Z",
            "user_id": "",
            "ref": "synthetic op ref",
        },
        {
            **base,
            "trace_id": "nine",
            "module": "op",
            "http_status": 200,
            "timestamp": "2026-03-20T01:02:05Z",
            "user_id": " ",
            "ref": "synthetic op ref",
        },
    ]
    events += [
        {**base, "trace_id": "ten", "module": "rp", "http_status": 302},
        {
            **base,
            "trace_id": "ten",
            "module": "op",
            "http_status": 200,
            "http_method": "GET",
            "timestamp": "2026-03-20T01:02:04Z",
            "ref": "synthetic handoff ref",
            "client_ip": "192.0.2.30",
            "user_agent": "synthetic client A",
        },
        {
            **base,
            "trace_id": "ten",
            "module": "auth",
            "http_status": 200,
            "timestamp": "2026-03-20T01:02:05Z",
            "user_id": "synthetic subject",
            "client_ip": "192.0.2.30",
            "user_agent": "synthetic client A",
        },
        {
            **base,
            "trace_id": "ten",
            "module": "op",
            "http_status": 200,
            "timestamp": "2026-03-20T01:02:06Z",
            "user_id": "synthetic subject",
            "client_ip": "192.0.2.40",
            "ref": "synthetic handoff ref",
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
                    "client_ip": event.get("client_ip", label),
                    "user_id": event.get("user_id", label),
                    "ref": event.get("ref", label),
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
        evaluation.capture(output, source, include_op_handoff_flow=True)
        packet = output / "predictions.json"
        for raw_value in (
            b"synthetic client",
            b"synthetic subject",
            b"192.0.2.10",
            b"synthetic op ref",
        ):
            assert raw_value not in packet.read_bytes()
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
    linked = snapshots[0][hashlib.sha256(b"eight").hexdigest()]
    assert linked["previous_sequence_flow_prediction"] is False
    assert linked["linked_flow_signals"] == ["same_subject_client_changed_between_posts"]
    assert linked["prediction"] is True
    unattributed = snapshots[0][hashlib.sha256(b"nine").hexdigest()]
    assert unattributed["previous_linked_flow_prediction"] is False
    assert unattributed["unattributed_op_flow_signals"] == [
        "consecutive_op_posts_for_same_client_without_subject"
    ]
    assert unattributed["prediction"] is True
    handoff = snapshots[0][hashlib.sha256(b"ten").hexdigest()]
    assert handoff["previous_unattributed_op_prediction"] is False
    assert handoff["op_handoff_signals"] == [
        "client_observation_discontinuity_at_bound_op_submission"
    ]
    assert handoff["prediction"] is True


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


REQUEST_POST = ("request", "POST", 200)
LDAP_POST = ("ldap", "POST", 200)
CLIENT_A = ("subject", "192.0.2.10", "agent A")
CLIENT_B = ("subject", "192.0.2.20", "agent B")


@pytest.mark.parametrize(
    "first, second, expected",
    [
        (
            (REQUEST_POST, CLIENT_A),
            (REQUEST_POST, CLIENT_B),
            ["same_subject_client_changed_between_posts"],
        ),
        ((REQUEST_POST, CLIENT_A), (REQUEST_POST, ("other", *CLIENT_B[1:])), []),
        ((REQUEST_POST, CLIENT_A), (REQUEST_POST, ("", *CLIENT_B[1:])), []),
        ((REQUEST_POST, CLIENT_A), (REQUEST_POST, (*CLIENT_B[:2], CLIENT_A[2])), []),
        ((REQUEST_POST, CLIENT_A), (REQUEST_POST, (CLIENT_B[0], "", CLIENT_B[2])), []),
        ((LDAP_POST, CLIENT_A), (LDAP_POST, CLIENT_A), ["same_client_rapid_ldap_posts"]),
        ((LDAP_POST, CLIENT_A), (LDAP_POST, CLIENT_B), []),
    ],
)
def test_linked_flow_requires_correlated_observations(first, second, expected):
    start = datetime(2026, 3, 20, tzinfo=UTC)
    events = [
        (start + timedelta(seconds=3), *second),
        (start, *first),
        (start - timedelta(seconds=1), RP_REDIRECT, ("", "", "")),
    ]
    statuses = Counter(event[1][-1] for event in events)
    assert evaluation.linked_flow_signals(statuses, events) == expected


def test_linked_flow_uses_strict_order_adjacency_and_ldap_interval():
    start = datetime(2026, 3, 20, tzinfo=UTC)
    first = (start, LDAP_POST, CLIENT_A)
    last = (start + timedelta(seconds=3), LDAP_POST, CLIENT_A)
    redirect = (start + timedelta(seconds=1), RP_REDIRECT, ("", "", ""))
    statuses = Counter([200, 302])
    assert evaluation.linked_flow_signals(statuses, [first, redirect, last]) == []
    assert evaluation.linked_flow_signals(statuses, [first, first]) == []
    late = (start + timedelta(seconds=3, milliseconds=1), LDAP_POST, CLIENT_A)
    assert evaluation.linked_flow_signals(statuses, [first, late]) == []
    assert evaluation.linked_flow_signals(Counter([200, 302, 401]), [first, last]) == []


def test_unattributed_op_requires_consecutive_same_client_and_no_op_subject():
    start = datetime(2026, 3, 20, tzinfo=UTC)
    first = (start, OP_SUBMIT, "", "client")
    second = (start + timedelta(seconds=2), OP_SUBMIT, "", "client")
    middle = start + timedelta(seconds=1)
    late_subject = (start + timedelta(seconds=3), OP_LOOKUP, "observed subject", "")
    redirect = (start - timedelta(seconds=1), RP_REDIRECT, "", "")
    statuses = Counter([200, 302])
    classify = evaluation.unattributed_op_signals
    assert classify(statuses, [second, redirect, first]) == [
        "consecutive_op_posts_for_same_client_without_subject"
    ]
    assert classify(statuses, [first, second, redirect, late_subject]) == []
    assert classify(statuses, [first, second, (middle, RP_REDIRECT, "", "")]) == []
    assert classify(statuses, [first, (second[0], OP_SUBMIT, "", "other"), redirect]) == []
    assert classify(statuses, [first, (second[0], OP_SUBMIT, "", ""), redirect]) == []
    assert classify(statuses, [first, first, redirect]) == []
    assert classify(Counter([200, 302, 401]), [first, second, redirect]) == []


def test_op_handoff_requires_observed_discontinuity_on_correlated_consecutive_stages():
    start = datetime(2026, 3, 20, tzinfo=UTC)
    lookup = (start, OP_LOOKUP, ("", "192.0.2.30", "browser", "client ref"))
    auth = (
        start + timedelta(seconds=1),
        ("auth", "POST", 200),
        ("subject", "192.0.2.30", "browser", ""),
    )
    submit = (
        start + timedelta(seconds=2),
        OP_SUBMIT,
        ("subject", "192.0.2.40", "", "client ref"),
    )
    classify = evaluation.op_handoff_signals
    statuses = Counter({200: 3, 302: 1})
    assert classify(statuses, [submit, auth, lookup]) == [
        "client_observation_discontinuity_at_bound_op_submission"
    ]
    for context in (
        ("subject", "192.0.2.40", "browser", "client ref"),
        ("subject", "192.0.2.30", "", "client ref"),
        ("subject", "", "", "client ref"),
        ("other", "192.0.2.40", "", "client ref"),
        ("subject", "192.0.2.40", "", "other client"),
    ):
        assert classify(statuses, [lookup, auth, (*submit[:2], context)]) == []
    assert classify(statuses, [lookup, auth, (auth[0], *submit[1:])]) == []
    unrelated = (start + timedelta(seconds=1, milliseconds=500), RP_REDIRECT, ("", "", "", ""))
    assert classify(statuses, [lookup, auth, unrelated, submit]) == []
    assert classify(Counter({200: 3, 302: 1, 401: 1}), [lookup, auth, submit]) == []
