"""Measure the existing local credential rule on a fixed public IAM time window."""

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from urllib.request import urlopen

from app.analyzers.rule_based import RuleBasedAnalyzer
from app.models import SecurityEvent
from scripts.compare_llm_grounded import compare_rows
from scripts.evaluate_llm_grounded import metrics, prediction
from scripts.evaluate_local_remote_holdout import fingerprint, read, write

COMMIT = "5fd5cae2001a6b67cafb952709db37e366cfa276"
SOURCE = f"https://raw.githubusercontent.com/KREONET/auth-anomaly-dataset/{COMMIT}/iam_anomaly_2026.jsonl"
SOURCE_SIZE = 91592665
SOURCE_HASH = "445f69377a2e12b4203a68f15cd9a4013fbc7e0ef21c19843969f671b1334a30"
START = datetime(2026, 3, 16, tzinfo=UTC)
STOP = datetime(2026, 3, 30, tzinfo=UTC)
WINDOWS = {
    "development": (datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 3, 1, tzinfo=UTC)),
    "calibration": (datetime(2026, 3, 1, tzinfo=UTC), START),
    "holdout": (START, STOP),
}
PROTOCOL_MODULES = {"op", "rp", "idp", "sp"}
PROTOCOL_STATUSES = {400, 401, 403, 404, 500}


def auth_flow_signals(statuses, *, post_denied):
    signals = {
        "malformed_request_and_unauthorized": statuses[400] > 0 and statuses[401] > 0,
        "denied_post_request": post_denied,
        "rate_limit_response": statuses[429] > 0,
    }
    return [name for name, seen in signals.items() if seen]


def protocol_flow_signals(statuses, stages):
    redirected = any(statuses[code] > 0 for code in (301, 302, 303, 307, 308))
    protocol_statuses = {code for code, _, module in stages if module in PROTOCOL_MODULES}
    unauthorized_modules = {module for code, _, module in stages if code == 401 and module}
    protocol_server_errors = {
        module for code, _, module in stages if code == 500 and module in PROTOCOL_MODULES
    }
    signals = {
        "protocol_bad_request_with_redirect": redirected and 400 in protocol_statuses,
        "protocol_get_denied_with_unauthorized": statuses[401] > 0
        and any(
            code == 403 and method == "GET" and module in PROTOCOL_MODULES
            for code, method, module in stages
        ),
        "protocol_not_found_with_unauthorized_and_redirect": (
            redirected and statuses[401] > 0 and 404 in protocol_statuses
        ),
        "protocol_server_error_and_unauthorized_at_distinct_components": any(
            server != unauthorized
            for server in protocol_server_errors
            for unauthorized in unauthorized_modules
        ),
    }
    return [name for name, seen in signals.items() if seen]


def success_flow_signals(statuses, request_counts, stage_user_agents):
    if statuses.keys() != {200, 302}:
        return []
    signals = {
        "repeated_idp_post_with_sp_post": (
            request_counts["idp", "POST"] >= 2 and request_counts["sp", "POST"] > 0
        ),
        "client_agent_changed_at_same_protocol_stage": any(
            len(agents) > 1 for agents in stage_user_agents.values()
        ),
    }
    return [name for name, seen in signals.items() if seen]


def sequence_flow_signals(statuses, events):
    if statuses.keys() != {200, 302}:
        return []
    ordered = sorted(events, key=lambda event: event[0])
    federation = [event for event in ordered if event[1] in PROTOCOL_MODULES]
    signals = []
    rp_redirect = ("rp", "GET", 302)
    end = federation[-2:]
    if [event[1:] for event in end] == [rp_redirect, rp_redirect] and end[0][0] < end[1][0]:
        signals.append("consecutive_rp_redirects_at_end")

    end = federation[-4:]
    saml_reads = [
        ("sp", "GET", 302),
        ("idp", "GET", 200),
        ("idp", "GET", 200),
        ("idp", "GET", 200),
    ]
    if [event[1:] for event in end] == saml_reads and all(
        first[0] < second[0] for first, second in pairwise(end)
    ):
        signals.append("repeated_idp_reads_after_sp_redirect_at_end")

    for redirect, lookup, submit in zip(ordered, ordered[1:], ordered[2:]):
        if (
            redirect[1:] == rp_redirect
            and lookup[1:] == ("op", "GET", 200)
            and submit[1:] == ("op", "POST", 200)
            and redirect[0] < lookup[0] < submit[0]
            and (submit[0] - redirect[0]).total_seconds() > 5
        ):
            signals.append("delayed_op_submission_after_rp_redirect")
            break
    return signals


def nonblank_text(value):
    return value.strip() if isinstance(value, str) else ""


def linked_flow_signals(statuses, events):
    if statuses.keys() != {200, 302}:
        return []
    ordered = sorted(events, key=lambda event: event[0])
    signals = set()
    for previous, current in pairwise(ordered):
        previous_time, previous_stage, previous_binding = previous
        current_time, current_stage, current_binding = current
        if previous_stage != current_stage or current_time <= previous_time:
            continue
        previous_user, previous_ip, previous_agent = previous_binding
        user, ip, agent = current_binding
        if not all((previous_ip, previous_agent, ip, agent)):
            continue
        if (
            current_stage == ("request", "POST", 200)
            and user
            and user == previous_user
            and ip != previous_ip
            and agent != previous_agent
        ):
            signals.add("same_subject_client_changed_between_posts")
        if (
            current_stage == ("ldap", "POST", 200)
            and ip == previous_ip
            and agent == previous_agent
            and (current_time - previous_time).total_seconds() <= 3
        ):
            signals.add("same_client_rapid_ldap_posts")
    return sorted(signals)


def unattributed_op_signals(statuses, events):
    if statuses.keys() != {200, 302}:
        return []
    if any(stage[0] == "op" and user for _, stage, user, _ in events):
        return []
    ordered = sorted(events, key=lambda event: event[0])
    op_post = ("op", "POST", 200)
    for previous, current in pairwise(ordered):
        previous_time, previous_stage, _, previous_ref = previous
        current_time, current_stage, _, current_ref = current
        if (
            previous_stage == current_stage == op_post
            and previous_time < current_time
            and current_ref
            and previous_ref == current_ref
        ):
            return ["consecutive_op_posts_for_same_client_without_subject"]
    return []


OP_AUTH_STAGES = (("op", "GET", 200), ("auth", "POST", 200), ("op", "POST", 200))


def op_client_discontinuity(lookup, authentication, submission):
    _, initial_ip, initial_agent, _ = lookup
    _, auth_ip, auth_agent, _ = authentication
    _, submit_ip, submit_agent, _ = submission
    return (
        initial_ip
        and initial_ip == auth_ip
        and initial_agent
        and initial_agent == auth_agent
        and submit_ip
        and submit_ip != auth_ip
        and not submit_agent
    )


def op_handoff_signals(statuses, events):
    if statuses.keys() != {200, 302}:
        return []
    ordered = sorted(events, key=lambda event: event[0])
    for lookup, authentication, submission in zip(ordered, ordered[1:], ordered[2:]):
        if (lookup[1], authentication[1], submission[1]) != OP_AUTH_STAGES:
            continue
        if not lookup[0] < authentication[0] < submission[0]:
            continue
        _, _, _, initial_ref = lookup[2]
        auth_user = authentication[2][0]
        submit_user, _, _, submit_ref = submission[2]
        if (
            auth_user
            and auth_user == submit_user
            and initial_ref
            and initial_ref == submit_ref
            and op_client_discontinuity(lookup[2], authentication[2], submission[2])
        ):
            return ["client_observation_discontinuity_at_bound_op_submission"]
    return []


SAML_AUTH_STAGES = (
    ("idp", "GET", 200),
    ("auth", "POST", 200),
    ("idp", "POST", 200),
    ("sp", "POST", 302),
)


def saml_handoff_signals(statuses, events):
    if statuses.keys() != {200, 302}:
        return []
    ordered = sorted(events, key=lambda event: event[0])
    for lookup, auth, assertion, returned in zip(ordered, ordered[1:], ordered[2:], ordered[3:]):
        stages = (lookup[1], auth[1], assertion[1], returned[1])
        if stages != SAML_AUTH_STAGES or not lookup[0] < auth[0] < assertion[0] < returned[0]:
            continue
        _, lookup_ip, lookup_agent, lookup_ref = lookup[2]
        auth_user, auth_ip, auth_agent, auth_ref = auth[2]
        assertion_user, assertion_ip, assertion_agent, assertion_ref = assertion[2]
        return_user, return_ip, return_agent, return_ref = returned[2]
        if (
            auth_user
            and auth_user == assertion_user == return_user
            and lookup_ref
            and lookup_ref == auth_ref == assertion_ref == return_ref
            and lookup_ip
            and lookup_ip == auth_ip == assertion_ip == return_ip
            and lookup_agent
            and lookup_agent == auth_agent == return_agent
            and not assertion_agent
        ):
            return ["saml_idp_post_missing_agent_between_bound_client_observations"]
    return []


LDAP_AUTH_STAGES = (("op", "GET", 200), ("ldap", "POST", 200), ("op", "POST", 200))


def ldap_handoff_signals(statuses, events):
    if statuses.keys() != {200, 302}:
        return []
    ordered = sorted(events, key=lambda event: event[0])
    for lookup, directory, submission in zip(ordered, ordered[1:], ordered[2:]):
        if (lookup[1], directory[1], submission[1]) != LDAP_AUTH_STAGES:
            continue
        if not lookup[0] < directory[0] < submission[0]:
            continue
        _, lookup_ip, lookup_agent, lookup_ref = lookup[2]
        _, directory_ip, directory_agent, _ = directory[2]
        _, submit_ip, submit_agent, submit_ref = submission[2]
        duration = directory[3]
        if (
            type(duration) is int
            and 0 < duration <= 50
            and lookup_ref
            and lookup_ref == submit_ref
            and lookup_ip
            and lookup_ip == directory_ip
            and lookup_agent
            and lookup_agent == directory_agent
            and submit_ip
            and submit_ip != directory_ip
            and not submit_agent
        ):
            return ["short_ldap_processing_with_bound_op_client_discontinuity"]
    return []


def op_entity_handoff_signals(statuses, events):
    if statuses.keys() != {200, 302}:
        return []
    ordered = sorted(events, key=lambda event: event[0])
    for lookup, authentication, submission in zip(ordered, ordered[1:], ordered[2:]):
        if (lookup[1], authentication[1], submission[1]) != OP_AUTH_STAGES:
            continue
        if not lookup[0] < authentication[0] < submission[0]:
            continue
        if (
            lookup[4]
            and lookup[4] == authentication[4] == submission[4]
            and all(not row[2][0] and not row[2][3] for row in (lookup, authentication, submission))
            and op_client_discontinuity(lookup[2], authentication[2], submission[2])
        ):
            return ["entity_linked_op_client_discontinuity_with_unobserved_subject_and_client_ref"]
    return []


def auth_recovery_signals(statuses, events):
    if not statuses[302]:
        return []
    ordered = sorted(events, key=lambda event: event[0])
    signals = set()
    provider_time = None
    for when, (module, method, status), _, _ in ordered:
        if provider_time is None and module in {"op", "idp"} and method == "GET" and status == 200:
            provider_time = when
        if (
            provider_time is not None
            and provider_time < when
            and (module, method) == ("auth", "POST")
            and status in {400, 409}
        ):
            signals.add("auth_request_rejected_after_provider_lookup")
    for previous, current in pairwise(ordered):
        previous_time, previous_stage, previous_subject, previous_agent = previous
        current_time, current_stage, current_subject, current_agent = current
        if (
            previous_stage == ("auth", "POST", 401)
            and current_stage in {("auth", "POST", 200), ("auth", "POST", 401)}
            and previous_time < current_time
            and previous_subject
            and previous_subject == current_subject
            and previous_agent
            and current_agent
            and previous_agent != current_agent
        ):
            signals.add("same_subject_client_agent_changed_on_auth_retry")
    return sorted(signals)


def capture(
    output,
    source=None,
    *,
    cohort="holdout",
    include_auth_flow=False,
    include_protocol_flow=False,
    include_success_flow=False,
    include_sequence_flow=False,
    include_linked_flow=False,
    include_unattributed_op_flow=False,
    include_op_handoff_flow=False,
    include_saml_handoff_flow=False,
    include_ldap_handoff_flow=False,
    include_op_entity_handoff_flow=False,
    include_auth_recovery_flow=False,
):
    include_op_entity_handoff_flow = include_op_entity_handoff_flow or include_auth_recovery_flow
    include_ldap_handoff_flow = include_ldap_handoff_flow or include_op_entity_handoff_flow
    include_saml_handoff_flow = include_saml_handoff_flow or include_ldap_handoff_flow
    include_op_handoff_flow = include_op_handoff_flow or include_saml_handoff_flow
    include_unattributed_op_flow = include_unattributed_op_flow or include_op_handoff_flow
    include_linked_flow = include_linked_flow or include_unattributed_op_flow
    include_sequence_flow = include_sequence_flow or include_linked_flow
    include_success_flow = include_success_flow or include_sequence_flow
    include_protocol_flow = include_protocol_flow or include_success_flow
    include_auth_flow = include_auth_flow or include_protocol_flow
    output.mkdir(exist_ok=True)
    plan = output / "plan.json"
    start, stop = WINDOWS[cohort]
    expected_plan = {
        "source": SOURCE,
        "source_sha256": SOURCE_HASH,
        "holdout_start": start.isoformat(),
        "holdout_stop_exclusive": stop.isoformat(),
        "timestamp_without_offset": "UTC",
        "metric_unit": "trace_id_entirely_in_window",
        "input_fields": ["trace_id for grouping", "timestamp for window", "http_status"],
        "mapping": "HTTP 401 rows per trace as a proxy for failed_attempts; no inferred MFA or approvals",
        "rule": "existing RuleBasedAnalyzer on LOGIN",
        "score_labels": ["attack", "benign"],
    }
    if include_auth_flow:
        expected_plan.update(
            {
                "cohort": cohort,
                "input_fields": [*expected_plan["input_fields"], "http_method"],
                "candidate": "baseline OR auth flow signals",
                "auth_flow_signals": [
                    "HTTP 400 and 401 in one flow",
                    "HTTP 403 on POST",
                    "HTTP 429",
                ],
            }
        )
    if include_protocol_flow:
        expected_plan["input_fields"].append("module")
        expected_plan["candidate"] = (
            "previous authentication flow detector OR protocol flow signals"
        )
        expected_plan["protocol_flow_signals"] = [
            "HTTP 400 at OP/RP/IdP/SP and a redirect",
            "HTTP 403 on GET at OP/RP/IdP/SP and HTTP 401",
            "HTTP 404 at OP/RP/IdP/SP with a redirect and HTTP 401",
            "HTTP 500 at OP/RP/IdP/SP and HTTP 401 at a different component",
        ]
    if include_success_flow:
        expected_plan["input_fields"].append("nonblank user_agent equality within a protocol stage")
        expected_plan["candidate"] = "previous protocol flow detector OR success flow signals"
        expected_plan["success_flow_signals"] = [
            "only 200 and 302: repeated POST at IdP with POST at SP in the same trace",
            "only 200 and 302: user agent changes within a protocol component and HTTP method",
        ]
    if include_sequence_flow:
        expected_plan["input_fields"].append("relative timestamp order and elapsed seconds")
        expected_plan["candidate"] = "previous success flow detector OR sequence flow signals"
        expected_plan["sequence_flow_signals"] = [
            "only 200 and 302: final two federation stages are RP GET 302",
            "only 200 and 302: final four federation stages are SP GET 302 and three IdP GET 200",
            "only 200 and 302: RP GET 302, OP GET 200, OP POST 200 over more than five seconds",
        ]
        expected_plan["sequence_order"] = "strictly increasing timestamps within matched stages"
    if include_linked_flow:
        expected_plan["input_fields"].append(
            "nonblank user_id, client_ip and user_agent equality for adjacent POST 200 rows"
        )
        expected_plan["candidate"] = "previous sequence flow detector OR linked flow signals"
        expected_plan["linked_flow_signals"] = [
            "only 200 and 302: adjacent request POST 200 has same user and changed IP and agent",
            "only 200 and 302: adjacent LDAP POST 200 has same IP and agent within three seconds",
        ]
    if include_unattributed_op_flow:
        expected_plan["input_fields"].append(
            "OP user_id presence and nonblank ref equality on adjacent OP POST 200 rows"
        )
        expected_plan["candidate"] = "previous linked flow detector OR unattributed OP flow signals"
        expected_plan["unattributed_op_flow_signals"] = [
            "adjacent OP POST 200 with equal nonblank ref, strict order, and no OP user_id"
        ]
    if include_op_handoff_flow:
        expected_plan["input_fields"].append(
            "user_id, client_ip, user_agent and ref presence/equality across OP and auth stages"
        )
        expected_plan["candidate"] = "previous unattributed OP detector OR OP handoff signal"
        expected_plan["op_handoff_signals"] = [
            "OP GET 200, auth POST 200, OP POST 200 in strict order with stable user and client ref",
            "IP and agent stable before OP POST, then IP changes and agent is absent",
        ]
    if include_saml_handoff_flow:
        expected_plan["input_fields"].append(
            "user_id, client_ip, user_agent and ref presence/equality across IdP, auth and SP"
        )
        expected_plan["candidate"] = "previous OP handoff detector OR SAML handoff signal"
        expected_plan["saml_handoff_signals"] = [
            "IdP GET 200, auth POST 200, IdP POST 200, SP POST 302 in strict order",
            "stable user after lookup and same IP and ref throughout",
            "same nonblank agent except on the intermediate IdP POST",
        ]
    if include_ldap_handoff_flow:
        expected_plan["input_fields"].append("LDAP duration_ms and relative client context")
        expected_plan["candidate"] = "previous SAML handoff detector OR LDAP handoff signal"
        expected_plan["ldap_handoff_signals"] = [
            "OP GET 200, LDAP POST 200, OP POST 200 in strict order",
            "same OP ref and client context through LDAP, then different IP and no agent on OP POST",
            "positive LDAP processing time at most 50 ms",
        ]
    if include_op_entity_handoff_flow:
        expected_plan["input_fields"].append("nonblank ref_id equality across OP and auth")
        expected_plan["candidate"] = "previous LDAP handoff detector OR entity-linked OP handoff"
        expected_plan["op_entity_handoff_signals"] = [
            "OP GET 200, auth POST 200 and OP POST 200 in strict order",
            "same nonblank ref_id and no user_id or ref on those stages",
            "client IP and agent stable before OP POST, then IP changes and agent is absent",
        ]
    if include_auth_recovery_flow:
        expected_plan["input_fields"].append(
            "timestamp, status and nonblank user_id/User-Agent equality on auth POST"
        )
        expected_plan["candidate"] = "previous entity handoff detector OR auth recovery signals"
        expected_plan["auth_recovery_signals"] = [
            "302 in trace and auth POST 400 or 409 after OP/IdP GET 200",
            "302 in trace and adjacent auth POST 401 then 200 or 401 with same user and new agent",
        ]
    if plan.exists():
        if read(plan) != expected_plan:
            raise ValueError("existing plan differs from frozen protocol")
    else:
        write(plan, expected_plan)
    source = source or output / "source.jsonl"
    if not source.exists():
        written = 0
        with urlopen(SOURCE, timeout=30) as response, source.open("xb") as stream:
            while chunk := response.read(1024 * 1024):
                written += len(chunk)
                if written > SOURCE_SIZE:
                    raise ValueError("source grew past pinned size")
                stream.write(chunk)
    if source.stat().st_size != SOURCE_SIZE or fingerprint(source) != SOURCE_HASH:
        raise ValueError("public dataset does not match pinned bytes")

    traces = {}
    sequence_events = defaultdict(list)
    linked_events = defaultdict(list)
    op_context_events = defaultdict(list)
    handoff_events = defaultdict(list)
    auth_recovery_events = defaultdict(list)
    request_counts = defaultdict(Counter)
    stage_user_agents = defaultdict(lambda: defaultdict(set))
    with source.open("rb") as stream:
        for raw in stream:
            row = json.loads(raw)
            key = row["trace_id"]
            when = datetime.fromisoformat(row["timestamp"])
            if when.tzinfo is None:
                when = when.replace(tzinfo=UTC)
            first, last, statuses, post_denied, stages = traces.setdefault(
                key, (when, when, Counter(), False, set())
            )
            status = row.get("http_status")
            statuses[status] += 1
            if include_protocol_flow and status in PROTOCOL_STATUSES:
                stages.add((status, row.get("http_method"), row.get("module")))
            if include_success_flow and status in {200, 302}:
                module = row.get("module")
                method = row.get("http_method")
                if include_sequence_flow:
                    sequence_events[key].append((when, module, method, status))
                if include_linked_flow:
                    binding = ("", "", "")
                    if method == "POST" and status == 200 and module in {"request", "ldap"}:
                        binding = tuple(
                            nonblank_text(row.get(field))
                            for field in ("user_id", "client_ip", "user_agent")
                        )
                    linked_events[key].append((when, (module, method, status), binding))
                if include_unattributed_op_flow:
                    user = nonblank_text(row.get("user_id")) if module == "op" else ""
                    client = (
                        nonblank_text(row.get("ref"))
                        if (module, method, status) == ("op", "POST", 200)
                        else ""
                    )
                    op_context_events[key].append((when, (module, method, status), user, client))
                if include_op_handoff_flow:
                    stage = (module, method, status)
                    context = ("", "", "", "")
                    if (
                        stage in OP_AUTH_STAGES
                        or (include_saml_handoff_flow and stage in SAML_AUTH_STAGES)
                        or (include_ldap_handoff_flow and stage == LDAP_AUTH_STAGES[1])
                    ):
                        context = tuple(
                            nonblank_text(row.get(field))
                            for field in ("user_id", "client_ip", "user_agent", "ref")
                        )
                    duration = (
                        row.get("duration_ms")
                        if include_ldap_handoff_flow and stage == LDAP_AUTH_STAGES[1]
                        else None
                    )
                    entity = (
                        nonblank_text(row.get("ref_id"))
                        if include_op_entity_handoff_flow and stage in OP_AUTH_STAGES
                        else ""
                    )
                    handoff_events[key].append((when, stage, context, duration, entity))
                if module in PROTOCOL_MODULES and method in {"GET", "POST"}:
                    stage = (module, method)
                    request_counts[key][stage] += 1
                    agent = nonblank_text(row.get("user_agent"))
                    if agent:
                        stage_user_agents[key][stage].add(agent)
            if include_auth_recovery_flow:
                stage = (row.get("module"), row.get("http_method"), status)
                subject = agent = ""
                if stage[:2] == ("auth", "POST") and status in {200, 401}:
                    subject = nonblank_text(row.get("user_id"))
                    agent = nonblank_text(row.get("user_agent"))
                auth_recovery_events[key].append((when, stage, subject, agent))
            traces[key] = (
                min(first, when),
                max(last, when),
                statuses,
                post_denied
                or (include_auth_flow and status == 403 and row.get("http_method") == "POST"),
                stages,
            )
    analyzer = RuleBasedAnalyzer()
    rows = {}
    for key, (first, last, statuses, post_denied, stages) in traces.items():
        if not start <= first <= last < stop:
            continue
        failures = statuses[401]
        identity = hashlib.sha256(key.encode()).hexdigest()
        event = SecurityEvent.model_validate(
            {
                "event_id": identity,
                "timestamp": first,
                "user": {"user_id": "public-iam", "role": "employee", "active": True},
                "device": {
                    "device_id": "unspecified",
                    "managed": True,
                    "security_posture": "healthy",
                },
                "network": {
                    "ip": "192.0.2.1",
                    "location": "public-iam",
                    "access_method": "unknown",
                },
                "resource": {
                    "resource_id": "iam",
                    "resource_type": "document",
                    "sensitivity": "internal",
                },
                "action": "LOGIN",
                "behavior": {},
                "auth_context": {
                    "authentication_result": "unknown",
                    "mfa": "unknown",
                    "failed_attempts": min(failures, 100),
                },
            }
        )
        result = analyzer.assess(event)
        baseline = prediction(result)
        rows[identity] = {"prediction": baseline, "failed_401_rows": failures}
        if include_auth_flow:
            signals = auth_flow_signals(statuses, post_denied=post_denied)
            rows[identity].update(
                {
                    "prediction": baseline or bool(signals),
                    "baseline_prediction": baseline,
                    "auth_flow_signals": signals,
                }
            )
        if include_protocol_flow:
            signals = protocol_flow_signals(statuses, stages)
            previous = rows[identity]["prediction"]
            rows[identity].update(
                {
                    "previous_auth_flow_prediction": previous,
                    "prediction": previous or bool(signals),
                    "protocol_flow_signals": signals,
                }
            )
        if include_success_flow:
            signals = success_flow_signals(
                statuses, request_counts.get(key, Counter()), stage_user_agents.get(key, {})
            )
            previous = rows[identity]["prediction"]
            rows[identity].update(
                {
                    "previous_protocol_flow_prediction": previous,
                    "prediction": previous or bool(signals),
                    "success_flow_signals": signals,
                }
            )
        if include_sequence_flow:
            signals = sequence_flow_signals(statuses, sequence_events.get(key, ()))
            previous = rows[identity]["prediction"]
            rows[identity].update(
                {
                    "previous_success_flow_prediction": previous,
                    "prediction": previous or bool(signals),
                    "sequence_flow_signals": signals,
                }
            )
        if include_linked_flow:
            signals = linked_flow_signals(statuses, linked_events.get(key, ()))
            previous = rows[identity]["prediction"]
            rows[identity].update(
                {
                    "previous_sequence_flow_prediction": previous,
                    "prediction": previous or bool(signals),
                    "linked_flow_signals": signals,
                }
            )
        if include_unattributed_op_flow:
            signals = unattributed_op_signals(statuses, op_context_events.get(key, ()))
            previous = rows[identity]["prediction"]
            rows[identity].update(
                {
                    "previous_linked_flow_prediction": previous,
                    "prediction": previous or bool(signals),
                    "unattributed_op_flow_signals": signals,
                }
            )
        if include_op_handoff_flow:
            signals = op_handoff_signals(statuses, handoff_events.get(key, ()))
            previous = rows[identity]["prediction"]
            rows[identity].update(
                {
                    "previous_unattributed_op_prediction": previous,
                    "prediction": previous or bool(signals),
                    "op_handoff_signals": signals,
                }
            )
        if include_saml_handoff_flow:
            signals = saml_handoff_signals(statuses, handoff_events.get(key, ()))
            previous = rows[identity]["prediction"]
            rows[identity].update(
                {
                    "previous_op_handoff_prediction": previous,
                    "prediction": previous or bool(signals),
                    "saml_handoff_signals": signals,
                }
            )
        if include_ldap_handoff_flow:
            signals = ldap_handoff_signals(statuses, handoff_events.get(key, ()))
            previous = rows[identity]["prediction"]
            rows[identity].update(
                {
                    "previous_saml_handoff_prediction": previous,
                    "prediction": previous or bool(signals),
                    "ldap_handoff_signals": signals,
                }
            )
        if include_op_entity_handoff_flow:
            signals = op_entity_handoff_signals(statuses, handoff_events.get(key, ()))
            previous = rows[identity]["prediction"]
            rows[identity].update(
                {
                    "previous_ldap_handoff_prediction": previous,
                    "prediction": previous or bool(signals),
                    "op_entity_handoff_signals": signals,
                }
            )
        if include_auth_recovery_flow:
            signals = auth_recovery_signals(statuses, auth_recovery_events.get(key, ()))
            previous = rows[identity]["prediction"]
            rows[identity].update(
                {
                    "previous_op_entity_handoff_prediction": previous,
                    "prediction": previous or bool(signals),
                    "auth_recovery_signals": signals,
                }
            )
    write(
        output / "predictions.json",
        {
            "plan_sha256": fingerprint(plan),
            "prediction_rows": rows,
        },
    )
    print(fingerprint(output / "predictions.json"))


def score(output, seal, source=None):
    packet = output / "predictions.json"
    source = source or output / "source.jsonl"
    if fingerprint(packet) != seal or fingerprint(source) != SOURCE_HASH:
        raise ValueError("source or prediction seal mismatch")
    packet = read(packet)
    if fingerprint(output / "plan.json") != packet["plan_sha256"]:
        raise ValueError("plan seal mismatch")
    forecasts = packet["prediction_rows"]
    labels = {}
    categories = {}
    with source.open("rb") as stream:
        for raw in stream:
            row = json.loads(raw)
            identity = hashlib.sha256(row["trace_id"].encode()).hexdigest()
            if identity in forecasts:
                label = labels.setdefault(identity, row["label"])
                if label != row["label"]:
                    raise ValueError("inconsistent publisher labels in a trace")
                category = row.get("category") or "unknown"
                current = categories.setdefault(identity, category)
                if current != category:
                    categories[identity] = "mixed"
    if labels.keys() != forecasts.keys() or not set(labels.values()) <= {
        "attack",
        "benign",
        "anomaly",
    }:
        raise ValueError("missing or unsupported labels")
    scored = [
        {"id": key, "truth": label == "attack", "prediction": forecasts[key]["prediction"]}
        for key, label in labels.items()
        if label in {"attack", "benign"}
    ]
    counts = Counter(labels.values())
    if not counts["attack"] or not counts["benign"]:
        raise ValueError("missing comparable populations")
    report = {
        "prediction_sha256": seal,
        "trace_counts": dict(counts),
        "metrics": metrics(scored),
        "anomaly_signalled": sum(
            forecasts[key]["prediction"] is True
            for key, label in labels.items()
            if label == "anomaly"
        ),
        "paid_api_calls": 0,
    }
    sample_forecast = next(iter(forecasts.values()))
    if "baseline_prediction" in sample_forecast:
        reference_field, signals_field = next(
            (reference, signals)
            for reference, signals in (
                ("previous_op_entity_handoff_prediction", "auth_recovery_signals"),
                ("previous_ldap_handoff_prediction", "op_entity_handoff_signals"),
                ("previous_saml_handoff_prediction", "ldap_handoff_signals"),
                ("previous_op_handoff_prediction", "saml_handoff_signals"),
                ("previous_unattributed_op_prediction", "op_handoff_signals"),
                ("previous_linked_flow_prediction", "unattributed_op_flow_signals"),
                ("previous_sequence_flow_prediction", "linked_flow_signals"),
                ("previous_success_flow_prediction", "sequence_flow_signals"),
                ("previous_protocol_flow_prediction", "success_flow_signals"),
                ("previous_auth_flow_prediction", "protocol_flow_signals"),
                ("baseline_prediction", "auth_flow_signals"),
            )
            if reference in sample_forecast
        )
        reference = [{**row, "prediction": forecasts[row["id"]][reference_field]} for row in scored]
        comparison = compare_rows(reference, scored)
        recovered = comparison["recovered_TP_ids"]
        report.update(
            {
                "comparison": comparison,
                "baseline_misses_by_category": dict(
                    Counter(
                        categories[row["id"]]
                        for row in reference
                        if row["truth"] and not row["prediction"]
                    )
                ),
                "candidate_misses_by_category": dict(
                    Counter(
                        categories[row["id"]]
                        for row in scored
                        if row["truth"] and not row["prediction"]
                    )
                ),
                "recoveries_by_signal": dict(
                    Counter(signal for key in recovered for signal in forecasts[key][signals_field])
                ),
            }
        )
    write(output / "report.json", report)
    print(json.dumps({key: value for key, value in report.items() if key != "comparison"}))


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("phase", choices=("capture", "score"))
    cli.add_argument("output", type=Path)
    cli.add_argument("--prediction-sha256")
    cli.add_argument("--source", type=Path)
    cli.add_argument("--cohort", choices=tuple(WINDOWS), default="holdout")
    cli.add_argument("--include-auth-flow", action="store_true")
    cli.add_argument("--include-protocol-flow", action="store_true")
    cli.add_argument("--include-success-flow", action="store_true")
    cli.add_argument("--include-sequence-flow", action="store_true")
    cli.add_argument("--include-linked-flow", action="store_true")
    cli.add_argument("--include-unattributed-op-flow", action="store_true")
    cli.add_argument("--include-op-handoff-flow", action="store_true")
    cli.add_argument("--include-saml-handoff-flow", action="store_true")
    cli.add_argument("--include-ldap-handoff-flow", action="store_true")
    cli.add_argument("--include-op-entity-handoff-flow", action="store_true")
    cli.add_argument("--include-auth-recovery-flow", action="store_true")
    args = cli.parse_args()
    if args.phase == "capture":
        capture(
            args.output,
            args.source,
            cohort=args.cohort,
            include_auth_flow=args.include_auth_flow,
            include_protocol_flow=args.include_protocol_flow,
            include_success_flow=args.include_success_flow,
            include_sequence_flow=args.include_sequence_flow,
            include_linked_flow=args.include_linked_flow,
            include_unattributed_op_flow=args.include_unattributed_op_flow,
            include_op_handoff_flow=args.include_op_handoff_flow,
            include_saml_handoff_flow=args.include_saml_handoff_flow,
            include_ldap_handoff_flow=args.include_ldap_handoff_flow,
            include_op_entity_handoff_flow=args.include_op_entity_handoff_flow,
            include_auth_recovery_flow=args.include_auth_recovery_flow,
        )
    elif args.prediction_sha256:
        score(args.output, args.prediction_sha256, args.source)
    else:
        cli.error("score requires --prediction-sha256")
