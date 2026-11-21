"""Measure the existing local credential rule on a fixed public IAM time window."""

import argparse
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
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


def capture(
    output, source=None, *, cohort="holdout", include_auth_flow=False, include_protocol_flow=False
):
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
        compare_protocol = "previous_auth_flow_prediction" in sample_forecast
        reference_field = (
            "previous_auth_flow_prediction" if compare_protocol else "baseline_prediction"
        )
        signals_field = "protocol_flow_signals" if compare_protocol else "auth_flow_signals"
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
    args = cli.parse_args()
    if args.phase == "capture":
        capture(
            args.output,
            args.source,
            cohort=args.cohort,
            include_auth_flow=args.include_auth_flow,
            include_protocol_flow=args.include_protocol_flow,
        )
    elif args.prediction_sha256:
        score(args.output, args.prediction_sha256, args.source)
    else:
        cli.error("score requires --prediction-sha256")
