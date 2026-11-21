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
from scripts.evaluate_llm_grounded import metrics, prediction
from scripts.evaluate_local_remote_holdout import fingerprint, read, write

COMMIT = "5fd5cae2001a6b67cafb952709db37e366cfa276"
SOURCE = f"https://raw.githubusercontent.com/KREONET/auth-anomaly-dataset/{COMMIT}/iam_anomaly_2026.jsonl"
SOURCE_SIZE = 91592665
SOURCE_HASH = "445f69377a2e12b4203a68f15cd9a4013fbc7e0ef21c19843969f671b1334a30"
START = datetime(2026, 3, 16, tzinfo=UTC)
STOP = datetime(2026, 3, 30, tzinfo=UTC)


def capture(output):
    output.mkdir(exist_ok=True)
    plan = output / "plan.json"
    expected_plan = {
        "source": SOURCE,
        "source_sha256": SOURCE_HASH,
        "holdout_start": START.isoformat(),
        "holdout_stop_exclusive": STOP.isoformat(),
        "timestamp_without_offset": "UTC",
        "metric_unit": "trace_id_entirely_in_window",
        "input_fields": ["trace_id for grouping", "timestamp for window", "http_status"],
        "mapping": "HTTP 401 rows per trace as a proxy for failed_attempts; no inferred MFA or approvals",
        "rule": "existing RuleBasedAnalyzer on LOGIN",
        "score_labels": ["attack", "benign"],
    }
    if plan.exists():
        if read(plan) != expected_plan:
            raise ValueError("existing plan differs from frozen protocol")
    else:
        write(plan, expected_plan)
    source = output / "source.jsonl"
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
            first, last, failures = traces.setdefault(key, (when, when, 0))
            traces[key] = (
                min(first, when),
                max(last, when),
                failures + (row.get("http_status") == 401),
            )
    analyzer = RuleBasedAnalyzer()
    rows = {}
    for key, (first, last, failures) in traces.items():
        if not START <= first <= last < STOP:
            continue
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
        rows[identity] = {"prediction": prediction(result), "failed_401_rows": failures}
    write(
        output / "predictions.json",
        {
            "plan_sha256": fingerprint(plan),
            "prediction_rows": rows,
        },
    )
    print(fingerprint(output / "predictions.json"))


def score(output, seal):
    packet = output / "predictions.json"
    source = output / "source.jsonl"
    if fingerprint(packet) != seal or fingerprint(source) != SOURCE_HASH:
        raise ValueError("source or prediction seal mismatch")
    packet = read(packet)
    if fingerprint(output / "plan.json") != packet["plan_sha256"]:
        raise ValueError("plan seal mismatch")
    forecasts = packet["prediction_rows"]
    labels = {}
    with source.open("rb") as stream:
        for raw in stream:
            row = json.loads(raw)
            identity = hashlib.sha256(row["trace_id"].encode()).hexdigest()
            if identity in forecasts:
                label = labels.setdefault(identity, row["label"])
                if label != row["label"]:
                    raise ValueError("inconsistent publisher labels in a trace")
    if labels.keys() != forecasts.keys() or not set(labels.values()) <= {
        "attack",
        "benign",
        "anomaly",
    }:
        raise ValueError("missing or unsupported labels")
    scored = [
        {"truth": label == "attack", "prediction": forecasts[key]["prediction"]}
        for key, label in labels.items()
        if label in {"attack", "benign"}
    ]
    counts = Counter(labels.values())
    if not counts["attack"] or not counts["benign"]:
        raise ValueError("missing comparable populations")
    write(
        output / "report.json",
        {
            "prediction_sha256": seal,
            "trace_counts": dict(counts),
            "metrics": metrics(scored),
            "anomaly_signalled": sum(
                forecasts[key]["prediction"] is True
                for key, label in labels.items()
                if label == "anomaly"
            ),
            "paid_api_calls": 0,
        },
    )
    print(json.dumps(read(output / "report.json")))


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("phase", choices=("capture", "score"))
    cli.add_argument("output", type=Path)
    cli.add_argument("--prediction-sha256")
    args = cli.parse_args()
    if args.phase == "capture":
        capture(args.output)
    elif args.prediction_sha256:
        score(args.output, args.prediction_sha256)
    else:
        cli.error("score requires --prediction-sha256")
