"""Evaluate a frozen KREONET model on separate local authentication scenario fixtures."""

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from random import Random
from time import perf_counter_ns

from scripts import evaluate_kreonet_auth as rules
from scripts import evaluate_kreonet_model as model
from scripts.evaluate_llm_grounded import metrics
from scripts.evaluate_local_remote_holdout import fingerprint, read, write

REDIRECT = ("rp", "GET", 302)
LOOKUP = ("op", "GET", 200)
AUTH = ("auth", "POST", 200)
DENIED = ("auth", "POST", 401)
SUBMIT = ("op", "POST", 200)
RETURN = ("rp", "GET", 200)
LOGIN = (REDIRECT, LOOKUP, AUTH, SUBMIT, RETURN)
RETRY = (REDIRECT, LOOKUP, DENIED, AUTH, SUBMIT, RETURN)
SCENARIOS = (
    ("approved_login", False, LOGIN),
    ("approved_after_typo", False, RETRY),
    ("normal_token_refresh", False, (LOOKUP, SUBMIT, RETURN)),
    (
        "valid_saml_sign_in",
        False,
        (
            ("sp", "GET", 302),
            ("idp", "GET", 200),
            AUTH,
            ("idp", "POST", 200),
            ("sp", "POST", 302),
        ),
    ),
    ("ordinary_upstream_outage", False, (REDIRECT, LOOKUP, ("op", "POST", 502))),
    ("normal_user_abandons_auth", False, (REDIRECT, LOOKUP, DENIED)),
    ("required_factor_missing", True, LOGIN),
    ("revoked_entitlement_used", True, LOGIN),
    ("device_not_approved", True, RETRY),
    (
        "credential_rejected_repeatedly",
        True,
        (REDIRECT, LOOKUP, DENIED, DENIED, DENIED, DENIED, DENIED),
    ),
    ("sign_in_without_required_approval", True, (REDIRECT, LOOKUP, SUBMIT, RETURN)),
    ("known_client_changes_after_rejection", True, RETRY),
)


def generate_fixtures(output):
    """Truth follows each case's predefined policy, even where the HTTP log is ambiguous."""
    rng = Random(17031)
    source = output / "observations.jsonl"
    manifest = {}
    traces = []
    for repeat in range(8):
        for name, attack, steps in SCENARIOS:
            key = f"{repeat:02d}-{name}"
            # Paired cases use the same timing variations and observable client context.
            peer = {
                "required_factor_missing": "approved_login",
                "revoked_entitlement_used": "approved_login",
                "device_not_approved": "approved_after_typo",
            }.get(name, name)
            seed = int.from_bytes(hashlib.sha256(f"{repeat}-{peer}".encode()).digest()[:8])
            variation = Random(seed)
            identity = hashlib.sha256(key.encode()).hexdigest()
            manifest[identity] = {"truth": attack, "scenario": name}
            when = datetime(2026, 3, 20, tzinfo=UTC) + timedelta(minutes=rng.randrange(800))
            for index, (module, method, status) in enumerate(steps):
                when += timedelta(milliseconds=variation.randint(75, 2300))
                changed = name == "known_client_changes_after_rejection" and index >= 3
                traces.append(
                    {
                        "trace_id": key,
                        "timestamp": when.isoformat(),
                        "module": module,
                        "http_method": method,
                        "http_status": status,
                        "duration_ms": variation.randint(28, 340),
                        "user_id": f"local-user-{repeat}" if module in {"auth", "rp", "sp"} else "",
                        "client_ip": "192.0.2.20" if changed else "192.0.2.10",
                        "user_agent": "local-client-other"
                        if changed
                        else f"local-client-{repeat % 3}",
                        "ref_id": "local-identity-provider",
                        "ref": "local-relying-party" if module != "auth" else "",
                    }
                )
    source.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in traces), encoding="utf-8"
    )
    write(output / "fixture_truth.json", manifest)
    return source


def audit_reference(source, previous_report, output):
    """Summarize frozen comparison errors without raw identifiers or label-bearing features."""
    comparison = previous_report["comparison"]
    categories = {"new_false_positive": set(comparison["new_FP_ids"])}
    packet = read(output / "predictions.json")["prediction_rows"]
    events, label_counts = defaultdict(list), Counter()
    categories["remaining_false_negative"] = set()
    with source.open("rb") as stream:
        for raw in stream:
            row = json.loads(raw)
            key = hashlib.sha256(row["trace_id"].encode()).hexdigest()
            if key not in packet:
                continue
            if row["label"] == "attack" and not packet[key]["prediction"]:
                categories["remaining_false_negative"].add(key)
            events[key].append(
                (datetime.fromisoformat(row["timestamp"]), model.stage(row), row.get("category"))
            )
    for kind, keys in categories.items():
        signatures = Counter()
        for key in keys:
            observed = sorted(events[key])
            statuses = "/".join(str(status) for status in sorted({r[1][2] for r in observed}))
            signature = "|".join(":".join(map(str, row[1])) for row in observed)
            signatures[signature] += 1
            label_counts[kind, "status", statuses] += 1
            label_counts[kind, "category", observed[0][2] or "unknown"] += 1
        for signature, count in signatures.most_common(8):
            label_counts[kind, "top_sequence", signature] = count
    report = defaultdict(lambda: defaultdict(dict))
    for (kind, group, value), count in sorted(label_counts.items()):
        report[kind][group][value] = count
    return report


def shadow_decision(previous, observe):
    """A model observation can emit an alert and cannot replace the rule decision."""
    if observe is None:
        return {"enforced": previous, "alert": False, "state": "disabled"}
    try:
        score, threshold = observe()
        return {"enforced": previous, "alert": score > threshold, "state": "scored"}
    except (RuntimeError, ValueError, TimeoutError):
        return {"enforced": previous, "alert": False, "state": "model_unavailable"}


def evaluate_transfer(output, source, references, frozen):
    from threadpoolctl import threadpool_limits

    output.mkdir(parents=True, exist_ok=True)
    prior_plan, prior_report = read(frozen / "plan.json"), read(frozen / "report.json")
    frozen_packet = read(frozen / "predictions.json")
    if (
        prior_report["prediction_sha256"] != fingerprint(frozen / "predictions.json")
        or frozen_packet["plan_sha256"] != fingerprint(frozen / "plan.json")
        or prior_plan["policy"] != "target"
    ):
        raise ValueError("frozen target plan or prediction seal mismatch")
    members, seals = model.read_reference(references)
    if prior_plan["reference_prediction_sha256"] != seals:
        raise ValueError("frozen training reference mismatch")
    events, labels = model.read_observations(source, members)
    training = [
        key
        for key, (split, hit) in members.items()
        if split == "development" and not hit and labels[key] in {"attack", "benign"}
    ]
    fixture_path = generate_fixtures(output)
    fixture_hash = fingerprint(fixture_path)
    rule_output = output / "rules"
    rules.capture(
        rule_output, fixture_path, local_source_sha256=fixture_hash, include_auth_outcome_flow=True
    )
    reference = read(rule_output / "predictions.json")["prediction_rows"]
    projected, _ = model.read_observations(
        fixture_path,
        {key: ("holdout", row["prediction"]) for key, row in reference.items()},
        local_source_sha256=fixture_hash,
    )
    threshold = prior_plan["target_threshold"]
    plan = {
        "observations_sha256": fixture_hash,
        "truth_sha256": fingerprint(output / "fixture_truth.json"),
        "frozen_plan_sha256": fingerprint(frozen / "plan.json"),
        "threshold": threshold,
        "source": "separate local simulated authorization scenarios",
    }
    write(output / "plan.json", plan)
    packet = {}
    elapsed = []
    with threadpool_limits(limits=3):
        fitted = model.fit_models(events, training, [labels[key] == "attack" for key in training])
        known_rows = frozen_packet["prediction_rows"]
        replay_keys = [key for key, row in known_rows.items() if row["model_score"] is not None]
        replay = model.model_scores(events, replay_keys, fitted)
        if any(
            abs(float(score) - known_rows[key]["model_score"]) > 1e-10
            for key, score in zip(replay_keys, replay, strict=True)
        ):
            raise ValueError("retrained model does not reproduce the frozen scores")
        for key, row in reference.items():
            baseline = row["prediction"]

            def observe(key=key):
                started = perf_counter_ns()
                score = float(model.model_scores(projected, [key], fitted)[0])
                elapsed.append((perf_counter_ns() - started) / 1_000_000)
                return score, threshold

            packet[key] = shadow_decision(baseline, None if baseline else observe)
    write(
        output / "predictions.json",
        {"plan_sha256": fingerprint(output / "plan.json"), "rows": packet},
    )
    seal = fingerprint(output / "predictions.json")
    truth = read(output / "fixture_truth.json")
    if truth.keys() != packet.keys():
        raise ValueError("fixture labels do not match predictions")
    prior = [
        {"id": key, "truth": truth[key]["truth"], "prediction": item["enforced"]}
        for key, item in packet.items()
    ]
    candidate = [
        {**row, "prediction": row["prediction"] or packet[row["id"]]["alert"]} for row in prior
    ]
    by_scenario = defaultdict(Counter)
    for before, after in zip(prior, candidate, strict=True):
        status = (
            "tp"
            if after["prediction"] and after["truth"]
            else "fp"
            if after["prediction"]
            else "fn"
            if after["truth"]
            else "tn"
        )
        by_scenario[truth[before["id"]]["scenario"]][status] += 1
    elapsed.sort()
    if not elapsed:
        raise ValueError("no shadow model observations")

    def unavailable():
        raise RuntimeError("local model unavailable")

    report = {
        "fixture_predictions_sha256": seal,
        "prior_rules": metrics(prior),
        "hypothetical_model_alerts": metrics(candidate),
        "known_rule_decisions_preserved": all(
            packet[key]["enforced"] == row["prediction"] for key, row in reference.items()
        ),
        "fallback_verified": all(
            shadow_decision(flag, unavailable)["enforced"] == flag for flag in (False, True)
        ),
        "p95_local_model_ms": elapsed[(95 * len(elapsed) + 99) // 100 - 1],
        "scenarios": by_scenario,
        "original_false_positive_and_miss_audit": audit_reference(source, prior_report, frozen),
        "frozen_scores_reproduced": len(replay_keys),
        "paid_api_calls": 0,
    }
    write(output / "report.json", report)
    print(
        json.dumps(
            {
                key: val
                for key, val in report.items()
                if key != "original_false_positive_and_miss_audit"
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--references", nargs=3, required=True, type=Path)
    parser.add_argument("--frozen", required=True, type=Path)
    args = parser.parse_args()
    evaluate_transfer(args.output, args.source, args.references, args.frozen)
