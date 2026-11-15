"""Paired observed-development replay of raw audit/auth observations; no grants."""

import argparse
import hashlib
from pathlib import Path

from scripts.f1_lab.audit_auth_review import AuditReview, caller_events, refine, su_transition
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.raw_observations import raw_time
from scripts.f1_lab.transfer_evaluation import score, sha, source_pins

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ["russellmitchell", "santos", "fox", "harrison_observed"]


def signals(raw_directory, preparation):
    """Only exact auth/audit siblings in one physical host namespace may link."""
    raw_directory = Path(raw_directory)
    require(
        sha(raw_directory / "audit.json") == preparation["source_manifest_sha256"],
        "audit_auth_raw_manifest",
    )
    manifest = decode((raw_directory / "audit.json").read_bytes())
    require(
        manifest.get("completed") is True
        and manifest.get("timestamp_basis")
        == "naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check",
        "audit_auth_timezone_contract",
    )
    groups, records, pins, observed = {}, {}, {}, {}
    for index, pair in enumerate(preparation["pairs"]):
        member = pair["raw_member"]
        suffix = next(
            (s for s in ("/logs/auth.log", "/logs/audit/audit.log") if member.endswith(s)), None
        )
        if suffix is None:
            continue
        host = member[: -len(suffix)]
        kind = "auth" if suffix == "/logs/auth.log" else "audit"
        group = groups.setdefault(host, {})
        require(kind not in group, "audit_auth_ambiguous_host_source")
        group[kind] = index
        provenance = manifest["pairs"][index]["provenance"]
        require(
            provenance["raw_member"] == member and provenance["raw_sha256"] == pair["raw_sha256"],
            "audit_auth_raw_binding",
        )
        path = raw_directory / f"pair-{index}-raw.source"
        require(sha(path, 64 * 1024**2) == pair["raw_sha256"], "audit_auth_raw_hash")
        pins[path] = pair["raw_sha256"]
        lines = []
        with path.open("rb") as stream:
            for ordinal, body in enumerate(stream, 1):
                require(len(body) <= MAX_ROW and ordinal <= 100000, "audit_auth_raw_bound")
                try:
                    line = body.decode("utf8")
                    time = raw_time(
                        line,
                        provenance["simulation_start"],
                        provenance["simulation_end"],
                        source_timezone="UTC",
                    )
                except (UnicodeError, ValueError, RecursionError):
                    line, time = "", None
                lines.append((time, line))
        require(len(lines) == pair["rows"], "audit_auth_raw_population")
        records[index] = lines
    for group in groups.values():
        auth = records.get(group.get("auth"), [])
        events = caller_events(auth)
        if "auth" in group:
            index = group["auth"]
            for ordinal, (time, line) in enumerate(auth, 1):
                if time is not None and su_transition(line):
                    observed[(index, ordinal)] = "web_service_account_su"
        if "audit" in group:
            index = group["audit"]
            review = AuditReview(events)
            for ordinal, (time, line) in enumerate(records[index], 1):
                reason = review.observe(line, time)
                if reason:
                    observed[(index, ordinal)] = reason
    require(all(sha(p) == expected for p, expected in pins.items()), "audit_auth_raw_changed")
    return observed, {
        "target_sources": len(records),
        "raw_sha256": {p.name: v for p, v in pins.items()},
        "observed_signals": len(observed),
        "labels_opened": False,
    }


def predict(prepared, preparation, raw_directory, baseline, baseline_hash, output):
    require(sha(baseline) == baseline_hash, "audit_auth_baseline_hash")
    selected, evidence = signals(raw_directory, preparation)
    output = Path(output)
    require(
        not output.exists() and not output.with_suffix(".part").exists(), "audit_auth_fresh_output"
    )
    count, source, ordinal, errors = 0, 0, 0, 0
    with Path(baseline).open("rb") as old, output.with_suffix(".part").open("xb") as target:
        while body := old.readline(MAX_ROW + 1):
            require(
                len(body) <= MAX_ROW and source < len(preparation["pairs"]),
                "audit_auth_previous_bound",
            )
            ordinal += 1
            pair = preparation["pairs"][source]
            prior = decode(body)
            case = hashlib.sha256((pair["raw_sha256"] + ":" + str(ordinal)).encode()).hexdigest()
            require(
                prior["case_id"] == case and prior["source_index"] == source,
                "audit_auth_case_order",
            )
            before = prior["after"] if prior["error"] is None else None
            after, probability, reason, error = (
                before,
                prior["after_score"],
                prior["reason"],
                prior["error"],
            )
            if error is None:
                decision = refine(
                    OperationDecision(prior["before_score"], probability, before, before, reason),
                    selected.get((source, ordinal)),
                )
                after, probability, reason = decision.alert, decision.score, decision.reason
                require(not before or after, "audit_auth_lost_alarm")
            errors += error is not None
            target.write(
                canonical(
                    {
                        "case_id": case,
                        "source_index": source,
                        "before": before,
                        "after": after,
                        "before_score": prior["after_score"],
                        "after_score": probability,
                        "reason": reason,
                        "error": error,
                    }
                )
                + b"\n"
            )
            count += 1
            if ordinal == pair["rows"]:
                source, ordinal = source + 1, 0
    require(
        source == len(preparation["pairs"]) and ordinal == 0 and sha(baseline) == baseline_hash,
        "audit_auth_previous_population_or_drift",
    )
    output.with_suffix(".part").rename(output)
    return {
        "population": count,
        "inference_errors": errors,
        "predictions_sha256": sha(output),
        "labels_opened_by_predictor": False,
        "raw_evidence": evidence,
    }


def run(plan_path, plan_hash, prior_path, prior_hash, output):
    require(
        sha(plan_path) == plan_hash and sha(prior_path) == prior_hash, "audit_auth_external_hash"
    )
    plan, prior = decode(Path(plan_path).read_bytes()), decode(Path(prior_path).read_bytes())
    require(
        plan["scope"] == prior["scope"] == "observed_development_only"
        and prior["completed"]
        and plan["goal_qualified"] is False
        and prior["goal_qualified"] is False
        and [s["name"] for s in plan["scenarios"]] == SCENARIOS
        and set(prior["scenarios"]) == set(SCENARIOS)
        and plan["candidate_sha256"] == source_pins(ROOT)["scripts/f1_lab/audit_auth_review.py"],
        "audit_auth_development_contract",
    )
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    pins = source_pins(ROOT)
    report = {
        "completed": False,
        "scope": plan["scope"],
        "goal_qualified": False,
        "production_adopted": False,
        "automatic_enforcement_allowed": False,
        "paid_api_calls": 0,
        "aws_calls": 0,
        "models_refitted": False,
        "labels_changed": False,
        "plan_sha256": plan_hash,
        "prior_sha256": prior_hash,
        "source_pins": pins,
        "scenarios": {},
    }
    (output / "plan.json").write_bytes(canonical(plan) + b"\n")
    try:
        preparations = {}
        for spec in plan["scenarios"]:
            name, prepared = spec["name"], Path(spec["prepared"])
            require(
                sha(prepared / "preparation.json") == spec["preparation_sha256"],
                "audit_auth_preparation_hash",
            )
            preparation = decode((prepared / "preparation.json").read_bytes())
            preparations[name] = preparation
            require(
                spec["baseline_sha256"]
                == prior["scenarios"][name]["prediction"]["predictions_sha256"],
                "audit_auth_prior_binding",
            )
            prediction = predict(
                prepared,
                preparation,
                spec["raw"],
                spec["baseline"],
                spec["baseline_sha256"],
                output / (name + "-predictions.jsonl"),
            )
            require(
                prediction["population"] == prior["scenarios"][name]["population"],
                "audit_auth_original_population",
            )
            report["scenarios"][name] = {"prediction": prediction}
            print(
                canonical({"predicted": name, "population": prediction["population"]}).decode(),
                flush=True,
            )
        require(source_pins(ROOT) == pins, "audit_auth_code_changed")
        (output / "prediction-seal.json").write_bytes(canonical(report) + b"\n")
        for spec in plan["scenarios"]:
            name = spec["name"]
            prediction = report["scenarios"][name]["prediction"]
            result = score(
                output / (name + "-predictions.jsonl"),
                Path(spec["prepared"]) / "truth.jsonl",
                prediction["predictions_sha256"],
                preparations[name]["files"]["truth.jsonl"]["sha256"],
            )
            require(
                result["metrics"]["before"] == prior["scenarios"][name]["metrics"]["after"],
                "audit_auth_prior_score",
            )
            report["scenarios"][name] = {**result, "prediction": prediction}
            print(canonical({"scored": name, "changes": result["changes"]}).decode(), flush=True)
        require(
            source_pins(ROOT) == pins
            and sha(plan_path) == plan_hash
            and sha(prior_path) == prior_hash,
            "audit_auth_inputs_changed",
        )
        report["candidate_development_gate_passed"] = (
            all(
                s["changes"]["introduced_fp"]
                == s["changes"]["lost_tp"]
                == s["prediction"]["inference_errors"]
                == 0
                for s in report["scenarios"].values()
            )
            and sum(s["changes"]["new_tp"] for s in report["scenarios"].values()) > 0
        )
        report["completed"] = True
    finally:
        (output / "run.json").write_bytes(canonical(report) + b"\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("plan", "prior", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--prior-sha256", required=True)
    args = parser.parse_args()
    run(args.plan, args.plan_sha256, args.prior, args.prior_sha256, args.output)


if __name__ == "__main__":
    main()
