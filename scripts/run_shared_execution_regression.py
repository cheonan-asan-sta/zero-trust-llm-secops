"""Check sealed prior decisions with unavailable new evidence; no label changes."""

import argparse
import hashlib
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.shared_execution_evidence import ServiceEvidenceJoiner, VerifiedServiceRisk
from scripts.f1_lab.transfer_evaluation import sha
from scripts.run_shared_execution_controls import setup

SCENARIOS = ["russellmitchell", "santos", "fox", "harrison_observed"]


def run(prior_directory, expected_prior_sha256, output):
    prior_directory, output = Path(prior_directory), Path(output)
    prior_path = prior_directory / "run.json"
    require(sha(prior_path) == expected_prior_sha256, "service_regression_prior_hash")
    prior = decode(prior_path.read_bytes())
    require(
        prior["completed"] is True
        and prior["goal_qualified"] is False
        and prior["scope"] == "observed_development_only"
        and set(prior["scenarios"]) == set(SCENARIOS),
        "service_regression_prior_contract",
    )
    output.mkdir(parents=True, exist_ok=False)
    _, _, pinned = setup(output / "control-registry")
    adapter = VerifiedServiceRisk(
        ServiceEvidenceJoiner(pinned, output / "ledger.sqlite3", expected_mode="local_process_lab")
    )
    report = {
        "schema": "extra-shared-execution-legacy-regression-1",
        "completed": False,
        "scope": "prior observed-development decision regression only; no new ground truth",
        "goal_qualified": False,
        "paid_api_calls": 0,
        "aws_calls": 0,
        "source_prior_sha256": expected_prior_sha256,
        "native_actor_command_evidence_added_to_legacy": 0,
        "scenarios": {},
    }
    try:
        for name in SCENARIOS:
            path = prior_directory / (name + "-predictions.jsonl")
            expected = prior["scenarios"][name]["prediction"]["predictions_sha256"]
            require(sha(path) == expected, "service_regression_predictions_hash")
            before_hash, after_hash = hashlib.sha256(), hashlib.sha256()
            count = changes = 0
            with path.open("rb") as stream:
                while body := stream.readline(MAX_ROW + 1):
                    require(len(body) <= MAX_ROW, "service_regression_row_bound")
                    row = decode(body)
                    before = row["after"]
                    if row["error"] is None:
                        decision = OperationDecision(
                            row["before_score"], row["after_score"], before, before, row["reason"]
                        )
                        result = adapter.decide(decision)
                        require(
                            result is decision and not result.automatic_enforcement_allowed,
                            "service_regression_changed_without_evidence",
                        )
                        after = result.alert
                    else:
                        require(before is None, "service_regression_error_contract")
                        after = None
                    count += 1
                    changes += before != after
                    before_hash.update(canonical([row["case_id"], row["source_index"], before]))
                    after_hash.update(canonical([row["case_id"], row["source_index"], after]))
            require(
                count == prior["scenarios"][name]["population"]
                and changes == 0
                and before_hash.digest() == after_hash.digest()
                and sha(path) == expected,
                "service_regression_population_drift",
            )
            report["scenarios"][name] = {
                "population": count,
                "changed_decisions": changes,
                "predictions_sha256": expected,
                "before_decision_sha256": before_hash.hexdigest(),
                "after_decision_sha256": after_hash.hexdigest(),
                "retained_metrics": prior["scenarios"][name]["metrics"]["after"],
                "introduced_fp": 0,
                "lost_tp": 0,
                "new_tp": 0,
                "removed_fp": 0,
                "labels_reopened": False,
            }
        require(sha(prior_path) == expected_prior_sha256, "service_regression_prior_changed")
        report["population"] = sum(s["population"] for s in report["scenarios"].values())
        report["completed"] = True
    finally:
        (output / "run.json").write_bytes(canonical(report) + b"\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior-directory", type=Path, required=True)
    parser.add_argument("--prior-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.prior_directory, args.prior_sha256, args.output)
    print(
        canonical(
            {
                "completed": result["completed"],
                "population": result["population"],
                "changed_decisions": 0,
            }
        ).decode()
    )


if __name__ == "__main__":
    main()
