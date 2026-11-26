"""Replay fixed local model alerts with runtime-verified session evidence."""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from app.services.auth_alert_triage import resolve_auth_alert, resolve_terminal_auth_alert
from scripts.evaluate_llm_grounded import metrics
from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.local_auth_attempt_lab import LocalAuthAttemptLab
from scripts.local_session_analysis_lab import LocalSessionAnalysisLab

# These describe the local collector observations and requested policy scope.
# The independent truth is joined only after the new alert dispositions are recorded.
SESSION_FIXTURES = {
    "approved_login": ("permitted_team", "remote-read", "success", True, "READ"),
    "approved_after_typo": ("permitted_team", "remote-read", "success", True, "READ"),
    "normal_token_refresh": ("permitted_team", "remote-read", "success", True, "READ"),
    "valid_saml_sign_in": ("permitted_team", "remote-read", "success", True, "READ"),
    "required_factor_missing": (
        "required_mfa_unknown",
        "remote-read",
        "unknown",
        True,
        "READ",
    ),
    "revoked_entitlement_used": (
        "revoked_request",
        "remote-read",
        "success",
        True,
        "READ",
    ),
    "device_not_approved": ("unmanaged", "remote-read", "success", False, "READ"),
    "sign_in_without_required_approval": (
        "action_denied",
        "remote-read",
        "success",
        True,
        "REMOTE_ACCESS",
    ),
}


def evidence_for_alert(lab, key, scenario):
    observation = SESSION_FIXTURES.get(scenario)
    if observation is None:
        return "needs_evidence"
    name, resource, mfa, managed, action = observation
    signal, _ = lab.create(
        (name, False, resource, "employee", mfa, managed, action), evidence_event_id=key
    )
    event = signal.event.model_copy(update={"event_id": key})
    return resolve_auth_alert(lab.service, event, signal, lab.principal)


def terminal_evidence_for_alert(lab, attempts, key, scenario):
    if scenario == "normal_user_abandons_auth":
        event = attempts.open(key)
        receipt = attempts.cancel(key)
    elif scenario == "ordinary_upstream_outage":
        event = attempts.open(key)
        with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(503))) as client:
            receipt = attempts.check_upstream(key, lambda: client.get("http://fixture-idp/ready"))
    else:
        return "needs_evidence"
    if receipt is None:
        return "needs_evidence"
    return resolve_terminal_auth_alert(lab.service, event, receipt, lab.principal)


def evaluate(previous, output, *, terminal_evidence=False):
    plan_path = previous / "plan.json"
    packet_path = previous / "predictions.json"
    truth_path = previous / "fixture_truth.json"
    packet, plan, report = read(packet_path), read(plan_path), read(previous / "report.json")
    prior_seal = fingerprint(packet_path)
    if (
        prior_seal != report["fixture_predictions_sha256"]
        or packet["plan_sha256"] != fingerprint(plan_path)
        or plan["truth_sha256"] != fingerprint(truth_path)
        or plan["observations_sha256"] != fingerprint(previous / "observations.jsonl")
    ):
        raise ValueError("transfer artifact integrity mismatch")

    # Provision observations by the already-defined scenario, without passing the label to triage.
    scenarios = {key: row["scenario"] for key, row in read(truth_path).items()}
    if scenarios.keys() != packet["rows"].keys():
        raise ValueError("fixture cases differ from frozen model cases")
    output.mkdir(parents=True, exist_ok=True)
    decisions = {}
    with TemporaryDirectory(prefix="zt-auth-alert-triage-") as scratch:
        lab = LocalSessionAnalysisLab(Path(scratch) / "authority")
        attempts = LocalAuthAttemptLab(lab) if terminal_evidence else None
        for key, row in packet["rows"].items():
            if row["enforced"]:
                disposition = "existing_rule"
            elif row["alert"]:
                disposition = evidence_for_alert(lab, key, scenarios[key])
                if disposition == "needs_evidence" and attempts is not None:
                    disposition = terminal_evidence_for_alert(lab, attempts, key, scenarios[key])
            else:
                disposition = "no_alert"
            decisions[key] = {"enforced": row["enforced"], "disposition": disposition}
    decision_path = output / "predictions.json"
    write(decision_path, {"source_prediction_sha256": prior_seal, "rows": decisions})
    decision_seal = fingerprint(decision_path)

    truth = read(truth_path)
    before, actionable = [], []
    by_scenario = defaultdict(Counter)
    pending = Counter()
    for key, row in packet["rows"].items():
        label = truth[key]["truth"]
        decision = decisions[key]
        disposition = decision["disposition"]
        by_scenario[scenarios[key]][disposition] += 1
        if disposition == "needs_evidence":
            pending["attack" if label else "benign"] += 1
        before.append({"id": key, "truth": label, "prediction": row["enforced"] or row["alert"]})
        actionable.append(
            {
                "id": key,
                "truth": label,
                "prediction": decision["enforced"] or disposition == "confirmed",
            }
        )
    result = {
        "source_prediction_sha256": prior_seal,
        "prediction_sha256": decision_seal,
        "raw_shadow_alerts": metrics(before),
        "confirmed_or_rule_alerts": metrics(actionable),
        "pending_review": dict(pending),
        "prior_enforcement_preserved": all(
            decisions[key]["enforced"] == row["enforced"] for key, row in packet["rows"].items()
        ),
        "lost_previously_detected_attack": sum(
            a["truth"] and a["prediction"] and not b["prediction"]
            for a, b in zip(before, actionable, strict=True)
        ),
        "scenarios": by_scenario,
        "terminal_evidence_enabled": terminal_evidence,
        "paid_api_calls": 0,
    }
    write(output / "report.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("previous", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--terminal-evidence", action="store_true")
    args = parser.parse_args()
    evaluate(args.previous, args.output, terminal_evidence=args.terminal_evidence)
