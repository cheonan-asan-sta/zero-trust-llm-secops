"""Freeze, capture, and score new local signed remote-session scenarios.

Run the three commands in order with the same output directory. The capture
phase reads the frozen input plan only. Labels come from the predeclared lab
operator's intent, which is established independently of PE/PA output.
"""

import argparse
import asyncio
import hashlib
import json
import random
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import ModuleType
from unittest.mock import patch

from app.analyzers.hybrid import HybridAnalyzer
from app.models import SecurityAssessment, SecurityEvent
from app.services.session_analysis_evidence import collect_session_evidence, event_digest
from app.zero_trust_models import SessionRevocationRequest
from scripts import local_session_analysis_lab as lab_support
from scripts.compare_llm_grounded import compare_rows
from scripts.evaluate_llm_grounded import prediction
from scripts.replay_hybrid_development import replay_settings

REFERENCE = "4bc10d5"
CANDIDATE = "583216bdb79bbdfe21b27ef8bfdb2199881670fb"
ANALYZER = "app/analyzers/hybrid.py"
# Intent refers to the final submitted request. Bootstrap challenges are not scored.
FAMILIES = (
    ("first_step_up", "REMOTE_ACCESS", "standard", "direct", "success", False),
    ("no_mfa_required_remote", "REMOTE_ACCESS", "optional", "direct", "unknown", False),
    ("allowed_read", "READ", "standard", "direct", "success", False),
    ("verified_read_completion", "READ", "standard", "bound", "success", False),
    ("verified_remote_completion", "REMOTE_ACCESS", "standard", "bound", "success", False),
    ("optional_read_unknown", "READ", "optional", "direct", "unknown", False),
    ("optional_read_not_required", "READ", "optional", "direct", "not_required", False),
    ("authorized_restricted_role", "READ", "restricted", "bound", "success", False),
    ("unbound_read_completion", "READ", "standard", "absent", "success", True),
    ("wrong_challenge_read", "READ", "standard", "wrong", "success", True),
    ("unbound_remote_completion", "REMOTE_ACCESS", "standard", "absent", "success", True),
    ("wrong_challenge_remote", "REMOTE_ACCESS", "standard", "wrong", "success", True),
    ("unauthorized_role", "REMOTE_ACCESS", "restricted", "direct", "success", True),
    ("unauthorized_action", "REMOTE_ACCESS", "read-only", "direct", "success", True),
    ("withdrawn_read", "READ", "standard", "revoked", "success", True),
    ("failed_required_mfa", "REMOTE_ACCESS", "standard", "direct", "failed", True),
)
PROFILES = (
    ("support", "vpn", "192.0.2.48", 1),
    ("maintenance", "remote", "198.51.100.71", 0),
    ("build", "vpn", "203.0.113.45", 3),
    ("recovery", "remote", "192.0.2.112", 2),
)
FOLLOWUP_FAMILIES = (
    ("service_desk_verified", "REMOTE_ACCESS", "standard", "bound", "success", False),
    ("after_hours_admin", "REMOTE_ACCESS", "restricted", "bound", "success", False),
    ("verified_previous_mfa", "REMOTE_ACCESS", "standard", "bound-existing-mfa", "success", False),
    ("busy_verified_operator", "REMOTE_ACCESS", "standard", "bound-busy", "success", False),
    ("optional_verified_followup", "REMOTE_ACCESS", "optional", "bound", "success", False),
    ("read_after_challenge", "READ", "standard", "bound", "success", False),
    ("first_authorized_admin", "REMOTE_ACCESS", "restricted", "direct", "success", False),
    ("optional_read_with_mfa", "READ", "optional", "direct", "success", False),
    ("verified_but_fanout", "REMOTE_ACCESS", "standard", "bound-fanout", "success", True),
    ("verified_but_unmanaged", "REMOTE_ACCESS", "standard", "bound-unmanaged", "success", True),
    ("verified_but_denied_action", "REMOTE_ACCESS", "standard", "bound-denied", "success", True),
    (
        "verified_but_unregistered",
        "REMOTE_ACCESS",
        "standard",
        "bound-unregistered",
        "success",
        True,
    ),
    ("wrong_remote_challenge", "REMOTE_ACCESS", "standard", "wrong", "success", True),
    ("missing_read_challenge", "READ", "standard", "absent", "success", True),
    ("failed_remote_challenge", "REMOTE_ACCESS", "standard", "bound", "failed", True),
    ("remote_after_revocation", "REMOTE_ACCESS", "standard", "revoked", "success", True),
)
FOLLOWUP_PROFILES = (
    ("service-desk", "vpn", "203.0.113.18", 0),
    ("after-hours", "remote", "198.51.100.43", 5),
    ("release", "vpn", "192.0.2.27", 2),
    ("continuity", "remote", "203.0.113.79", 4),
)
CONFIRMATION_FAMILIES = (
    ("repeated_mfa_supported", "REMOTE_ACCESS", "standard", "bound-repeat", "success", False),
    ("repeated_admin_mfa", "REMOTE_ACCESS", "restricted", "bound-repeat", "success", False),
    ("seven_assets_after_mfa", "REMOTE_ACCESS", "restricted", "bound-busy", "success", False),
    ("remote_no_required_mfa", "REMOTE_ACCESS", "optional", "direct", "not_required", False),
    ("optional_remote_reported_mfa", "REMOTE_ACCESS", "optional", "direct", "success", False),
    ("restricted_read_approved", "READ", "restricted", "direct", "success", False),
    ("read_only_mfa_followup", "READ", "read-only", "bound", "success", False),
    ("optional_read_without_mfa", "READ", "optional", "direct", "not_required", False),
    ("initial_verified_team_access", "REMOTE_ACCESS", "standard", "direct", "success", False),
    ("optional_repeated_mfa", "REMOTE_ACCESS", "optional", "bound-repeat", "success", False),
    ("eight_assets_after_mfa", "REMOTE_ACCESS", "standard", "bound-fanout", "success", True),
    ("nine_assets_after_mfa", "REMOTE_ACCESS", "standard", "bound-peak", "success", True),
    ("read_after_operator_revocation", "READ", "read-only", "revoked", "success", True),
    ("remote_revoked_optional_mfa", "REMOTE_ACCESS", "optional", "revoked", "success", True),
    (
        "compromised_device_after_mfa",
        "REMOTE_ACCESS",
        "standard",
        "bound-compromised",
        "success",
        True,
    ),
    ("disabled_subject_after_mfa", "REMOTE_ACCESS", "standard", "bound-inactive", "success", True),
    ("unmanaged_device_on_protected_read", "READ", "read-only", "bound-unmanaged", "success", True),
    ("wrong_bound_read_response", "READ", "read-only", "wrong", "success", True),
    ("remote_missing_bound_response", "REMOTE_ACCESS", "standard", "absent", "success", True),
    ("read_failed_required_mfa", "READ", "read-only", "bound", "failed", True),
)
CONFIRMATION_PROFILES = (
    ("night-shift", "vpn", "198.51.100.96", 6),
    ("field-operations", "remote", "203.0.113.144", 2),
)
MFA_VALIDATION_FAMILIES = (
    ("repeated_managed_remote", "REMOTE_ACCESS", "standard", "bound-repeat", "success", False),
    ("repeated_privileged_remote", "REMOTE_ACCESS", "restricted", "bound-repeat", "success", False),
    ("verified_privileged_read", "READ", "restricted", "bound", "success", False),
    ("accepted_required_remote", "REMOTE_ACCESS", "standard", "bound", "success", False),
    (
        "verified_after_prior_success",
        "REMOTE_ACCESS",
        "standard",
        "bound-existing-mfa",
        "success",
        False,
    ),
    ("normal_seven_resource_remote", "REMOTE_ACCESS", "standard", "bound-busy", "success", False),
    ("optional_mfa_success_remote", "REMOTE_ACCESS", "optional", "bound", "success", False),
    ("optional_mfa_unknown_read", "READ", "optional", "direct", "unknown", False),
    ("ordinary_privileged_remote", "REMOTE_ACCESS", "restricted", "direct", "success", False),
    ("ordinary_optional_remote", "REMOTE_ACCESS", "optional", "direct", "unknown", False),
    (
        "missing_third_response",
        "REMOTE_ACCESS",
        "standard",
        "bound-repeat-missing",
        "success",
        True,
    ),
    (
        "mismatched_third_response",
        "REMOTE_ACCESS",
        "standard",
        "bound-repeat-wrong",
        "success",
        True,
    ),
    ("missing_protected_read_response", "READ", "read-only", "absent", "success", True),
    ("mismatched_protected_remote_response", "REMOTE_ACCESS", "standard", "wrong", "success", True),
    ("failed_protected_remote_response", "REMOTE_ACCESS", "standard", "bound", "failed", True),
    ("failed_direct_protected_read", "READ", "read-only", "direct", "failed", True),
    (
        "fanout_after_matching_challenge",
        "REMOTE_ACCESS",
        "standard",
        "bound-fanout",
        "success",
        True,
    ),
    ("withdrawn_remote_permission", "REMOTE_ACCESS", "standard", "revoked", "success", True),
    (
        "unmanaged_remote_after_challenge",
        "REMOTE_ACCESS",
        "standard",
        "bound-unmanaged",
        "success",
        True,
    ),
    (
        "inactive_remote_after_challenge",
        "REMOTE_ACCESS",
        "standard",
        "bound-inactive",
        "success",
        True,
    ),
)
MFA_VALIDATION_PROFILES = (
    ("engineering-gateway", "vpn", "192.0.2.56", 3),
    ("continuity-gateway", "remote", "203.0.113.162", 5),
)
REMOTE_TRIAGE_FAMILIES = (
    ("privileged_initial_review", "REMOTE_ACCESS", "restricted", "direct", "success", False),
    ("privileged_matching_response", "REMOTE_ACCESS", "restricted", "bound", "success", False),
    ("optional_mfa_repeat_review", "REMOTE_ACCESS", "optional", "bound-repeat", "success", False),
    (
        "ordinary_worker_repeat_review",
        "REMOTE_ACCESS",
        "standard",
        "bound-repeat",
        "success",
        False,
    ),
    (
        "privileged_busy_below_threshold",
        "REMOTE_ACCESS",
        "restricted",
        "bound-busy",
        "success",
        False,
    ),
    ("optional_mfa_no_enrollment", "REMOTE_ACCESS", "optional", "direct", "not_required", False),
    ("privileged_protected_read", "READ", "restricted", "bound", "success", False),
    ("same_scope_protected_read", "READ", "read-only", "bound", "success", False),
    ("optional_read_no_observation", "READ", "optional", "direct", "unknown", False),
    (
        "successful_prior_mfa_and_response",
        "REMOTE_ACCESS",
        "standard",
        "bound-existing-mfa",
        "success",
        False,
    ),
    ("withdrawn_protected_read", "READ", "read-only", "revoked", "success", True),
    ("revoked_remote_with_success", "REMOTE_ACCESS", "standard", "revoked", "success", True),
    ("third_response_absent", "REMOTE_ACCESS", "standard", "bound-repeat-missing", "success", True),
    (
        "third_response_mismatched",
        "REMOTE_ACCESS",
        "standard",
        "bound-repeat-wrong",
        "success",
        True,
    ),
    ("read_response_mismatched", "READ", "read-only", "wrong", "success", True),
    ("remote_initial_mfa_failure", "REMOTE_ACCESS", "standard", "direct", "failed", True),
    ("devices_and_fanout_eight", "REMOTE_ACCESS", "standard", "bound-fanout", "success", True),
    ("devices_and_fanout_nine", "REMOTE_ACCESS", "standard", "bound-peak", "success", True),
    (
        "compromised_remote_device",
        "REMOTE_ACCESS",
        "standard",
        "bound-compromised",
        "success",
        True,
    ),
    ("scope_restricted_to_read", "REMOTE_ACCESS", "standard", "bound-denied", "success", True),
)
REMOTE_TRIAGE_PROFILES = (
    ("support-access", "vpn", "198.51.100.113", 4),
    ("service-recovery", "remote", "203.0.113.32", 1),
)
COHORTS = {
    "initial": (FAMILIES, PROFILES, 6211709, "L"),
    "followup": (FOLLOWUP_FAMILIES, FOLLOWUP_PROFILES, 4190013, "H"),
    "confirmation": (CONFIRMATION_FAMILIES, CONFIRMATION_PROFILES, 679331, "C"),
    "mfa-validation": (MFA_VALIDATION_FAMILIES, MFA_VALIDATION_PROFILES, 761109, "M"),
    "remote-triage": (REMOTE_TRIAGE_FAMILIES, REMOTE_TRIAGE_PROFILES, 994017, "T"),
}


def git(*args):
    return subprocess.check_output(["git", *args])


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as out:
        json.dump(value, out, ensure_ascii=False, indent=2, sort_keys=True)
        out.write("\n")


def read(path):
    return json.loads(path.read_bytes())


def verify_product(revision):
    subprocess.run(["git", "diff", "--exit-code", revision, "--", "app"], check=True)


def freeze(directory, reference, candidate, cohort):
    reference = (
        git("rev-parse", "--verify", "--end-of-options", f"{reference}^{{commit}}").decode().strip()
    )
    candidate = (
        git("rev-parse", "--verify", "--end-of-options", f"{candidate}^{{commit}}").decode().strip()
    )
    verify_product(candidate)
    directory.mkdir()
    scenarios = []
    families, profiles, seed, prefix = COHORTS[cohort]
    for family, action, resource, workflow, mfa, threat in families:
        for profile, method, ip, distinct in profiles:
            role = "administrator" if resource == "restricted" and not threat else "employee"
            scenarios.append(
                (
                    {
                        "profile": profile,
                        "method": method,
                        "ip": ip,
                        "distinct": distinct,
                        "action": action,
                        "resource": resource,
                        "workflow": workflow,
                        "mfa": mfa,
                        "role": role,
                    },
                    {"family": family, "threat": threat},
                )
            )

    random.Random(seed).shuffle(scenarios)
    cases, truth = {}, {}
    for index, (case, label) in enumerate(scenarios, 1):
        case_id = f"{prefix}{index:03}"
        cases[case_id], truth[case_id] = case, label
    write(directory / "truth.json", truth)
    write(
        directory / "plan.json",
        {
            "cases": cases,
            "candidate": candidate,
            "reference": reference,
            "cohort": cohort,
            "truth_sha256": fingerprint(directory / "truth.json"),
            "harness_sha256": fingerprint(Path(__file__)),
            "scope": "new_local_controlled_signed_session_holdout",
        },
    )
    print(fingerprint(directory / "plan.json"))


def local_policy(profile):
    rules = (
        ("standard", ["employee", "administrator"], ["READ", "REMOTE_ACCESS"], True),
        ("optional", ["employee", "administrator"], ["READ", "REMOTE_ACCESS"], False),
        ("restricted", ["administrator"], ["READ", "REMOTE_ACCESS"], True),
        ("read-only", ["employee"], ["READ"], True),
    )
    return {
        "version": f"remote-holdout-{profile}-1",
        "resources": [
            {
                "resource_id": f"{profile}-{resource}",
                "resource_type": "document",
                "sensitivity": "internal",
                "roles": roles,
                "actions": actions,
                "require_mfa": mfa,
                "require_managed": True,
            }
            for resource, roles, actions, mfa in rules
        ],
    }


def collect(lab, case_id, case):
    workflow = case["workflow"]
    initial_mfa = "unknown"
    if workflow in {"direct", "revoked"}:
        initial_mfa = case["mfa"]
    if workflow == "bound-existing-mfa":
        initial_mfa = "success"
    session_id = f"holdout-session-{case_id}"
    event = SecurityEvent.model_validate(
        {
            "event_id": f"holdout-event-{case_id}-1",
            "timestamp": datetime.now(UTC),
            "user": {"user_id": "local-user", "role": case["role"], "active": True},
            "device": {"device_id": "local-device", "managed": True, "security_posture": "healthy"},
            "network": {
                "ip": case["ip"],
                "location": "local-holdout",
                "access_method": case["method"],
            },
            "resource": {
                "resource_id": f"{case['profile']}-{case['resource']}",
                "resource_type": "document",
                "sensitivity": "internal",
            },
            "action": case["action"],
            "behavior": {"distinct_resources_10m": case["distinct"]},
            "auth_context": {
                "authentication_result": "success",
                "mfa": initial_mfa,
                "failed_attempts": int(initial_mfa == "failed"),
            },
        }
    )
    signal = lab.sign(event, session_id)
    first = lab.service.evaluate_signed(signal, lab.principal).session
    if workflow == "direct":
        return signal
    previous = first
    challenge = None
    if workflow == "revoked":
        previous = lab.service.revoke(
            session_id,
            SessionRevocationRequest(
                expected_version=first.version,
                note="Predeclared local access withdrawal",
            ),
            lab.principal,
        )
    else:
        if not first.challenge_id:
            raise ValueError(f"{case_id}: no server challenge")
        if workflow.startswith("bound"):
            challenge = first.challenge_id
        elif workflow == "wrong":
            # Submit a deterministic placeholder instead of the issued challenge.
            challenge = hashlib.sha256(case_id.encode()).hexdigest()
    event = event.model_copy(
        update={
            "event_id": f"holdout-event-{case_id}-2",
            "timestamp": max(datetime.now(UTC), previous.observed_at + timedelta(microseconds=1)),
            "auth_context": event.auth_context.model_copy(
                update={
                    "mfa": case["mfa"],
                    "failed_attempts": int(case["mfa"] == "failed"),
                }
            ),
        }
    )
    resource_counts = {"bound-busy": 7, "bound-fanout": 8, "bound-peak": 9}
    if workflow in resource_counts:
        event.behavior = event.behavior.model_copy(
            update={"distinct_resources_10m": resource_counts[workflow]}
        )
    if workflow == "bound-unmanaged":
        event.device = event.device.model_copy(update={"managed": False})
    if workflow == "bound-compromised":
        event.device = event.device.model_copy(update={"security_posture": "compromised"})
    if workflow == "bound-inactive":
        event.user = event.user.model_copy(update={"active": False})
    if workflow in {"bound-denied", "bound-unregistered"}:
        target = "read-only" if workflow == "bound-denied" else "unregistered"
        event.resource = event.resource.model_copy(
            update={"resource_id": f"{case['profile']}-{target}"}
        )
    signal = lab.sign(event, session_id, previous.version, challenge_id=challenge)
    result = lab.service.evaluate_signed(signal, lab.principal)
    if workflow.startswith("bound-repeat"):
        latest = result.session
        if latest.challenge_id is None:
            raise ValueError(f"{case_id}: expected a pending review challenge")
        final = event.model_copy(
            update={
                "event_id": f"holdout-event-{case_id}-3",
                "timestamp": max(datetime.now(UTC), latest.observed_at + timedelta(microseconds=1)),
            }
        )
        challenge = latest.challenge_id
        if workflow == "bound-repeat-missing":
            challenge = None
        elif workflow == "bound-repeat-wrong":
            challenge = hashlib.sha256(case_id.encode()).hexdigest()
        signal = lab.sign(final, session_id, latest.version, challenge_id=challenge)
        lab.service.evaluate_signed(signal, lab.principal)
    return signal


class LocalModelStub:
    """Keep provider output constant to isolate changes in the deterministic gate."""

    async def analyze(self, event):
        return SecurityAssessment(
            risk_score=10,
            risk_level="LOW",
            violation_type="NORMAL",
            rationale="Constant local control response.",
            evidence=["action"],
            recommended_action="ALLOW",
            confidence=0.8,
            requires_human_review=True,
        )

    async def analyze_with_evidence(self, event, context):
        return await self.analyze(event)


async def capture(directory):
    plan_path = directory / "plan.json"
    plan = read(plan_path)
    verify_product(plan["candidate"])
    if plan["harness_sha256"] != fingerprint(Path(__file__)):
        raise ValueError("frozen harness changed")
    old = ModuleType("local_previous_hybrid")
    # The baseline is read from the fixed, trusted local repository revision.
    baseline = git("show", f"{plan['reference']}:{ANALYZER}")
    exec(compile(baseline, ANALYZER, "exec"), old.__dict__)  # noqa: S102
    before = old.HybridAnalyzer(replay_settings(), LocalModelStub())
    after = HybridAnalyzer(replay_settings(), LocalModelStub())
    rows, observations = {"reference": [], "candidate": []}, {}
    with TemporaryDirectory(prefix="remote-holdout-") as scratch:
        labs = {}
        for profile in sorted({case["profile"] for case in plan["cases"].values()}):
            with patch.object(
                lab_support, "remote_policy_bundle", return_value=local_policy(profile)
            ):
                labs[profile] = lab_support.LocalSessionAnalysisLab(Path(scratch) / profile)
        for case_id, case in plan["cases"].items():
            lab = labs[case["profile"]]
            signed = collect(lab, case_id, case)
            context = collect_session_evidence(lab.service, signed, lab.principal)
            history = lab.service.history(signed.session_id, lab.principal)
            facts = context.for_event(signed.event)
            observations[case_id] = {
                "session_id": signed.session_id,
                "event_id": signed.event.event_id,
                "event_sha256": event_digest(signed.event),
                "policy": facts["policy"],
                "signal": facts["signal"],
                "session": facts["session"],
                "collected_at": facts["collected_at"],
                "history": [
                    item.model_dump(
                        mode="json",
                        include={
                            "version",
                            "event_id",
                            "observed_at",
                            "evaluated_at",
                            "decision",
                            "status",
                            "reason_codes",
                            "input_digest_sha256",
                            "policy_digest_sha256",
                        },
                    )
                    for item in history
                ],
            }
            for arm, analyzer in (("reference", before), ("candidate", after)):
                result = await analyzer.analyze_with_evidence(signed.event, context)
                rows[arm].append(
                    {
                        "id": case_id,
                        "prediction": prediction(result),
                        "type": result.violation_type.value,
                        "evidence": result.evidence,
                    }
                )
            if lab.service.history(signed.session_id, lab.principal) != history:
                raise ValueError("analyzing unexpectedly changed the approval journal")
    write(directory / "observations.json", observations)
    packet = directory / "predictions.json"
    write(
        packet,
        {
            "plan_sha256": fingerprint(plan_path),
            "observations_sha256": fingerprint(directory / "observations.json"),
            "rows": rows,
        },
    )
    print(fingerprint(packet))


def score(directory, sealed_hash):
    packet_path = directory / "predictions.json"
    if fingerprint(packet_path) != sealed_hash:
        raise ValueError("prediction seal mismatch")
    packet = read(packet_path)
    plan_path = directory / "plan.json"
    if fingerprint(plan_path) != packet["plan_sha256"]:
        raise ValueError("frozen plan changed")
    if fingerprint(directory / "observations.json") != packet["observations_sha256"]:
        raise ValueError("captured observations changed")
    plan = read(plan_path)
    truth_path = directory / "truth.json"
    if fingerprint(truth_path) != plan["truth_sha256"]:
        raise ValueError("frozen truth changed")
    truth = read(truth_path)
    if set(truth) != set(plan["cases"]):
        raise ValueError("frozen IDs differ")
    scored = {}
    for arm in ("reference", "candidate"):
        if len(packet["rows"][arm]) != len(truth) or {r["id"] for r in packet["rows"][arm]} != set(
            truth
        ):
            raise ValueError(f"{arm} prediction coverage mismatch")
        scored[arm] = [{**r, "truth": truth[r["id"]]["threat"]} for r in packet["rows"][arm]]
    comparison = compare_rows(scored["reference"], scored["candidate"])
    families = {
        name: compare_rows(
            *(
                [row for row in scored[arm] if truth[row["id"]]["family"] == name]
                for arm in ("reference", "candidate")
            )
        )
        for name in sorted({label["family"] for label in truth.values()})
    }
    result = {
        "candidate": plan["candidate"],
        "reference": plan["reference"],
        "truth_sha256": plan["truth_sha256"],
        "predictions_sha256": sealed_hash,
        "plan_sha256": packet["plan_sha256"],
        "scope": plan["scope"],
        "cohort": plan.get("cohort", "initial"),
        "provider_calls": 0,
        "comparison": comparison,
        "families": families,
    }
    write(directory / "report.json", result)
    print(json.dumps(comparison, ensure_ascii=False))


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("phase", choices=("freeze", "capture", "score"))
    cli.add_argument("directory", type=Path)
    cli.add_argument("--prediction-sha256")
    cli.add_argument("--reference", default=REFERENCE)
    cli.add_argument("--candidate", default=CANDIDATE)
    cli.add_argument("--cohort", choices=tuple(COHORTS), default="initial")
    args = cli.parse_args()
    if args.phase == "freeze":
        freeze(args.directory, args.reference, args.candidate, args.cohort)
    elif args.phase == "capture":
        asyncio.run(capture(args.directory))
    else:
        if not args.prediction_sha256:
            cli.error("score requires --prediction-sha256")
        score(args.directory, args.prediction_sha256)
