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
from datetime import UTC, datetime
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


def verify_product():
    subprocess.run(["git", "diff", "--exit-code", CANDIDATE, "--", "app"], check=True)


def freeze(directory):
    verify_product()
    directory.mkdir()
    scenarios = []
    for family, action, resource, workflow, mfa, threat in FAMILIES:
        for profile, method, ip, distinct in PROFILES:
            role = "administrator" if family == "authorized_restricted_role" else "employee"
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

    random.Random(6211709).shuffle(scenarios)
    cases, truth = {}, {}
    for index, (case, label) in enumerate(scenarios, 1):
        case_id = f"L{index:03}"
        cases[case_id], truth[case_id] = case, label
    write(directory / "truth.json", truth)
    write(
        directory / "plan.json",
        {
            "cases": cases,
            "candidate": CANDIDATE,
            "reference": REFERENCE,
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
                "mfa": case["mfa"] if workflow in {"direct", "revoked"} else "unknown",
                "failed_attempts": int(case["mfa"] == "failed"),
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
        if workflow == "bound":
            challenge = first.challenge_id
        elif workflow == "wrong":
            # Submit a deterministic placeholder instead of the issued challenge.
            challenge = hashlib.sha256(case_id.encode()).hexdigest()
    event = event.model_copy(
        update={
            "event_id": f"holdout-event-{case_id}-2",
            "timestamp": datetime.now(UTC),
            "auth_context": event.auth_context.model_copy(update={"mfa": case["mfa"]}),
        }
    )
    signal = lab.sign(event, session_id, previous.version, challenge_id=challenge)
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
    verify_product()
    plan_path = directory / "plan.json"
    plan = read(plan_path)
    if plan["harness_sha256"] != fingerprint(Path(__file__)):
        raise ValueError("frozen harness changed")
    old = ModuleType("local_previous_hybrid")
    # The baseline is read from the fixed, trusted local repository revision.
    exec(compile(git("show", f"{REFERENCE}:{ANALYZER}"), ANALYZER, "exec"), old.__dict__)  # noqa: S102
    before = old.HybridAnalyzer(replay_settings(), LocalModelStub())
    after = HybridAnalyzer(replay_settings(), LocalModelStub())
    rows, observations = {"reference": [], "candidate": []}, {}
    with TemporaryDirectory(prefix="remote-holdout-") as scratch:
        labs = {}
        for profile, *_ in PROFILES:
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
    args = cli.parse_args()
    if args.phase == "freeze":
        freeze(args.directory)
    elif args.phase == "capture":
        asyncio.run(capture(args.directory))
    else:
        if not args.prediction_sha256:
            cli.error("score requires --prediction-sha256")
        score(args.directory, args.prediction_sha256)
