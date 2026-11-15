"""Check the development-only contract for missing and adverse session evidence."""

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import StrictBool

from app.models import StrictModel
from scripts.evaluate_m6 import canonical, digest, write_report


class VerifiedEvidence(StrictModel):
    """Facts supplied by trusted policy and verifiers before classification."""

    proof_requirement: Literal["required", "optional", "unknown"]
    proof_state: Literal["absent", "verified", "expired", "unverifiable"]
    identity_binding: Literal["verified", "unconfirmed", "conflicting", "credential_replay"]
    endpoint_scope: Literal["direct", "delegated", "outside_scope", "unconfirmed"]
    verified_violation: Literal["scope_mismatch", "nonce_reuse", "unauthorized_key_rotation"] | None
    verified_device_compromise: StrictBool = False


def assess(evidence: VerifiedEvidence) -> tuple[str, str, str]:
    """Return a verdict, a proposed next check, and a reason without changing access."""
    if evidence.verified_violation is not None:
        return "threat", "restrict", evidence.verified_violation
    if evidence.identity_binding == "credential_replay":
        return "threat", "restrict", "verified_credential_replay"
    if evidence.verified_device_compromise:
        return "threat", "restrict", "verified_device_compromise"
    if evidence.identity_binding == "verified" and evidence.endpoint_scope == "outside_scope":
        return "unknown", "restrict", "verified_use_outside_scope"
    if evidence.proof_requirement == "unknown":
        return "unknown", "revalidate", "proof_requirement_unknown"
    if evidence.proof_state in {"expired", "unverifiable"}:
        return "unknown", "revalidate", f"proof_{evidence.proof_state}"
    if evidence.proof_requirement == "required" and evidence.proof_state == "absent":
        return "unknown", "revalidate", "required_proof_absent"
    if evidence.identity_binding != "verified":
        return "unknown", "revalidate", f"identity_{evidence.identity_binding}"
    if evidence.endpoint_scope == "unconfirmed":
        return "unknown", "revalidate", "endpoint_scope_unconfirmed"
    return "normal", "continue_policy_checks", f"verified_{evidence.endpoint_scope}_use"


def development_cases():
    def case(
        description, label, next_check, reason, *,
        requirement="optional", proof="absent", identity="verified", scope="direct",
        violation=None,
    ):
        return (
            description,
            VerifiedEvidence(
                proof_requirement=requirement,
                proof_state=proof,
                identity_binding=identity,
                endpoint_scope=scope,
                verified_violation=violation,
            ),
            (label, next_check, reason),
        )

    return (
        case("Optional proof absent, direct use confirmed", "normal",
             "continue_policy_checks", "verified_direct_use"),
        case("Optional proof absent, delegation confirmed for this request", "normal",
             "continue_policy_checks", "verified_delegated_use", scope="delegated"),
        case("Optional proof absent, verified actor used an excluded endpoint", "unknown",
             "restrict", "verified_use_outside_scope", scope="outside_scope"),
        case("Optional proof absent, request actor unconfirmed", "unknown",
             "revalidate", "identity_unconfirmed", identity="unconfirmed"),
        case("Conflicting actor bindings with a scope mismatch claim", "unknown",
             "revalidate", "identity_conflicting", identity="conflicting", scope="outside_scope"),
        case("Optional proof absent, delegation scope unconfirmed", "unknown",
             "revalidate", "endpoint_scope_unconfirmed", scope="unconfirmed"),
        case("Required proof absent, direct use otherwise confirmed", "unknown",
             "revalidate", "required_proof_absent", requirement="required"),
        case("Required proof expired, direct use otherwise confirmed", "unknown",
             "revalidate", "proof_expired", requirement="required", proof="expired"),
        case("Required proof unverifiable, delegation otherwise confirmed", "unknown",
             "revalidate", "proof_unverifiable", requirement="required", proof="unverifiable",
             scope="delegated"),
        case("Required proof verified and direct use confirmed", "normal",
             "continue_policy_checks", "verified_direct_use", requirement="required",
             proof="verified"),
        case("Valid proof with independently confirmed out-of-scope use", "unknown",
             "restrict", "verified_use_outside_scope", proof="verified", scope="outside_scope"),
        case("Required proof absent, identity verifier independently confirms credential replay",
             "threat", "restrict", "verified_credential_replay", requirement="required",
             identity="credential_replay"),
        case("Policy requirement unknown despite valid proof and direct use", "unknown",
             "revalidate", "proof_requirement_unknown", requirement="unknown", proof="verified"),
        case("Optional proof submitted but unverifiable", "unknown",
             "revalidate", "proof_unverifiable", proof="unverifiable"),
        case("Independent verifier reports nonce reuse for this exact session", "threat",
             "restrict", "nonce_reuse", violation="nonce_reuse", identity="conflicting"),
        case("Independent verifier confirms proof bound to a different scope", "threat",
             "restrict", "scope_mismatch", violation="scope_mismatch", requirement="required",
             proof="unverifiable"),
        case("Independent verifier confirms unauthorized key rotation", "threat",
             "restrict", "unauthorized_key_rotation", violation="unauthorized_key_rotation",
             proof="unverifiable"),
        case("Required proof verified with unconfirmed delegation scope", "unknown",
             "revalidate", "endpoint_scope_unconfirmed", requirement="required", proof="verified",
             scope="unconfirmed"),
        case("Optional proof submitted but expired", "unknown",
             "revalidate", "proof_expired", proof="expired"),
        case("Optional proof absent, identity verifier independently confirms credential replay",
             "threat", "restrict", "verified_credential_replay", identity="credential_replay"),
    )


def run_development():
    rows = []
    for index, (description, evidence, expected) in enumerate(development_cases(), start=1):
        facts = evidence.model_dump(exclude_defaults=True)
        actual = assess(evidence)
        fields = ("verdict", "next_check", "reason")
        rows.append({
            "case_id": f"proof-dev-{index:02}",
            "description": description,
            "evidence": facts,
            "evidence_sha256": digest(canonical(facts)),
            "expected": dict(zip(fields, expected, strict=True)),
            "actual": dict(zip(fields, actual, strict=True)),
            "passed": actual == expected,
        })
    return {
        "schema": "m6-proof-policy-development-1",
        "scope": "synthetic_development_contract_check",
        "external_model_requests": 0,
        "cases": len(rows),
        "passed": sum(row["passed"] for row in rows),
        "verdict_counts": dict(Counter(row["actual"]["verdict"] for row in rows)),
        "rows": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_development()
    write_report(args.output, report)
    print(json.dumps({key: value for key, value in report.items() if key != "rows"}))
    return int(report["passed"] != report["cases"])


if __name__ == "__main__":
    raise SystemExit(main())
