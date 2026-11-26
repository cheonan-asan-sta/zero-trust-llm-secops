"""Audit public MFA and enrollment coverage without assigning takeover labels."""

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from scripts.evaluate_local_remote_holdout import write
from scripts.evaluate_public_login_history import digest

PUBLISHER_ASSETS = {
    "entra-device.jsonl": "7d1c4f09f999747446560f3a4fe6c62247a41f3424b8827aeecff5f765f025b6",
    "entra-login.jsonl": "7de7bf2e60ee2746ab4cabfb714ffc42e7a1d839e7b5f33b2b0d07f228266a86",
    "entra-mfa-method.jsonl": "c99d21c5ffc0a698829aa9be7fc91f10e1ac5154c89dd12d9c16b3a9da1c8cc7",
    "okta-device.jsonl": "f8ec2771496b383efc5e47d3d0686dfa7c6aa182ca9b75761f78e6375341e1b7",
    "okta-mfa.jsonl": "dda3d9c1afb6f538ffd04f666b05f1d386d38620c61cac1e6af504e625951515",
    "external-mfa-fatigue.json": "fdb0f54316f56aa7ef18508282477ba85181a17662ca681c9b090f25086fc3c0",
}

FRESH_PUSH = {"MFA completed in Azure AD", "MFA successfully completed"}


def entra_mfa_completed(row):
    properties = row["properties"]
    return any(
        step.get("authenticationMethod") == "Mobile app notification"
        and step.get("succeeded") is True
        and step.get("authenticationStepResultDetail") in FRESH_PUSH
        for step in properties.get("authenticationDetails") or []
    )


def instant(value):
    stamp = datetime.fromisoformat(value)
    if stamp.utcoffset() is None:
        raise ValueError("provider timestamp requires a time zone")
    return stamp


def complete_identity(*parts):
    if all(isinstance(part, str) and part.strip() for part in parts):
        return parts
    return None


def count_links(signins, enrollments):
    # Both feeds must belong to the same source/scope supplied by the caller.
    # Registration must precede the login. IP, UA and display names never act as keys.
    return sum(
        key is not None
        and any(
            previous == key and registered_at < logged_at for previous, registered_at in enrollments
        )
        for key, logged_at in signins
    )


def entra(rows):
    counts = Counter(
        dict.fromkeys(
            (
                "sign_in_rows",
                "successful_sign_ins",
                "fresh_mfa_step_success_rows",
                "fresh_mfa_success_on_successful_login",
                "success_with_token_claim_only_mfa",
                "sign_ins_with_provider_device_id",
                "successful_device_registration_rows",
                "registrations_with_initiator_and_device_id",
                "fresh_mfa_signins_joined_to_prior_registration",
            ),
            0,
        )
    )
    enrolled, fresh = [], []
    for row in rows:
        properties = row["properties"]
        if row["category"] == "AuditLogs":
            if (
                properties.get("activityDisplayName") != "Register device"
                or properties.get("result") != "success"
            ):
                continue
            counts["successful_device_registration_rows"] += 1
            actor = ((properties.get("initiatedBy") or {}).get("user") or {}).get("id")
            device = [
                x.get("value")
                for x in properties.get("additionalDetails") or []
                if x.get("key") == "Device Id"
            ]
            if len(device) == 1:
                identity = complete_identity(row.get("tenantId"), actor, device[0])
                if identity is not None:
                    counts["registrations_with_initiator_and_device_id"] += 1
                    enrolled.append((identity, instant(row["time"])))
            continue
        if row["category"] not in {"SignInLogs", "NonInteractiveUserSignInLogs"}:
            continue
        counts["sign_in_rows"] += 1
        device = (properties.get("deviceDetail") or {}).get("deviceId")
        counts["sign_ins_with_provider_device_id"] += bool(device)
        fresh_completed = entra_mfa_completed(row)
        counts["fresh_mfa_step_success_rows"] += fresh_completed
        if (
            str(row.get("resultType")) != "0"
            or (properties.get("status") or {}).get("errorCode") != 0
        ):
            continue
        counts["successful_sign_ins"] += 1
        if fresh_completed:
            counts["fresh_mfa_success_on_successful_login"] += 1
            fresh.append(
                (
                    complete_identity(row.get("tenantId"), properties.get("userId"), device),
                    instant(row["time"]),
                )
            )
        elif any(
            str(step.get("authenticationStepResultDetail", "")).casefold()
            == "mfa requirement satisfied by claim in the token"
            for step in properties.get("authenticationDetails") or []
        ):
            counts["success_with_token_claim_only_mfa"] += 1
    counts["fresh_mfa_signins_joined_to_prior_registration"] = count_links(fresh, enrolled)
    return counts


def okta(rows):
    return {
        "device_enrollment_success_rows": sum(
            row.get("eventType") == "device.enrollment.create"
            and (row.get("outcome") or {}).get("result") == "SUCCESS"
            and any(
                target.get("type") == "UDDevice" and target.get("id")
                for target in row.get("target") or []
            )
            for row in rows
        ),
        "mfa_push_actions": sum(
            row.get("eventType") == "system.push.send_factor_verify_push" for row in rows
        ),
        "mfa_factor_outcomes": dict(
            Counter(
                (row.get("outcome") or {}).get("result", "UNAVAILABLE")
                for row in rows
                if row.get("eventType") == "user.authentication.auth_via_mfa"
            )
        ),
        "mfa_outcomes_with_authoritative_device_id": sum(
            bool((row.get("device") or {}).get("id"))
            for row in rows
            if row.get("eventType") == "user.authentication.auth_via_mfa"
        ),
        "session_start_rows": sum(row.get("eventType") == "user.session.start" for row in rows),
    }


def run(directory, output):
    results = {}
    for file, expected in PUBLISHER_ASSETS.items():
        path = directory / file
        if digest(path) != expected:
            raise ValueError(f"publisher digest mismatch for {file}")
        if file.endswith(".jsonl"):
            documents = (
                json.loads(line)
                for line in path.read_text(encoding="utf-8-sig").splitlines()
                if line
            )
            events = [row for doc in documents for row in doc.get("records", [doc])]
            counts = entra(events) if file.startswith("entra-") else okta(events)
            results[file] = {"sha256": expected, "events": len(events), "coverage": counts}
        else:
            data = json.loads(path.read_bytes())
            attempts = data["sign_in_attempts"]
            changes = data["mfa_method_changes"]
            results[file] = {
                "sha256": expected,
                "source_type": "external synthetic fixture",
                "sign_in_attempts": len(attempts),
                "mfa_setup_changes": len(changes),
                "published_origin": dict(Counter(row["origin"] for row in attempts)),
                "attacker_mfa_approved_rows": sum(
                    row["attack_result"] == "approved under fatigue" for row in attempts
                ),
                "attempts_with_session_id": sum(bool(row.get("session_id")) for row in attempts),
                "attempts_with_registered_device_join_key": sum(
                    bool(row.get("device_id")) for row in attempts
                ),
                "changes_with_registered_device_join_key": sum(
                    bool(row.get("device_id")) for row in changes
                ),
            }
    write(output, {"files": results, "takeover_detector_labeled_score_available": False})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    run(args.directory, args.output)
