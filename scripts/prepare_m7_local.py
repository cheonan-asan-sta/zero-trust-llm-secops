"""Capture a balanced local OIDC bearer-verification evaluation dataset."""

import argparse
import json
import re
import secrets
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from scripts import prepare_m7 as m7
from scripts.local_oidc_capture import capture_cases
from scripts.prepare_m7_holdout import verify_requests

ROOT = Path(__file__).resolve().parents[1]
PRIOR = (
    ROOT / "infra/m7/pilot/development.jsonl",
    ROOT / "infra/m7/pilot/evaluation.jsonl",
    ROOT / "runtime/m7/final-holdout/observations.jsonl",
)
VARIANTS = 10
DOCUMENTS = "zt-demo-documents"
VAULT = "zt-demo-vault"
# Each request is declared as (actual fixture actor, bearer mode, grant, HTTP result, policy reason).
ALLOW = ("owner", "valid", "issued", 200, "ACCESS_GRANTED")
FAMILIES = {
    "authorized_document": ("document", (ALLOW,)),
    "authorized_vault_read": ("vault", (ALLOW,)),
    "authorized_vault_download": ("download", (ALLOW,)),
    "legitimate_expiry_retry": ("mixed", (("owner", "expired", "issued", 401, None), ALLOW)),
    "legitimate_missing_retry": ("mixed", (("owner", "missing", "issued", 401, None), ALLOW)),
    "legitimate_audience_retry": ("mixed", (("owner", "wrong_audience", "issued", 401, None), ALLOW)),
    "legitimate_clock_retry": ("mixed", (("owner", "future_nbf", "issued", 401, None), ALLOW)),
    "legitimate_double_submit": ("mixed", (ALLOW, ("owner", "valid", "issued", 403, "GRANT_ALREADY_USED"))),
    "legitimate_expired": ("mixed", (("owner", "expired", "issued", 401, None),)),
    "legitimate_viewer": ("mixed", (("owner", "viewer", "issued", 403, None),)),
    "copied_bearer_and_grant": ("mixed", (("attacker", "valid", "issued", 200, "ACCESS_GRANTED"),)),
    "copied_bearer_invalid_grant": ("mixed", (("attacker", "valid", "invalid", 403, "GRANT_INVALID"),)),
    "forged_signature": ("mixed", (("attacker", "wrong_key", "issued", 401, None),)),
    "altered_claims": ("mixed", (("attacker", "tampered", "issued", 401, None),)),
    "foreign_issuer": ("mixed", (("attacker", "wrong_issuer", "issued", 401, None),)),
    "foreign_audience": ("mixed", (("attacker", "wrong_audience", "issued", 401, None),)),
    "unregistered_key": ("mixed", (("attacker", "unknown_kid", "issued", 401, None),)),
    "copied_expired_bearer": ("mixed", (("attacker", "expired", "issued", 401, None),)),
    "cross_tenant_grant": ("mixed", (("attacker", "foreign_tenant", "issued", 403, "GRANT_INVALID"),)),
    "copied_consumed_grant": ("mixed", (ALLOW, ("attacker", "valid", "issued", 403, "GRANT_ALREADY_USED"))),
}
OBSERVED_FIELDS = {
    "http_status", "duration_ms", "authenticated_subject", "authenticated_tenant",
    "content_present", "reason_code", "journal_matches", "since_previous_ms",
}


def planned_case(family, variant, case_id):
    target, steps = FAMILIES[family]
    resource = VAULT if target in {"vault", "download"} or target == "mixed" and variant % 2 == 0 else DOCUMENTS
    action = "DOWNLOAD" if target == "download" or target == "mixed" and variant % 4 == 0 else "READ"
    owner = case_id + "-owner"
    attacker = case_id + "-other"
    tenant = case_id + "-tenant"
    attempts = []
    for actor, bearer, grant, status, reason in steps:
        verified_tenant = tenant + "-other" if bearer == "foreign_tenant" else tenant
        verified_subject = attacker if bearer == "foreign_tenant" else owner
        attempts.append({
            "actor_id": owner if actor == "owner" else attacker,
            "credential_owner_id": (None if bearer in {"missing", "tampered", "wrong_key", "unknown_kid"}
                                    else verified_subject),
            "claimed_subject_id": (None if bearer == "missing" else
                                   attacker if bearer == "tampered" else verified_subject),
            "authorized_actor": actor == "owner",
            "bearer": bearer,
            "grant_kind": grant,
            "expected_status": status,
            "expected_reason": reason,
            "expected_subject": None if status == 401 else verified_subject,
            "expected_tenant": None if status == 401 else verified_tenant,
        })
    return {
        "case_id": case_id,
        "session_id": m7.session_id_for("m7-local-oidc-v1:" + case_id),
        "family": family,
        "variant": variant,
        "expected_label": "normal" if attempts[-1]["authorized_actor"] else "threat",
        "owner_id": owner,
        "attacker_id": attacker,
        "tenant_id": tenant,
        "account_id": case_id + "-account",
        "device_id": case_id + "-device",
        "resource_id": resource,
        "action": action,
        "account_role": "administrator" if resource == VAULT else "employee",
        "attempts": attempts,
    }


def create_plan():
    cases = [planned_case(family, variant, "oidc-" + secrets.token_hex(12))
             for family in FAMILIES for variant in range(1, VARIANTS + 1)]
    secrets.SystemRandom().shuffle(cases)
    return cases


def jsonl(rows):
    return b"".join(m7.canonical(row) + b"\n" for row in rows)


def verify_plan(plan):
    templates = {(family, i) for family in FAMILIES for i in range(1, VARIANTS + 1)}
    if len(plan) != len(templates) or {(row["family"], row["variant"]) for row in plan} != templates:
        raise ValueError("m7_local_plan_coverage")
    ids = {row["case_id"] for row in plan}
    if len(ids) != len(plan) or any(not re.fullmatch(r"oidc-[a-f0-9]{24}", value) for value in ids):
        raise ValueError("m7_local_plan_ids")
    if any(row != planned_case(row["family"], row["variant"], row["case_id"]) for row in plan):
        raise ValueError("m7_local_plan_mismatch")


def check_observation(observed, *, status, subject, tenant, reason, is_grant=False):
    fields = OBSERVED_FIELDS | ({"grant_issued"} if is_grant else set())
    if set(observed) != fields or type(observed["duration_ms"]) is not int or observed["duration_ms"] < 0:
        raise ValueError("m7_local_capture_shape")
    gap = observed["since_previous_ms"]
    if (is_grant and gap is not None) or (not is_grant and (type(gap) is not int or gap < 0)):
        raise ValueError("m7_local_capture_timing")
    if (type(observed["http_status"]) is not int or observed["http_status"] != status
            or observed["authenticated_subject"] != subject or observed["authenticated_tenant"] != tenant
            or observed["reason_code"] != reason or observed["content_present"] is not (status == 200 and not is_grant)):
        raise ValueError("m7_local_capture_outcome")
    if is_grant:
        if observed["grant_issued"] is not True or observed["journal_matches"] is not None:
            raise ValueError("m7_local_capture_grant")
    elif observed["journal_matches"] is not True:
        raise ValueError("m7_local_capture_journal")


def project(case, capture):
    if set(capture) != {"case_id", "policy_digest_sha256", "grant", "attempts"}:
        raise ValueError("m7_local_capture_shape")
    if not re.fullmatch(r"[a-f0-9]{64}", capture["policy_digest_sha256"]):
        raise ValueError("m7_local_policy_digest")
    if capture["case_id"] != case["case_id"] or len(capture["attempts"]) != len(case["attempts"]):
        raise ValueError("m7_local_capture_mismatch")
    check_observation(capture["grant"], status=200, subject=case["owner_id"],
                      tenant=case["tenant_id"], reason=None, is_grant=True)
    for expected, observed in zip(case["attempts"], capture["attempts"], strict=True):
        check_observation(observed, status=expected["expected_status"], subject=expected["expected_subject"],
                          tenant=expected["expected_tenant"], reason=expected["expected_reason"])

    sid = case["session_id"]
    events = [
        m7.EnrichedEvent(
            evidence_id=m7.evidence_id_for(sid, position + 1),
            module="rp", http_method="POST", http_status=step["http_status"], level="INFO",
            duration_ms=step["duration_ms"], auth_stage="authorize" if position == 0 else "access",
            failure_reason=None, since_previous_ms=None,
        ) for position, step in enumerate([capture["grant"], *capture["attempts"]])
    ]
    return m7.EnrichedSession(session_id=sid, events=events)


def prior_overlap(sessions, prior_paths):
    session_ids = {row.session_id for row in sessions}
    event_ids = {event.evidence_id for row in sessions for event in row.events}
    if len(session_ids) != len(sessions) or len(event_ids) != sum(len(row.events) for row in sessions):
        raise ValueError("m7_local_duplicate_ids")
    result = []
    for path in prior_paths:
        source = path.read_bytes()
        known = m7.read_rows(source, m7.EnrichedSession if path.name == "observations.jsonl" else m7.Session)
        sessions_overlap = len(session_ids.intersection(row.session_id for row in known))
        evidence_overlap = len(event_ids.intersection(event.evidence_id for row in known for event in row.events))
        if sessions_overlap or evidence_overlap:
            raise ValueError("m7_local_prior_overlap")
        result.append({"file": path.name, "sha256": m7.sha(source), "sessions": 0, "evidence_ids": 0})
    return result


def build_bundle(plan, captures, prior_paths):
    verify_plan(plan)
    if len(plan) != len(captures):
        raise ValueError("m7_local_capture_count")
    captures_by_case = dict(zip((row["case_id"] for row in plan), captures, strict=True))
    sessions, labels = [], []
    patterns = defaultdict(set)
    outcomes = defaultdict(Counter)
    families = defaultdict(set)
    for case in sorted(plan, key=lambda row: row["session_id"]):
        capture = captures_by_case[case["case_id"]]
        session = project(case, capture)
        sessions.append(session)
        label = case["expected_label"]
        labels.append({"session_id": session.session_id, "expected_label": label})
        signature = tuple((event.module, event.http_method, event.http_status, event.level,
                           event.auth_stage, event.failure_reason) for event in session.events)
        patterns[signature].add(label)
        outcomes[label][str(capture["attempts"][-1]["http_status"])] += 1
        families[label].add(case["family"])
    observations = m7.jsonl(sessions)
    request_check = verify_requests(observations)
    overlaps = prior_overlap(sessions, prior_paths)
    files = {
        "observations.jsonl": observations,
        "private/plan.jsonl": jsonl(plan),
        "private/scoring-labels.jsonl": jsonl(labels),
        "private/evidence.jsonl": jsonl(captures),
    }
    manifest = {
        "schema": "m7-local-oidc-capture-1",
        "scope": "Controlled in-process OIDC bearer verification and application access; local fixture JWKS.",
        "label_source": "Predeclared credential authorization and actor intent in the private controller plan.",
        "timing": "Request durations are measured locally. Fixture inter-request intervals stay in private evidence.",
        "files": {name: m7.sha(data) for name, data in files.items()},
        "cohort": {
            "sessions": len(sessions), "events": sum(len(row.events) for row in sessions),
            "labels": dict(Counter(label["expected_label"] for label in labels)),
            "scenario_templates": {label: len(names) for label, names in sorted(families.items())},
            "terminal_http_by_label": {label: dict(counts) for label, counts in sorted(outcomes.items())},
            "observable_patterns_ignoring_time": len(patterns),
            "patterns_shared_by_both_labels": sum(len(values) > 1 for values in patterns.values()),
        },
        "prior_overlap": overlaps,
        "model_request_check": request_check,
        "policy_digests": sorted({row["policy_digest_sha256"] for row in captures}),
        "actual_model_calls": 0,
    }
    files["manifest.json"] = json.dumps(manifest, ensure_ascii=False, indent=2).encode() + b"\n"
    return files, manifest


def verify_bundle(directory, prior_paths=PRIOR):
    plan, captures = ([json.loads(line) for line in (directory / name).read_bytes().splitlines()]
                      for name in ("private/plan.jsonl", "private/evidence.jsonl"))
    files, manifest = build_bundle(plan, captures, prior_paths)
    if any((directory / name).read_bytes() != data for name, data in files.items()):
        raise ValueError("m7_local_bundle_mismatch")
    return manifest


def prepare(directory, prior_paths=PRIOR):
    directory.mkdir(parents=True, mode=0o700, exist_ok=False)
    private = directory / "private"
    private.mkdir(mode=0o700)
    plan = create_plan()
    # Freeze authorization and scenario truth before starting any request.
    (private / "plan.jsonl").write_bytes(jsonl(plan))
    with tempfile.TemporaryDirectory(prefix="m7-local-oidc-") as scratch:
        captures = capture_cases(plan, Path(scratch))
    (private / "evidence.jsonl").write_bytes(jsonl(captures))
    files, manifest = build_bundle(plan, captures, prior_paths)
    for name, data in files.items():
        if name not in {"private/plan.jsonl", "private/evidence.jsonl"}:
            (directory / name).write_bytes(data)
        if name.startswith("private/"):
            (directory / name).chmod(0o600)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "verify"))
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        operation = prepare if args.mode == "prepare" else verify_bundle
        manifest = operation(args.directory)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"m7 local capture rejected: {type(exc).__name__}\n")
    print(json.dumps(manifest["cohort"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
