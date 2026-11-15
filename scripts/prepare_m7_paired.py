"""Capture and verify the matched 200-session OIDC evaluation cohort."""

import argparse
import json
import re
import secrets
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from scripts import evaluate_m6 as m6
from scripts import prepare_m7 as m7
from scripts.local_oidc_capture import capture_cases
from scripts.prepare_m7_local import DOCUMENTS, ROOT, VAULT, check_observation, jsonl

VARIANTS = 20
ALLOW = ("valid", "issued", 200, "ACCESS_GRANTED")
EXPIRED = ("expired", "issued", 401, None)
FLOWS = {
    "successful_access": (ALLOW,),
    "expired_credential": (EXPIRED,),
    "access_after_valid_retry": (EXPIRED, ALLOW),
    "invalid_grant": (("valid", "invalid", 403, "GRANT_INVALID"),),
    "consumed_grant": (ALLOW, ("valid", "issued", 403, "GRANT_ALREADY_USED")),
}
PRIOR = {
    "development": ROOT / "infra/m7/pilot/development.jsonl",
    "pilot_evaluation": ROOT / "infra/m7/pilot/evaluation.jsonl",
    "prior_public_holdout": ROOT / "runtime/m7/final-holdout/observations.jsonl",
    "prior_local_200": ROOT / "runtime/m7/local-oidc-evaluation/observations.jsonl",
    "public_policy_denial_12": ROOT / "runtime/m7/evidence-verified-holdout/observations.jsonl",
}
ORIGINS = {"first": "192.0.2.10", "second": "192.0.2.20"}
GRANT = "/zero-trust/signals/evaluate"
ACCESS = "/zero-trust/protected-access"
CAPTURE_FIELDS = {"observed_origin", "operation", "method", "requested_resource", "requested_action"}
REQUEST_FIELDS = {"case_id", "events", "evidence_ids", "labels", "question"}
EVENT_FIELDS = {
    "evidence_id", "operation", "http_method", "http_status", "resource", "action",
    "origin", "registered_account", "endpoint_account", "verified_account", "reason_code",
    "content_present",
}
QUESTION = (
    "Classify the access activity as normal, threat, or unknown using the supplied events in order. "
    "The first event evaluates a signed session and subsequent events request the protected operation. "
    "Origin and account aliases are local to the session. registered_account describes device inventory, "
    "endpoint_account describes workstation login context, and verified_account is the principal "
    "accepted by the API. Null means unavailable. A successful or failed HTTP request is not itself "
    "evidence that the caller was authorized or attempting misuse."
)
SCOPE = (
    "Controlled local OIDC and protected-access fixture. FastAPI JWT verification, protected-resource "
    "responses, and SQLite access journal are exercised in-process. Client origin and account context "
    "come from the lab driver and predeclared inventory, not production telemetry."
)


def plan_case(pair_id, case_id, family, variant, label):
    resource, action = ((DOCUMENTS, "READ"), (VAULT, "READ"), (VAULT, "DOWNLOAD"))[variant % 3]
    owner = case_id + "-a"
    peer = case_id + "-b"
    actor = owner if label == "normal" else peer
    endpoint_context = (
        {"registered_account": actor, "endpoint_account": None},
        {"registered_account": peer, "endpoint_account": actor},
        {"registered_account": owner, "endpoint_account": actor},
    )
    # Start from a shared workstation in both cases so the presence of a second account is neutral.
    inventory = {
        ORIGINS["first"]: {"registered_account": peer, "endpoint_account": owner},
        ORIGINS["second"]: endpoint_context[((variant - 1) // 3) % len(endpoint_context)],
    }
    attempts = []
    for index, (bearer, grant, status, reason) in enumerate(FLOWS[family]):
        setup = family == "consumed_grant" and index == 0
        attempts.append({
            "bearer": bearer, "grant_kind": grant, "origin": "first" if setup else "second",
            "actor": owner if setup else actor, "expected_status": status, "expected_reason": reason,
        })
    return {
        "case_id": case_id, "session_id": m7.session_id_for("m7-paired-oidc-v1:" + case_id),
        "pair_id": pair_id, "family": family, "variant": variant, "expected_label": label,
        "owner_id": owner, "attacker_id": peer, "tenant_id": case_id + "-tenant",
        "account_id": case_id + "-account", "device_id": case_id + "-device",
        "resource_id": resource, "action": action,
        "account_role": "administrator" if resource == VAULT else "employee",
        "origins": ORIGINS, "origin_inventory": inventory, "attempts": attempts,
    }


def create_plan():
    cases = []
    for family in FLOWS:
        for variant in range(1, VARIANTS + 1):
            pair_id = "pair-" + secrets.token_hex(12)
            for label in ("normal", "threat"):
                cases.append(plan_case(pair_id, "oidc-" + secrets.token_hex(12), family, variant, label))
    return sorted(cases, key=lambda case: case["session_id"])


def verify_plan(plan):
    expected = Counter((family, variant, label) for family in FLOWS
                       for variant in range(1, VARIANTS + 1) for label in ("normal", "threat"))
    actual = Counter((row["family"], row["variant"], row["expected_label"]) for row in plan)
    if actual != expected or len({row["case_id"] for row in plan}) != len(plan):
        raise ValueError("paired_plan_coverage")
    for case in plan:
        if (not re.fullmatch(r"oidc-[0-9a-f]{24}", case["case_id"])
                or not re.fullmatch(r"pair-[0-9a-f]{24}", case["pair_id"])
                or case != plan_case(case["pair_id"], case["case_id"], case["family"],
                                     case["variant"], case["expected_label"])):
            raise ValueError("paired_plan_mismatch")


def verify_capture(case, capture):
    if (set(capture) != {"case_id", "policy_digest_sha256", "grant", "attempts"}
            or capture["case_id"] != case["case_id"]
            or not re.fullmatch(r"[0-9a-f]{64}", capture["policy_digest_sha256"])
            or len(capture["attempts"]) != len(case["attempts"])):
        raise ValueError("paired_capture_mismatch")
    expected_grant = {"origin": "first", "expected_status": 200, "expected_reason": None}
    for index, (expected, observed) in enumerate(zip(
        [expected_grant, *case["attempts"]], [capture["grant"], *capture["attempts"]], strict=True,
    )):
        status = expected["expected_status"]
        if (not CAPTURE_FIELDS <= observed.keys()
                or observed["observed_origin"] != case["origins"][expected["origin"]]
                or observed["operation"] != (GRANT if index == 0 else ACCESS)
                or observed["method"] != "POST"
                or observed["requested_resource"] != case["resource_id"]
                or observed["requested_action"] != case["action"]):
            raise ValueError("paired_capture_request")
        check_observation(
            {key: value for key, value in observed.items() if key not in CAPTURE_FIELDS},
            status=status, subject=None if status == 401 else case["owner_id"],
            tenant=None if status == 401 else case["tenant_id"],
            reason=expected["expected_reason"], is_grant=index == 0,
        )


def model_request(session_id, inventory, capture):
    accounts, origins, events = {}, {}, []
    for index, observed in enumerate([capture["grant"], *capture["attempts"]], 1):
        origin = observed["observed_origin"]
        origins.setdefault(origin, f"origin-{len(origins) + 1}")
        event = {
            "evidence_id": m7.evidence_id_for(session_id, index),
            "operation": observed["operation"], "http_method": observed["method"],
            "http_status": observed["http_status"], "resource": observed["requested_resource"],
            "action": observed["requested_action"], "origin": origins[origin],
            "reason_code": observed["reason_code"], "content_present": observed["content_present"],
        }
        fields = {"verified_account": observed["authenticated_subject"], **inventory[origin]}
        for field, value in fields.items():
            event[field] = accounts.setdefault(value, f"account-{len(accounts) + 1}") if value else None
        events.append(event)
    return {
        "case_id": session_id, "events": events, "evidence_ids": [event["evidence_id"] for event in events],
        "labels": m6.LABELS, "question": QUESTION,
    }


def verify_overlap(requests, prior_paths):
    session_ids = {row["case_id"] for row in requests}
    evidence_ids = {value for row in requests for value in row["evidence_ids"]}
    if len(session_ids) != len(requests) or len(evidence_ids) != sum(len(row["events"]) for row in requests):
        raise ValueError("paired_duplicate_ids")
    overlap = {}
    for name, path in prior_paths.items():
        data = path.read_bytes()
        rows = [json.loads(line) for line in data.splitlines()]
        old_sessions = {row["session_id"] for row in rows}
        old_evidence = {event["evidence_id"] for row in rows for event in row["events"]}
        if session_ids & old_sessions or evidence_ids & old_evidence:
            raise ValueError("paired_prior_overlap")
        overlap[name] = {"sha256": m7.sha(data), "sessions": 0, "evidence_ids": 0}
    return overlap


def operation_signature(request):
    fields = ("operation", "http_method", "resource", "action", "http_status", "reason_code", "content_present")
    return tuple(tuple(event[field] for field in fields) for event in request["events"])


def build_bundle(plan, captures, prior_paths=PRIOR):
    verify_plan(plan)
    by_case = {row["case_id"]: row for row in captures}
    if len(by_case) != len(captures) or set(by_case) != {case["case_id"] for case in plan}:
        raise ValueError("paired_capture_ids")
    requests, scores, sizes = [], [], []
    pairs = defaultdict(list)
    status_counts = defaultdict(Counter)
    account_count_labels = defaultdict(Counter)
    relationship_baseline_correct = 0
    for case in sorted(plan, key=lambda row: row["session_id"]):
        capture = by_case[case["case_id"]]
        verify_capture(case, capture)
        request = model_request(case["session_id"], case["origin_inventory"], capture)
        encoded = m6.canonical(request)
        if (set(request) != REQUEST_FIELDS or request["labels"] != m6.LABELS
                or any(set(event) != EVENT_FIELDS for event in request["events"])
                or len(encoded) > 4096):
            raise ValueError("paired_request_schema")
        requests.append(request)
        sizes.append(len(encoded))
        label = "normal" if case["attempts"][-1]["actor"] == case["owner_id"] else "threat"
        scores.append({
            "session_id": case["session_id"], "pair_id": case["pair_id"], "expected_label": label,
            "scenario": case["family"], "input_sha256": m6.digest(encoded),
        })
        signature = operation_signature(request)
        observed = [{key: value for key, value in event.items() if key != "evidence_id"}
                    for event in request["events"]]
        pairs[case["pair_id"]].append((case, signature, observed))
        status_counts[tuple(event["http_status"] for event in request["events"])][label] += 1
        accounts = {event[field] for event in request["events"]
                    for field in ("registered_account", "endpoint_account", "verified_account")}
        account_count_labels[len(accounts - {None})][label] += 1
        first, last = observed[0], observed[-1]
        endpoint_account = last["endpoint_account"] or last["registered_account"]
        baseline_label = "normal" if endpoint_account == first["verified_account"] else "threat"
        relationship_baseline_correct += baseline_label == label

    for left, right in pairs.values():
        one, one_signature, one_events = left
        other, other_signature, other_events = right
        if (one_signature != other_signature or one_events == other_events
                or (one["family"], one["variant"]) != (other["family"], other["variant"])
                or one["expected_label"] == other["expected_label"]):
            raise ValueError("paired_matching_failed")
    if len(pairs) != len(FLOWS) * VARIANTS:
        raise ValueError("paired_pair_count")
    if any(group["normal"] != group["threat"] for group in account_count_labels.values()):
        raise ValueError("paired_account_count_shortcut")

    files = {
        "model-requests.jsonl": jsonl(requests),
        "private/scoring-labels.jsonl": jsonl(scores),
        "private/plan.jsonl": jsonl(plan),
        "private/evidence.jsonl": jsonl(captures),
    }
    labels = dict(Counter(row["expected_label"] for row in scores))
    manifest = {
        "schema": "m7-paired-oidc-1", "scope": SCOPE,
        "sessions": len(requests), "pairs": len(pairs), "labels": labels,
        "events": sum(len(request["events"]) for request in requests),
        "pair_checks": {
            "operation_method_resource_action_http_sequence_reason_content_equal": len(pairs),
            "observational_context_differs_ignoring_evidence_ids": len(pairs),
            "pairs_by_scenario": dict(Counter(group[0][0]["family"] for group in pairs.values())),
            "status_sequences": {"/".join(map(str, vector)): dict(counts)
                                 for vector, counts in sorted(status_counts.items())},
            "best_possible_status_only_accuracy": sum(max(group.values()) for group in status_counts.values())
            / len(requests),
            "best_possible_account_count_only_accuracy": (
                sum(max(group.values()) for group in account_count_labels.values()) / len(requests)
            ),
        },
        "prior_overlap": verify_overlap(requests, prior_paths),
        "relationship_baseline": {
            "rule": "Match the final endpoint account (or registered account) to the first verified principal.",
            "correct": relationship_baseline_correct, "sessions": len(requests),
        },
        "model_request_check": {
            "max_bytes": max(sizes), "answer_fields": 0, "pair_fields": 0,
            "timing_fields": 0, "identifier_scope": "session",
        },
        "files": {name: m7.sha(data) for name, data in files.items()},
        "policy_digests": sorted({row["policy_digest_sha256"] for row in captures}),
        "actual_model_calls": 0,
    }
    files["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()
    return files, manifest


def verified_bundle(directory, prior_paths=PRIOR):
    plan, captures = ([json.loads(line) for line in (directory / name).read_bytes().splitlines()]
                      for name in ("private/plan.jsonl", "private/evidence.jsonl"))
    files, manifest = build_bundle(plan, captures, prior_paths)
    if any((directory / name).read_bytes() != data for name, data in files.items()):
        raise ValueError("paired_bundle_changed")
    return files, manifest


def prepare(directory):
    if directory.exists():
        raise ValueError("paired_output_exists")
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory.parent, prefix=".m7-paired-") as temporary:
        stage = Path(temporary) / "bundle"
        (stage / "private").mkdir(parents=True, mode=0o700)
        stage.chmod(0o700)
        plan = create_plan()
        frozen = stage / "private/plan.jsonl"
        frozen.write_bytes(jsonl(plan))
        frozen.chmod(0o600)
        captures = capture_cases(plan, Path(temporary))
        files, manifest = build_bundle(plan, captures)
        if frozen.read_bytes() != files["private/plan.jsonl"]:
            raise ValueError("paired_plan_changed")
        for name, data in files.items():
            path = stage / name
            if path != frozen:
                path.write_bytes(data)
            if path.parent.name == "private":
                path.chmod(0o600)
        stage.rename(directory)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "verify"))
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    manifest = prepare(args.directory) if args.mode == "prepare" else verified_bundle(args.directory)[1]
    print(json.dumps(manifest, ensure_ascii=False))


if __name__ == "__main__":
    main()
