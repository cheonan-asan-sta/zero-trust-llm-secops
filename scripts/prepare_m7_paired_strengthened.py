"""Freeze the strengthened 100-pair OIDC evaluation cohort and its evidence."""

import argparse
import json
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

from scripts import evaluate_m6 as m6
from scripts import paired_oidc_proof_capture as proof
from scripts import prepare_m7_paired as paired
from scripts.local_oidc_capture import capture_cases
from scripts.prepare_m7_local import jsonl

BASE = paired.ROOT / "runtime/m7/paired-oidc-evaluation"
RETAINED_VARIANTS = 12
HARD_PLAN = "private/hard-plan.jsonl"
HARD_EVIDENCE = "private/hard-app-evidence.jsonl"
PROOF_EVIDENCE = "private/hard-proof-evidence.jsonl"
SCOPE = (
    "Controlled OIDC evaluation with 60 retained account-context pairs and 40 new matched pairs "
    "whose accounts agree. The app HTTP responses and journal were captured locally. Signed proof "
    "observations come from a separate controlled verifier and do not change the app's HTTP decisions."
)


def rows(data):
    return [json.loads(line, object_pairs_hook=m6.unique_fields) for line in data.splitlines()]


def retained_cases(files):
    base_plan = {row["session_id"]: row for row in rows(files["private/plan.jsonl"])}
    base_scores = {row["session_id"]: row for row in rows(files["private/scoring-labels.jsonl"])}
    return [
        (request, base_scores[request["case_id"]] | {"cohort": "account_context"}, None)
        for request in rows(files["model-requests.jsonl"])
        if base_plan[request["case_id"]]["variant"] <= RETAINED_VARIANTS
    ]


def hard_cases(plan, captures, proofs):
    proof.verify_plan(plan)
    app_by_id = {row["case_id"]: row for row in captures}
    ids = {row["case_id"] for row in plan}
    if len(app_by_id) != len(captures) or set(app_by_id) != ids or set(proofs) != ids:
        raise ValueError("m7_hard_evidence_coverage")
    for case in plan:
        capture = app_by_id[case["case_id"]]
        paired.verify_capture(case, capture)
        observed = proof.verify_proof(case, proofs[case["case_id"]])
        request = paired.model_request(case["session_id"], case["origin_inventory"], capture)
        yield request, {
            "session_id": case["session_id"], "pair_id": case["pair_id"],
            "expected_label": case["expected_label"], "scenario": case["proof_variant"],
            "cohort": "session_proof",
        }, observed


def account_prediction(request):
    first, last = request["events"][0], request["events"][-1]
    account = last["endpoint_account"] or last["registered_account"]
    return "normal" if account == first["verified_account"] else "threat"


def build_bundle(plan, captures, proofs, base_files, prior_paths=paired.PRIOR):
    retained = retained_cases(base_files)
    combined = sorted([*retained, *hard_cases(plan, captures, proofs)], key=lambda item: item[0]["case_id"])
    groups = defaultdict(list)
    statuses = defaultdict(Counter)
    baseline = Counter()
    requests, scores, sizes = [], [], []
    for request, score, observed in combined:
        request["question"] = paired.QUESTION + " " + proof.QUESTION_SUFFIX
        request["events"][-1]["session_proof"] = observed
        payload = m6.canonical(request)
        if len(payload) > 4096:
            raise ValueError("m7_strengthened_request_size")
        requests.append(request)
        sizes.append(len(payload))
        label, cohort = score["expected_label"], score["cohort"]
        groups[score["pair_id"]].append((request, label, cohort))
        statuses[tuple(event["http_status"] for event in request["events"])][label] += 1
        baseline[cohort] += account_prediction(request) == label
        scores.append(score | {"input_sha256": m6.digest(payload)})

    counts = Counter((score["cohort"], score["expected_label"]) for score in scores)
    if counts != {
        ("account_context", "normal"): 60, ("account_context", "threat"): 60,
        ("session_proof", "normal"): 40, ("session_proof", "threat"): 40,
    } or len(groups) != 100:
        raise ValueError("m7_strengthened_cohort")
    for members in groups.values():
        if len(members) != 2:
            raise ValueError("m7_strengthened_pair_size")
        (left, left_label, cohort), (right, right_label, other_cohort) = members
        if (left_label == right_label or cohort != other_cohort
                or paired.operation_signature(left) != paired.operation_signature(right)):
            raise ValueError("m7_strengthened_pair_mismatch")
        if cohort == "session_proof":
            left_proof, right_proof = (item["events"][-1]["session_proof"] for item in (left, right))
            if left_proof == right_proof or any(account_prediction(item) != "normal" for item in (left, right)):
                raise ValueError("m7_strengthened_proof_pair")
            for left_event, right_event in zip(left["events"], right["events"], strict=True):
                fields = paired.EVENT_FIELDS - {"evidence_id"}
                if any(left_event[field] != right_event[field] for field in fields):
                    raise ValueError("m7_strengthened_nonproof_difference")

    old_ids = {row["case_id"] for row in rows(base_files["model-requests.jsonl"])}
    if {request["case_id"] for request, _, _ in combined} & old_ids != {
        request["case_id"] for request, _, _ in retained
    }:
        raise ValueError("m7_strengthened_unplanned_reuse")
    files = {
        "model-requests.jsonl": jsonl(requests),
        "private/scoring-labels.jsonl": jsonl(scores),
        HARD_PLAN: jsonl(plan), HARD_EVIDENCE: jsonl(captures),
        PROOF_EVIDENCE: m6.canonical(proofs) + b"\n",
    }
    manifest = {
        "schema": "m7-paired-oidc-strengthened-1",
        "scope": SCOPE, "sessions": len(requests), "pairs": len(groups),
        "retained_pairs": len(retained) // 2, "new_proof_pairs": len(plan) // 2,
        "labels": dict(Counter(score["expected_label"] for score in scores)),
        "scenarios": dict(Counter(score["scenario"] for score in scores)),
        "same_http_sequence_and_operation_pairs": len(groups),
        "best_possible_status_only_accuracy": sum(max(group.values()) for group in statuses.values()) / len(requests),
        "relationship_baseline": {
            "correct": sum(baseline.values()), "sessions": len(requests),
            "correct_by_cohort": dict(baseline), "proof_threats_missed": 40,
        },
        "prior_overlap": paired.verify_overlap(requests, prior_paths),
        "base_manifest_sha256": m6.digest(base_files["manifest.json"]),
        "request_check": {"max_bytes": max(sizes), "answer_fields": 0},
        "files": {name: m6.digest(data) for name, data in files.items()},
    }
    files["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()
    return files, manifest


def verified_bundle(directory, base=BASE):
    base_files, _ = paired.verified_bundle(base)
    plan = rows((directory / HARD_PLAN).read_bytes())
    captures = rows((directory / HARD_EVIDENCE).read_bytes())
    proofs = json.loads((directory / PROOF_EVIDENCE).read_bytes(), object_pairs_hook=m6.unique_fields)
    files, manifest = build_bundle(plan, captures, proofs, base_files)
    if any((directory / name).read_bytes() != data for name, data in files.items()):
        raise ValueError("m7_strengthened_bundle_changed")
    return files, manifest


def prepare(directory, base=BASE):
    if directory.exists():
        raise ValueError("m7_strengthened_output_exists")
    base_files, _ = paired.verified_bundle(base)
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory.parent, prefix=".m7-strengthened-") as temporary:
        stage = Path(temporary) / "bundle"
        (stage / "private").mkdir(parents=True, mode=0o700)
        stage.chmod(0o700)
        plan = proof.create_plan()
        frozen = stage / HARD_PLAN
        frozen.write_bytes(jsonl(plan))
        frozen.chmod(0o600)
        captures = capture_cases(plan, Path(temporary))
        proofs = proof.capture_proofs(plan)
        files, manifest = build_bundle(plan, captures, proofs, base_files)
        if files[HARD_PLAN] != frozen.read_bytes():
            raise ValueError("m7_strengthened_plan_changed")
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
    parser.add_argument("--base", type=Path, default=BASE)
    args = parser.parse_args()
    manifest = prepare(args.directory, args.base) if args.mode == "prepare" else verified_bundle(
        args.directory, args.base,
    )[1]
    print(json.dumps(manifest, ensure_ascii=False))


if __name__ == "__main__":
    main()
