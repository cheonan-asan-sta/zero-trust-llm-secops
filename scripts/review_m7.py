"""Prepare local M7 review worksheets; never certify a person's independent review."""

import argparse
import json
import shutil
import tempfile
from pathlib import Path

from scripts.freeze_m7 import FILES, digest, verify_frozen


def require(condition, code):
    if not condition:
        raise ValueError(code)


def rows(path):
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def create(frozen, anchor, destination, *, author):
    require(isinstance(author, str) and bool(author.strip()), "review_author_required")
    verify_frozen(frozen, anchor)
    require(not destination.exists(), "review_fresh_directory_required")
    labels = rows(frozen / "labels.jsonl")
    worksheet = [{"session_id": row["session_id"], "reviewer_subject": None,
                  "reviewer_label": None, "evidence_ids": [], "rationale": ""} for row in labels]
    contract = {"schema": "m7-review-kit-1", "freeze_sha256": anchor,
                "implementation_author": author, "sessions": len(labels),
                "independent_review_verified": False}
    raw = (json.dumps(contract, sort_keys=True, indent=2) + "\n").encode()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix=".m7-review-") as temp:
        stage = Path(temp) / "kit"
        (stage / "candidate").mkdir(parents=True)
        for name in (*FILES, "freeze.json"):
            shutil.copyfile(frozen / name, stage / "candidate" / name)
        (stage / "contract.json").write_bytes(raw)
        (stage / "reviews.jsonl").write_text("".join(json.dumps(row) + "\n" for row in worksheet), encoding="utf8")
        stage.rename(destination)
    return digest(raw)


def assess(directory, expected):
    require(not directory.is_symlink(), "review_directory_symlink")
    path = directory / "contract.json"
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4096,
            "review_contract_file")
    raw = path.read_bytes()
    require(digest(raw) == expected, "review_contract_anchor")
    contract = json.loads(raw)
    require(contract["schema"] == "m7-review-kit-1" and
            contract["independent_review_verified"] is False, "review_contract")
    frozen = directory / "candidate"
    verify_frozen(frozen, contract["freeze_sha256"])
    truths = {row["session_id"]: row for row in rows(frozen / "labels.jsonl")}
    observations = {row["session_id"]: row for split in ("development", "evaluation")
                    for row in rows(frozen / f"{split}.jsonl")}
    path = directory / "reviews.jsonl"
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024**2,
            "review_worksheet_file")
    reviews = rows(path)
    require(len(reviews) == contract["sessions"] == len(truths), "review_session_count")
    seen, pending, reviewed, disagreements = set(), 0, 0, 0
    for row in reviews:
        require(set(row) == {"session_id", "reviewer_subject", "reviewer_label", "evidence_ids", "rationale"},
                "review_fields")
        ident = row["session_id"]
        require(ident in truths and ident not in seen, "review_session_identity")
        seen.add(ident)
        if row["reviewer_label"] is None:
            pending += 1
            continue
        require(row["reviewer_label"] in {"normal", "threat", "unknown"}, "review_label")
        subject = row["reviewer_subject"]
        require(isinstance(subject, str) and bool(subject.strip()) and
                subject.strip().casefold() != contract["implementation_author"].strip().casefold(),
                "review_different_subject_required")
        require(isinstance(row["rationale"], str) and 10 <= len(row["rationale"].strip()) <= 2000,
                "review_rationale_required")
        valid = {event["evidence_id"] for event in observations[ident]["events"]}
        evidence = row["evidence_ids"]
        require(isinstance(evidence, list) and evidence and all(isinstance(v, str) for v in evidence)
                and len(set(evidence)) == len(evidence) and set(evidence) <= valid,
                "review_session_evidence_required")
        reviewed += 1
        disagreements += row["reviewer_label"] != truths[ident]["expected_label"]
    return {"schema": "m7-review-assessment-1", "sessions": len(truths), "reviewed": reviewed,
            "pending": pending, "disagreements": disagreements,
            "ready_for_team_adjudication": pending == 0, "label_approval": "pending",
            "independent_review_verified": False, "identity_assurance": "self_reported_only",
            "contract_sha256": expected, "freeze_sha256": contract["freeze_sha256"],
            "worksheet_sha256": digest(path.read_bytes())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("create", "assess"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--frozen", type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--author")
    args = parser.parse_args()
    if args.mode == "create":
        require(args.frozen is not None, "review_frozen_directory_required")
        print(json.dumps({"contract_sha256": create(args.frozen, args.expected_sha256,
            args.directory, author=args.author), "independent_review_verified": False}))
        return 0
    result = assess(args.directory, args.expected_sha256)
    print(json.dumps(result))
    return 0 if result["ready_for_team_adjudication"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
