import json

import pytest

from scripts.freeze_m7 import SOURCE, freeze_candidate
from scripts.review_m7 import assess, create, rows


@pytest.fixture
def kit(tmp_path):
    frozen, directory = tmp_path / "frozen", tmp_path / "review"
    anchor = freeze_candidate(SOURCE.parent / "pilot", frozen)
    contract = create(frozen, anchor, directory, author="implementation-author")
    return directory, contract


def write(directory, reviews):
    (directory / "reviews.jsonl").write_text("".join(json.dumps(row) + "\n" for row in reviews), encoding="utf8")


def completed(directory):
    reviews = rows(directory / "reviews.jsonl")
    inputs = {row["session_id"]: row for split in ("development", "evaluation")
              for row in rows(directory / "candidate" / f"{split}.jsonl")}
    for row in reviews:
        row.update(reviewer_subject="fixture-reviewer", reviewer_label="unknown",
                   rationale="Test fixture only; no person performed this review.",
                   evidence_ids=[inputs[row["session_id"]]["events"][0]["evidence_id"]])
    return reviews


def test_blank_worksheet_is_48_pending_and_contains_no_expected_labels(kit):
    directory, anchor = kit
    result = assess(directory, anchor)
    assert result["pending"] == 48 and result["reviewed"] == 0
    assert not result["ready_for_team_adjudication"]
    assert not result["independent_review_verified"]
    assert "expected_label" not in (directory / "reviews.jsonl").read_text()


def test_completed_fixture_can_only_request_adjudication_never_approve_labels(kit):
    directory, anchor = kit
    write(directory, completed(directory))
    result = assess(directory, anchor)
    assert result["ready_for_team_adjudication"] and result["disagreements"] == 48
    assert result["label_approval"] == "pending"
    assert not result["independent_review_verified"]


@pytest.mark.parametrize("damage", ["self", "empty_reason", "foreign_evidence", "duplicate", "extra", "truncated"])
def test_self_review_unexplained_foreign_or_wrong_scope_worksheet_is_rejected(kit, damage):
    directory, anchor = kit
    reviews = completed(directory)
    if damage == "self":
        reviews[0]["reviewer_subject"] = " IMPLEMENTATION-AUTHOR "
    elif damage == "empty_reason":
        reviews[0]["rationale"] = ""
    elif damage == "foreign_evidence":
        reviews[0]["evidence_ids"] = reviews[1]["evidence_ids"]
    elif damage == "duplicate":
        reviews[0] = reviews[1]
    elif damage == "extra":
        reviews[0]["approved"] = True
    else:
        reviews.pop()
    write(directory, reviews)
    with pytest.raises(ValueError):
        assess(directory, anchor)


def test_changed_candidate_or_contract_anchor_is_rejected(kit):
    directory, anchor = kit
    with pytest.raises(ValueError):
        assess(directory, "0" * 64)
    with (directory / "candidate/labels.jsonl").open("ab") as stream:
        stream.write(b"\n")
    with pytest.raises(ValueError):
        assess(directory, anchor)
