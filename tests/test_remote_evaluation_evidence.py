import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from test_f1_evaluation_preparation import case, digest

from scripts.check_remote_evaluation_evidence import RemoteEvidence, read_metadata, summarize


def references(record):
    common = {"session_group_sha256": record.groups["session"][0], "available_at": record.end}
    return {
        "case_id": record.case_id,
        "payload_sha256": record.payload_sha256,
        "approval": dict(
            common, record_sha256=digest(["approval", record.case_id]), outcome="denied"
        ),
        "mfa": dict(common, record_sha256=digest(["mfa", record.case_id]), outcome="not_required"),
    }


def test_report_separates_references_from_independent_adjudication():
    final = case(1, "final_reserved", domains=["remote"])
    old = case(2, domains=["remote"], exposure="observed")
    report = summarize(
        {row.case_id: row for row in (final, old)},
        {final.case_id: RemoteEvidence.model_validate(references(final))},
    )
    assert report["final_remote_cases_with_references"] == 1
    assert report["by_case"][old.case_id]["issues"] == [
        "approval_reference_missing",
        "mfa_reference_missing",
    ]
    assert report["evidence_bytes_verified"] is report["independent_evaluation_performed"] is False


@pytest.mark.parametrize(
    ("kind", "field", "value", "issue"),
    [
        ("approval", "outcome", "unknown", "approval_outcome_unknown"),
        ("mfa", "available_at", datetime(2100, 1, 1, tzinfo=UTC), "mfa_available_after_case_end"),
        ("approval", "session_group_sha256", "1" * 64, "approval_binding_mismatch"),
    ],
)
def test_unresolved_metadata_does_not_count_as_available(kind, field, value, issue):
    record = case(1, "final_reserved", domains=["remote"])
    data = references(record)
    data[kind][field] = value
    report = summarize(
        {record.case_id: record}, {record.case_id: RemoteEvidence.model_validate(data)}
    )
    assert issue in report["by_case"][record.case_id]["issues"]
    assert report["final_remote_cases_with_references"] == 0


def test_reused_receipt_does_not_support_a_different_session():
    first, second = (case(n, "final_reserved", domains=["remote"]) for n in (1, 2))
    a, b = references(first), references(second)
    b["mfa"]["record_sha256"] = a["mfa"]["record_sha256"]
    a["approval"]["available_at"] = first.end - timedelta(seconds=60)
    summary = summarize(
        {row.case_id: row for row in (first, second)},
        {row["case_id"]: RemoteEvidence.model_validate(row) for row in (a, b)},
    )
    assert all(
        row["issues"] == ["mfa_record_reused_across_sessions"]
        for row in summary["by_case"].values()
    )


def test_hash_pinned_reader_rejects_duplicates_and_hidden_extra_fields(tmp_path):
    row = RemoteEvidence.model_validate(references(case(1, domains=["remote"])))
    path = tmp_path / "evidence.jsonl"
    line = row.model_dump_json().encode() + b"\n"
    for raw, expected in (
        (line * 2, "duplicate_case"),
        (line.replace(b"}\n", b',"truth":true}\n'), "Extra inputs"),
    ):
        path.write_bytes(raw)
        with pytest.raises(ValueError, match=expected):
            read_metadata(path, hashlib.sha256(raw).hexdigest(), RemoteEvidence)
    with pytest.raises(ValueError, match="preparation_file_pin"):
        read_metadata(path, "0" * 64, RemoteEvidence)


def test_opt_in_record_check_validates_bytes_without_claiming_independent_truth(tmp_path):
    row = case(1, "final_reserved", domains=["remote"])
    data = references(row)
    for kind in ("approval", "mfa"):
        content = f"anonymized {kind} evidence".encode()
        digest = hashlib.sha256(content).hexdigest()
        data[kind]["record_sha256"] = digest
        (tmp_path / digest).write_bytes(content)
    catalog, sidecar = {row.case_id: row}, {row.case_id: RemoteEvidence.model_validate(data)}
    report = summarize(catalog, sidecar, tmp_path)
    assert report["evidence_bytes_verified"] and not report["independent_evaluation_performed"]
    (tmp_path / data["mfa"]["record_sha256"]).write_bytes(b"altered")
    report = summarize(catalog, sidecar, tmp_path)
    assert not report["evidence_bytes_verified"]
    assert report["by_case"][row.case_id]["issues"] == ["mfa_record_file_hash_mismatch"]
