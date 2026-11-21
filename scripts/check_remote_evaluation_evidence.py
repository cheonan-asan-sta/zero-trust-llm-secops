"""Check which remote evaluation cases have contemporaneous evidence references."""

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator

from app.models import StrictModel
from scripts.f1_lab.evaluation_preparation import MAX_CASES, SHA, CaseMetadata
from scripts.f1_lab.native_jsonl import decode, require
from scripts.prepare_independent_evaluation import read_pinned


class EvidenceReference(StrictModel):
    record_sha256: SHA
    session_group_sha256: SHA
    available_at: datetime

    @field_validator("available_at")
    @classmethod
    def aware(cls, value):
        if value.utcoffset() is None:
            raise ValueError("evidence_availability_timezone")
        return value


class ApprovalReference(EvidenceReference):
    outcome: Literal["approved", "denied", "unknown"]


class MFAReference(EvidenceReference):
    outcome: Literal["required_satisfied", "required_unsatisfied", "not_required", "unknown"]


class RemoteEvidence(StrictModel):
    case_id: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    payload_sha256: SHA
    approval: ApprovalReference | None = None
    mfa: MFAReference | None = None


def read_metadata(path, sha256, model):
    raw = read_pinned(path, sha256)
    lines = raw.splitlines()
    require(len(lines) <= MAX_CASES, "remote_evidence_row_limit")
    result = {}
    for line in lines:
        require(0 < len(line) <= 65536, "remote_evidence_line_size")
        row = model.model_validate(decode(line))
        require(row.case_id not in result, "remote_evidence_duplicate_case")
        result[row.case_id] = row
    return result


def summarize(catalog, sidecar):
    remote = {key: row for key, row in catalog.items() if "remote" in row.domains}
    require(sidecar.keys() <= remote.keys(), "remote_evidence_unknown_or_nonremote_case")
    sessions_by_record = defaultdict(set)
    for row in sidecar.values():
        for kind in ("approval", "mfa"):
            reference = getattr(row, kind)
            if reference:
                sessions_by_record[(kind, reference.record_sha256)].add(
                    reference.session_group_sha256
                )

    cases = {}
    for key, case in remote.items():
        row = sidecar.get(key)
        issues = []
        for kind in ("approval", "mfa"):
            reference = getattr(row, kind) if row is not None else None
            if reference is None:
                issues.append(f"{kind}_reference_missing")
                continue
            if row.payload_sha256 != case.payload_sha256 or (
                reference.session_group_sha256 not in case.groups["session"]
            ):
                issues.append(f"{kind}_binding_mismatch")
            if reference.available_at > case.end:
                issues.append(f"{kind}_available_after_case_end")
            if reference.outcome == "unknown":
                issues.append(f"{kind}_outcome_unknown")
            if len(sessions_by_record[(kind, reference.record_sha256)]) > 1:
                issues.append(f"{kind}_record_reused_across_sessions")
        cases[key] = {
            "split": case.requested_split,
            "source_kind": case.source_kind,
            "label_purpose": case.label_purpose,
            "reference_binding_complete": not issues,
            "issues": issues,
        }
    return {
        "remote_cases": len(remote),
        "final_remote_cases": sum(r.requested_split == "final_reserved" for r in remote.values()),
        "final_remote_cases_with_references": sum(
            row["reference_binding_complete"] and row["split"] == "final_reserved"
            for row in cases.values()
        ),
        "evidence_bytes_verified": False,
        "independent_evaluation_performed": False,
        "by_case": cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--catalog-sha256", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--evidence-sha256", required=True)
    args = parser.parse_args()
    catalog = read_metadata(args.catalog, args.catalog_sha256, CaseMetadata)
    sidecar = read_metadata(args.evidence, args.evidence_sha256, RemoteEvidence)
    print(json.dumps(summarize(catalog, sidecar), sort_keys=True))


if __name__ == "__main__":
    main()
