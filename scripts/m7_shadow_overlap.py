"""Reject reused session, evidence, or request identifiers in the M7 shadow cohort."""

import json
import re
from pathlib import Path

from scripts.evaluate_m6 import canonical, digest, unique_fields

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "infra/m7/pilot/development.jsonl": 24,
    "infra/m7/pilot/evaluation.jsonl": 24,
    "infra/m7/pilot/labels.jsonl": 48,
    "runtime/m7/final-holdout/observations.jsonl": 24,
    "runtime/m7/final-holdout/scoring-labels.jsonl": 24,
    "runtime/m7/evidence-verified-holdout/observations.jsonl": 12,
    "runtime/m7/evidence-verified-holdout/model-requests.jsonl": 12,
    "runtime/m7/evidence-verified-holdout/private/scoring-labels.jsonl": 12,
    "runtime/m7/local-oidc-evaluation/observations.jsonl": 200,
    "runtime/m7/local-oidc-evaluation/private/plan.jsonl": 200,
    "runtime/m7/local-oidc-evaluation/private/scoring-labels.jsonl": 200,
    "runtime/m7/paired-oidc-evaluation/model-requests.jsonl": 200,
    "runtime/m7/paired-oidc-evaluation/private/scoring-labels.jsonl": 200,
    "runtime/m7/paired-oidc-evaluation/private/plan.jsonl": 200,
    "runtime/m7/paired-oidc-strengthened/model-requests.jsonl": 200,
    "runtime/m7/paired-oidc-strengthened/private/scoring-labels.jsonl": 200,
    "runtime/m7/paired-oidc-strengthened/private/hard-plan.jsonl": 80,
}
OPTIONAL = {
    "runtime/m7/pilot-opaque-ids/development.jsonl": 24,
    "runtime/m7/pilot-opaque-ids/evaluation.jsonl": 24,
    "runtime/m7/pilot-opaque-ids/labels.jsonl": 48,
    "runtime/m7/evaluation-20261109/local-access/plan.json": 200,
    "runtime/m6/proof-policy-dev/report.json": 20,
}
SCORED_REQUEST_COHORTS = (
    "runtime/m7/evidence-verified-holdout",
    "runtime/m7/paired-oidc-evaluation",
    "runtime/m7/paired-oidc-strengthened",
)
SHA256 = re.compile(r"[a-f0-9]{64}")
LOCAL_EVENT_ALIAS = re.compile(r"(?:e|ev|event|evidence)[-_]?\d+", re.IGNORECASE)
RELATED_IDS = ("case_id", "pair_id", "raw_session_id", "original_session_id", "trace_id")


def checked_ids(values):
    ids = set(values)
    if any(not isinstance(value, str) or not value for value in ids):
        raise ValueError("m7_shadow_overlap_invalid_id")
    return ids


def checked_hashes(values):
    hashes = checked_ids(values)
    if any(not SHA256.fullmatch(value) for value in hashes):
        raise ValueError("m7_shadow_overlap_invalid_hash")
    return hashes


def load_rows(path, raw, expected_count):
    if path.suffix == ".json":
        collection = "cases" if path.name == "plan.json" else "rows"
        rows = json.loads(raw, object_pairs_hook=unique_fields)[collection]
    else:
        rows = [json.loads(line, object_pairs_hook=unique_fields) for line in raw.splitlines()]
    if (not isinstance(rows, list) or len(rows) != expected_count
            or any(not isinstance(row, dict) for row in rows)):
        raise ValueError(f"m7_shadow_overlap_prior_row_shape: {path}")
    identifiers = checked_ids(row.get("session_id", row.get("case_id")) for row in rows)
    if len(identifiers) != expected_count:
        raise ValueError(f"m7_shadow_overlap_prior_duplicate_rows: {path}")
    return rows


def fingerprints(rows):
    sessions = checked_ids(row["session_id"] for row in rows if "session_id" in row)
    related = checked_ids(row[key] for row in rows for key in RELATED_IDS if key in row)
    event_records = [
        event for row in rows for key in ("events", "records", "evidence_records")
        for event in row.get(key, ())
    ]
    evidence = checked_ids(
        [event[key] for event in event_records for key in ("evidence_id", "event_id") if key in event]
        + [item for row in rows for item in row.get("evidence_ids", ())]
    )
    request_hashes = checked_hashes(row["input_sha256"] for row in rows if "input_sha256" in row)
    request_hashes.update(digest(canonical(row)) for row in rows if "question" in row)
    source_hashes = checked_hashes(event["sha256"] for event in event_records if "sha256" in event)
    return {
        "session_ids": sessions,
        "related_ids": related,
        "evidence_ids": {value for value in evidence if not LOCAL_EVENT_ALIAS.fullmatch(value)},
        "request_hashes": request_hashes,
        "source_hashes": source_hashes,
    }


def verify_overlap(
    new_session_ids,
    new_evidence_ids,
    new_request_hashes,
    *,
    root=ROOT,
    new_related_ids=(),
    new_source_hashes=(),
):
    """Check saved cohorts, including raw plan IDs and the score-file payload hashes.

    Supply globally unique event IDs and any raw runtime session or case IDs. Labels stay local
    and only source identifiers and hashes enter the audit. Short aliases like e1 are session-local.
    """
    new_sessions = checked_ids(new_session_ids)
    evidence = checked_ids(new_evidence_ids)
    scoped_aliases = {value for value in evidence if LOCAL_EVENT_ALIAS.fullmatch(value)}
    new_ids = new_sessions | (evidence - scoped_aliases) | checked_ids(new_related_ids)
    new_requests = checked_hashes(new_request_hashes)
    new_source = checked_hashes(new_source_hashes)
    if not new_sessions or len(new_requests) != len(new_sessions):
        raise ValueError("m7_shadow_overlap_new_cohort_shape")

    sources = {}
    source_rows = {}
    missing_optional = []
    for name, expected_count in (REQUIRED | OPTIONAL).items():
        path = root / name
        try:
            raw = path.read_bytes()
        except FileNotFoundError as exc:
            if name in REQUIRED:
                raise ValueError(f"m7_shadow_overlap_missing_prior: {name}") from exc
            missing_optional.append(name)
            continue
        rows = load_rows(path, raw, expected_count)
        source_rows[name] = rows
        prior = fingerprints(rows)
        compared = dict.fromkeys(("session_ids", "related_ids", "evidence_ids"), new_ids)
        compared.update(request_hashes=new_requests, source_hashes=new_source)
        overlaps = {key: len(values & compared[key]) for key, values in prior.items()}
        if any(overlaps.values()):
            raise ValueError(f"m7_shadow_overlap_prior_reuse: {name} {overlaps}")
        sources[name] = {
            "sha256": digest(raw),
            "rows": len(rows),
            "identifiers": {key: len(values) for key, values in prior.items()},
            "overlaps": overlaps,
        }

    for cohort in SCORED_REQUEST_COHORTS:
        requests = source_rows[cohort + "/model-requests.jsonl"]
        scoring = source_rows[cohort + "/private/scoring-labels.jsonl"]
        if {row["case_id"]: digest(canonical(row)) for row in requests} != {
            row["session_id"]: row["input_sha256"] for row in scoring
        }:
            raise ValueError(f"m7_shadow_overlap_prior_request_hash_mismatch: {cohort}")

    return {
        "sources": sources,
        "missing_optional": missing_optional,
        "new_session_ids": len(new_sessions),
        "new_global_evidence_ids": len(evidence - scoped_aliases),
        "new_local_evidence_aliases_excluded": len(scoped_aliases),
        "new_request_hashes": len(new_requests),
        "new_source_hashes": len(new_source),
    }
