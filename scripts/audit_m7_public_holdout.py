"""Audit raw CloudTrail overlap after a detector freeze, including excluded source events."""

import argparse
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from scripts import evaluate_m6 as m6
from scripts import m7_public_cloudtrail as cloudtrail
from scripts.m7_public_behavior_inputs import scoped_pseudonym
from scripts.m7_shadow_overlap import ROOT

DEFAULT_ROOT = ROOT / "runtime/m7/public-behavior-holdout"


def read_pinned_records(path, expected_sha256):
    if path.stat().st_size > cloudtrail.MAX_ARCHIVE_BYTES:
        raise ValueError("holdout_audit_archive_size")
    raw = path.read_bytes()
    if m6.digest(raw) != expected_sha256:
        raise ValueError("holdout_audit_archive_hash")
    with ZipFile(BytesIO(raw)) as archive:
        members = [info for info in archive.infolist()
                   if not info.is_dir() and info.filename.lower().endswith(".json")]
        if len(members) != 1 or members[0].file_size > cloudtrail.MAX_MEMBER_BYTES:
            raise ValueError("holdout_audit_archive_member")
        member = archive.read(members[0])
    payload = json.loads(member, object_pairs_hook=m6.unique_fields)
    if not isinstance(payload, dict) or not isinstance(payload.get("Records"), list):
        raise TypeError("holdout_audit_records")
    return payload["Records"], m6.digest(member)


def index_records(raw_rows):
    # Validate publisher annotations, but never use them to choose overlap exclusions.
    references, metadata = cloudtrail.normalize_records(raw_rows)
    candidate_ids = {row["original_group_id"] for row in references}
    events, event_ids, groups, credentials, principals, temporary_keys = (
        set(), defaultdict(set), set(), set(), set(), set()
    )
    indexed = []
    for raw in raw_rows:
        record = {key: value for key, value in raw.items() if key not in cloudtrail.ANNOTATIONS}
        event_hash = m6.digest(m6.canonical(record))
        identity = record.get("userIdentity") or {}
        account = cloudtrail.logged_identifier(identity.get("accountId"))
        event_id = cloudtrail.logged_identifier(record.get("eventID"))
        event_id_hash = m6.digest(m6.canonical(["event_id", event_id])) if event_id else None
        credential = scoped_pseudonym("cloudtrail_credential", identity.get("accessKeyId"), account)
        principal = scoped_pseudonym(
            "cloudtrail_principal", identity.get("principalId") or identity.get("arn"), account
        )
        group = cloudtrail.credential_group(record, event_hash)
        group_id = m6.digest(m6.canonical(("cloudtrail", group))) if group[0] != "event_only" else None
        if group_id is not None and group_id not in candidate_ids:
            raise ValueError("holdout_audit_candidate_group_mismatch")
        events.add(event_hash)
        if event_id_hash:
            event_ids[event_id_hash].add(event_hash)
        if group_id:
            groups.add(group_id)
        if credential:
            credentials.add(credential)
            if identity.get("accessKeyId", "").startswith("ASIA"):
                temporary_keys.add(credential)
        if principal:
            principals.add(principal)
        indexed.append({
            "event_hash": event_hash, "event_id_hash": event_id_hash,
            "group_id": group_id, "credential": credential, "principal": principal,
        })
    return {
        "rows": indexed, "events": events, "event_ids": event_ids, "groups": groups,
        "credentials": credentials, "temporary_keys": temporary_keys, "principals": principals,
        "candidate_ids": candidate_ids, "metadata": metadata,
    }


def audit_records(prior_records, holdout_records):
    """Exclude whole candidate groups for overlap; a repeated principal alone is permitted."""
    prior, new = index_records(prior_records), index_records(holdout_records)
    reasons = defaultdict(set)
    event_only = Counter()
    for row in new["rows"]:
        overlap = set()
        if row["event_hash"] in prior["events"]:
            overlap.add("same_raw_event")
        if row["event_id_hash"] is not None and row["event_id_hash"] in prior["event_ids"]:
            overlap.add("same_event_id")
        if row["group_id"] is not None and row["group_id"] in prior["groups"]:
            overlap.add("same_credential_group")
        if row["credential"] is not None and row["credential"] in prior["credentials"]:
            overlap.add("same_access_key")
        if row["group_id"] is None:
            event_only["total_rows"] += 1
            event_only["rows_with_any_overlap"] += bool(overlap)
            for reason in overlap:
                event_only[reason] += 1
        elif overlap:
            reasons[row["group_id"]].update(overlap)
    common_ids = prior["event_ids"].keys() & new["event_ids"].keys()
    conflicting_ids = sum(prior["event_ids"][key] != new["event_ids"][key] for key in common_ids)
    shared_principals = prior["principals"] & new["principals"]
    principal_only = {row["group_id"] for row in new["rows"]
                      if row["group_id"] and row["principal"] in shared_principals
                      and row["group_id"] not in reasons}
    return {
        "schema": "m7-public-holdout-overlap-1",
        "prior_raw_rows": len(prior_records), "holdout_raw_rows": len(holdout_records),
        "prior_unique_raw_events": len(prior["events"]),
        "holdout_unique_raw_events": len(new["events"]),
        "prior_candidate_groups": len(prior["candidate_ids"]),
        "holdout_candidate_groups": len(new["candidate_ids"]),
        "shared_raw_event_hashes": len(prior["events"] & new["events"]),
        "shared_event_ids": len(common_ids), "shared_event_ids_with_different_payloads": conflicting_ids,
        "shared_credential_groups": len(prior["groups"] & new["groups"]),
        "shared_access_keys": len(prior["credentials"] & new["credentials"]),
        "shared_temporary_access_keys": len(prior["temporary_keys"] & new["temporary_keys"]),
        "shared_principals": len(shared_principals),
        "retained_groups_with_shared_principal": len(principal_only),
        "holdout_event_only": dict(event_only),
        "excluded_group_ids": sorted(reasons),
        "excluded_groups_by_reason": dict(Counter(reason for values in reasons.values() for reason in values)),
        "retained_candidate_groups": len(new["candidate_ids"] - reasons.keys()),
        "policy": (
            "All raw source rows, including previously excluded event-only records, participate in "
            "event hash, event ID and credential overlap checks. Exclude an entire candidate group "
            "on any match, independent of labels. A repeated principal alone is reported, not excluded. "
            "Candidate groups follow existing temporary credentials, explicit principal sessions, "
            "or fixed 30-minute actor windows; event-only rows are never candidate groups."
        ),
    }


def audit(freeze_path, prior_path, holdout_path, output):
    from scripts.evaluate_m6_public_behavior import HOLDOUT_SHA, implementation_hashes

    if output.exists():
        raise ValueError("holdout_audit_output_exists")
    frozen_raw = freeze_path.read_bytes()
    frozen = json.loads(frozen_raw, object_pairs_hook=m6.unique_fields)
    if (frozen.get("schema") != "m6-public-behavior-freeze-1"
            or frozen.get("implementation_sha256") != implementation_hashes()
            or frozen.get("holdout_archive_sha256") != HOLDOUT_SHA):
        raise ValueError("holdout_audit_freeze_mismatch")
    prior, prior_member_hash = read_pinned_records(prior_path, cloudtrail.ARCHIVE_SHA256)
    holdout, holdout_member_hash = read_pinned_records(holdout_path, HOLDOUT_SHA)
    report = audit_records(prior, holdout) | {
        "audited_at": datetime.now(UTC).isoformat(), "freeze_sha256": m6.digest(frozen_raw),
        "prior_archive_sha256": cloudtrail.ARCHIVE_SHA256,
        "prior_json_member_sha256": prior_member_hash,
        "holdout_archive_sha256": HOLDOUT_SHA, "holdout_json_member_sha256": holdout_member_hash,
        "scope": "Previously unused same-publisher CloudTrail records; not independent-source validation",
    }
    if frozen["implementation_sha256"] != implementation_hashes():
        raise ValueError("holdout_audit_implementation_changed")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", type=Path, default=DEFAULT_ROOT / "freeze.json")
    parser.add_argument("--output", type=Path, default=DEFAULT_ROOT / "holdout-overlap-audit.json")
    parser.add_argument("--prior", type=Path,
                        default=ROOT / "runtime/m7/public-independent/source/cloudtrail-a.zip")
    parser.add_argument("--holdout", type=Path,
                        default=DEFAULT_ROOT / "source/cloudtrail-train-labeled.zip")
    args = parser.parse_args()
    print(json.dumps(audit(args.freeze, args.prior, args.holdout, args.output), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
