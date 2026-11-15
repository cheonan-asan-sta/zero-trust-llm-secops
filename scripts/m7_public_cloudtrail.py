"""Load the Ariel Cyber CloudTrail holdout without exposing annotation fields to rules."""

import json
import re
import zipfile
from collections import Counter, defaultdict
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

from scripts.evaluate_m6 import canonical, digest, unique_fields

SOURCE = "cloudtrail"
REVISION = "18d3f248f4def592f4e86152c3fcb54506fbcbf6"
SOURCE_URL = (
    "https://raw.githubusercontent.com/ArielCyber/cloud_log_sampling/"
    f"{REVISION}/TestOn/labeled_cloudtrail_a.zip"
)
README_URL = f"https://github.com/ArielCyber/cloud_log_sampling/blob/{REVISION}/README.md"
ARCHIVE_SHA256 = "d5dce3dbdb61ffb935e16cb4728aaca933daa42201a672dfad7387fd168f6eb0"
EXPECTED_LABEL_COUNTS = {False: 21_502, True: 2_585}
MAX_ARCHIVE_BYTES = 12 * 1024 * 1024
MAX_MEMBER_BYTES = 160 * 1024 * 1024
WINDOW_SECONDS = 30 * 60
ANNOTATIONS = {"attack_name", "should_sample"}
ANONYMOUS_TYPES = {"unknown", "anonymous", "anonymoususer"}
UNIDENTIFIED = {"anonymous", "anonymous_principal", "unknown", "null", "-", "n/a"}
ACTION_TOKEN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def logged_identifier(value):
    if isinstance(value, str) and value.strip() and value.casefold() not in UNIDENTIFIED:
        return value
    return None


def utc_timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment.astimezone(UTC) if moment.tzinfo is not None else None


def credential_group(record, event_sha256):
    """Use only logged identity and timestamp, never collection/attack labels."""
    identity = record.get("userIdentity") or {}
    context = identity.get("sessionContext") or {}
    attributes = context.get("attributes") or {}
    account = logged_identifier(identity.get("accountId"))
    key = logged_identifier(identity.get("accessKeyId"))
    principal = logged_identifier(identity.get("principalId")) or logged_identifier(identity.get("arn"))
    created = utc_timestamp(attributes.get("creationDate"))
    if key and key.startswith("ASIA"):
        return ("temporary_credential", account, key)
    if principal and created:
        return ("principal_session", account, principal, created.isoformat())
    moment = utc_timestamp(record.get("eventTime"))
    identity_type = identity.get("type")
    if (moment and (principal or key)
            and (not isinstance(identity_type, str) or identity_type.casefold() not in ANONYMOUS_TYPES)):
        return ("actor_time_window", account, principal, key, int(moment.timestamp()) // WINDOW_SECONDS)
    return ("event_only", event_sha256)


def safe_action(record):
    parts = (record.get("eventSource"), record.get("eventName"))
    return ":".join(value if isinstance(value, str) and ACTION_TOKEN.fullmatch(value) else "unknown"
                    for value in parts)


def normalize_records(raw_rows):
    """Produce separate observations and publisher labels, with global event deduplication."""
    groups = defaultdict(list)
    by_event_id = {}
    by_hash = {}
    labels = Counter()
    attack_events = Counter()
    excluded_event_only = Counter()
    excluded_attack_families = Counter()
    duplicates = 0
    for raw in raw_rows:
        if not isinstance(raw, dict) or type(raw.get("should_sample")) is not bool:
            raise ValueError("cloudtrail_missing_publisher_label")
        threat = raw["should_sample"]
        family = raw.get("attack_name")
        if ((threat and (not isinstance(family, str) or not ACTION_TOKEN.fullmatch(family)))
                or (not threat and family is not None)):
            raise ValueError("cloudtrail_invalid_attack_name")
        labels[threat] += 1
        record = {key: value for key, value in raw.items() if key not in ANNOTATIONS}
        event_hash = digest(canonical(record))
        event_id = logged_identifier(record.get("eventID"))
        if event_id is not None and by_event_id.setdefault(event_id, event_hash) != event_hash:
            raise ValueError("cloudtrail_conflicting_event_id")
        if event_hash in by_hash:
            if by_hash[event_hash] != (threat, family):
                raise ValueError("cloudtrail_conflicting_duplicate_label")
            duplicates += 1
            continue
        by_hash[event_hash] = (threat, family)
        group = credential_group(record, event_hash)
        if threat:
            attack_events[family] += 1
        if group[0] == "event_only":
            excluded_event_only["threat" if threat else "normal"] += 1
            if threat:
                excluded_attack_families[family] += 1
            continue
        identity = record.get("userIdentity") or {}
        groups[group].append((
            event_hash, threat, family, safe_action(record),
            bool(record.get("errorCode")), logged_identifier(identity.get("principalId")) is not None,
            logged_identifier(identity.get("accessKeyId")) is not None,
        ))

    rows = []
    group_counts, events_by_group, mixed_counts, family_groups = (
        Counter(), Counter(), Counter(), Counter()
    )
    group_truth_counts = defaultdict(Counter)
    for group, events in groups.items():
        grouping = group[0]
        threat_events = sum(event[1] for event in events)
        expected_label = "threat" if threat_events else "normal"
        families = sorted({event[2] for event in events if event[1]})
        group_counts[grouping] += 1
        group_truth_counts[grouping][expected_label] += 1
        events_by_group[grouping] += len(events)
        if 0 < threat_events < len(events):
            mixed_counts[grouping] += 1
        family_groups.update(families)
        rows.append({
            "source": SOURCE,
            "original_group_id": digest(canonical((SOURCE, group))),
            "event_hashes": sorted(event[0] for event in events),
            "observation": {
                "grouping": grouping,
                "event_count": len(events),
                "api_action_counts": dict(sorted(Counter(event[3] for event in events).items())),
                "api_error_count": sum(event[4] for event in events),
                "events_with_logged_principal": sum(event[5] for event in events),
                "events_with_logged_access_key": sum(event[6] for event in events),
            },
            "expected_label": expected_label,
            "families": families,
        })
    return sorted(rows, key=lambda row: row["original_group_id"]), {
        "publisher_event_counts": {"normal": labels[False], "threat": labels[True]},
        "exact_duplicate_events_removed": duplicates,
        "unique_events": len(by_hash),
        "event_only_excluded": {
            "normal": excluded_event_only["normal"],
            "threat": excluded_event_only["threat"],
            "unlabeled": 0,
        },
        "event_only_excluded_attack_families": dict(excluded_attack_families),
        "groups_by_method": dict(group_counts),
        "group_truth_by_method": {
            method: {"normal": counts["normal"], "threat": counts["threat"]}
            for method, counts in group_truth_counts.items()
        },
        "events_by_method": dict(events_by_group),
        "mixed_truth_groups_by_method": dict(mixed_counts),
        "attack_events_by_family": dict(attack_events),
        "attack_groups_by_family": dict(family_groups),
        "ground_truth": (
            "Publisher should_sample is event truth. A group is threat if any retained member is "
            "publisher-labeled adversarial; mixed groups count as threat and are reported separately."
        ),
        "grouping_limitations": (
            "Temporary access keys or explicit principal and creation time identify credential sessions. "
            "Other stable actors are grouped in fixed 30-minute UTC windows. Events with insufficient "
            "actor context are reported and excluded as event-only cases."
        ),
        "capture_limitations": (
            "AWS emitted the logs during a controlled live deployment with generated normal traffic "
            "and attack execution. CloudTrail principal, API outcome, or repeated credential use do not "
            "supply local device proof, session binding, access approval, or replay confirmation."
        ),
    }


def load_cloudtrail(path: Path):
    """Read only the pinned publisher's small test archive and verify its declared counts."""
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("cloudtrail_archive_size_limit")
    archive_bytes = path.read_bytes()
    if digest(archive_bytes) != ARCHIVE_SHA256:
        raise ValueError("cloudtrail_archive_sha256_mismatch")
    with zipfile.ZipFile(BytesIO(archive_bytes)) as archive:
        members = [info for info in archive.infolist()
                   if not info.is_dir() and info.filename.lower().endswith(".json")]
        if len(members) != 1 or members[0].file_size > MAX_MEMBER_BYTES:
            raise ValueError("cloudtrail_archive_json_shape")
        source_json = archive.read(members[0])
    payload = json.loads(source_json, object_pairs_hook=unique_fields)
    if not isinstance(payload, dict) or not isinstance(payload.get("Records"), list):
        raise TypeError("cloudtrail_archive_missing_records")
    rows, metadata = normalize_records(payload["Records"])
    if metadata["publisher_event_counts"] != {
        "normal": EXPECTED_LABEL_COUNTS[False], "threat": EXPECTED_LABEL_COUNTS[True],
    }:
        raise ValueError("cloudtrail_publisher_count_mismatch")
    return rows, metadata | {
        "source_url": SOURCE_URL,
        "publisher_documentation": README_URL,
        "revision": REVISION,
        "archive_sha256": ARCHIVE_SHA256,
        "json_member_sha256": digest(source_json),
        "license": "Publisher invites research use and citation; no explicit license file identified.",
    }
