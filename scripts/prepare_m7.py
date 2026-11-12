"""Prepare and verify the pinned M7 authentication session pilot offline."""

import argparse
import hashlib
import json
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from app.models import StrictModel

SOURCE = Path(__file__).resolve().parents[1] / "infra/m7/source.json"
SPLITS = ("development", "evaluation")
FILES = ("development.jsonl", "evaluation.jsonl", "labels.jsonl")
LABELS = {"benign": "normal", "attack": "threat"}
SIGNALS = ("module", "http_method", "http_status", "level")
FEATURES = (*SIGNALS, "duration_ms")
AUTH_STAGES = {
    "admin_oidc_op_create": "configuration",
    "admin_oidc_op_delete": "configuration",
    "admin_saml_idp_create": "configuration",
    "auth_access_log_failed": "access",
    "auth_access_log_success": "access",
    "auth_login_attempt": "login",
    "auth_login_failed_rejected": "login",
    "auth_login_failed_user_not_found": "login",
    "auth_login_success": "login",
    "auth_registration_attempt": "registration",
    "auth_registration_failed_captcha": "registration",
    "auth_registration_failed_duplicate": "registration",
    "idp_samlresponse_created": "assertion",
    "idp_slo_all": "logout",
    "idp_slo_all_sent": "logout",
    "idp_slo_invalid_request": "logout",
    "idp_sso_request": "authorize",
    "op_authorize_request": "authorize",
    "op_session_clear_prompt": "logout",
    "op_session_created": "session",
    "op_token_request": "token",
    "request_create": "request",
    "request_response": "request",
    "request_update": "request",
    "rp_oidc_finalize_success": "session",
    "rp_oidc_login": "login",
    "rp_unregistration": "account_management",
    "rp_unregistration_failed": "account_management",
    "sp_federation_fetch": "federation",
    "sp_login_by_idp": "login",
    "sp_saml_login": "login",
}
FAILURE_REASONS = {
    "auth_login_failed_user_not_found": "user_not_found",
    "auth_registration_failed_captcha": "captcha_failed",
    "auth_registration_failed_duplicate": "duplicate_registration",
    "idp_slo_invalid_request": "request_validation_failed",
}
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SessionID = Annotated[str, Field(pattern=r"^m7-session-[0-9a-f]{64}$")]
EvidenceID = Annotated[str, Field(pattern=r"^m7-event-[0-9a-f]{64}$")]


class Event(StrictModel):
    evidence_id: EvidenceID
    module: Literal["admin", "auth", "idp", "ldap", "op", "request", "rp", "sp"]
    http_method: Literal["DELETE", "GET", "POST"]
    http_status: Annotated[int, Field(strict=True, ge=100, le=599)]
    level: Literal["DEBUG", "ERROR", "INFO", "LOG", "WARNING"]
    duration_ms: Annotated[int, Field(strict=True, ge=0)]


class Session(StrictModel):
    session_id: SessionID
    events: Annotated[list[Event], Field(min_length=1)]


class EnrichedEvent(Event):
    auth_stage: str
    failure_reason: str | None
    since_previous_ms: Annotated[int, Field(strict=True, ge=0)] | None


class EnrichedSession(Session):
    events: Annotated[list[EnrichedEvent], Field(min_length=1)]


class Record(StrictModel):
    line: Annotated[int, Field(strict=True, gt=0)]
    evidence_id: EvidenceID
    sha256: Digest
    timestamp: str


class Label(StrictModel):
    session_id: SessionID
    split: Literal["development", "evaluation"]
    expected_label: Literal["normal", "threat"]
    source_label: Literal["benign", "attack"]
    category: Annotated[str, Field(min_length=1)]
    subcategory: str | None
    subjects: list[Digest]
    clients: list[Digest]
    records: Annotated[list[Record], Field(min_length=1)]


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def session_id_for(trace):
    return "m7-session-" + sha(trace.encode())


def evidence_id_for(session_id, line):
    return "m7-event-" + sha(canonical(["m7-evidence-1", session_id, line]))


def timestamp(value):
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() is None:
        raise ValueError("m7_timestamp_requires_offset")
    return parsed


def pattern(events):
    return tuple(tuple(getattr(event, field) for field in SIGNALS) for event in events)


def split_for(family, pilot):
    label, category, _ = family
    if label == "benign":
        held_out = category in pilot["evaluation_benign_categories"]
    else:
        held_out = int(sha(canonical(family))[:8], 16) % 3 == 0
    return "evaluation" if held_out else "development"


def in_time_range(split, ordered_records, cutoff):
    if split == "evaluation":
        return ordered_records[0][0] >= cutoff
    return ordered_records[-1][0] < cutoff


def read_source(source, contract):
    if source.stat().st_size != contract["bytes"]:
        raise ValueError("m7_source_size")
    sessions = defaultdict(list)
    hashes = set()
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        for line, raw in enumerate(stream, 1):
            digest.update(raw)
            record_hash = sha(raw.rstrip(b"\r\n"))
            if record_hash in hashes:
                raise ValueError("m7_duplicate_raw_record")
            hashes.add(record_hash)
            row = json.loads(raw)
            trace = row["trace_id"]
            if not isinstance(trace, str) or not trace:
                raise ValueError("m7_missing_trace")
            family = row["label"], row["category"], row["subcategory"]
            evidence_id = evidence_id_for(session_id_for(trace), line)
            event = Event(evidence_id=evidence_id, **{field: row[field] for field in FEATURES})
            record = Record(line=line, evidence_id=evidence_id, sha256=record_hash,
                            timestamp=row["timestamp"])
            actors = tuple(row[key] for key in ("user_id", "action_by") if row[key] is not None)
            sessions[trace].append((timestamp(record.timestamp), event, record, family,
                                    actors, row["client_ip"]))
    if digest.hexdigest() != contract["sha256"]:
        raise ValueError("m7_source_digest")

    counts = Counter()
    for rows in sessions.values():
        if len({row[3] for row in rows}) != 1:
            raise ValueError("m7_conflicting_session_labels")
        counts[rows[0][3][0]] += 1
    if {"rows": len(hashes), "sessions": dict(counts)} != contract["source_counts"]:
        raise ValueError("m7_source_counts")
    return sessions


def session_pair(trace, rows, split):
    source_label, category, subcategory = rows[0][3]
    session_id = session_id_for(trace)
    data = Session(session_id=session_id, events=[row[1] for row in rows])
    subjects = {sha(canonical(["subject", actor])) for row in rows for actor in row[4]}
    clients = {sha(canonical(["client", row[5]])) for row in rows}
    truth = Label(
        session_id=session_id, split=split, expected_label=LABELS[source_label],
        source_label=source_label, category=category, subcategory=subcategory,
        subjects=sorted(subjects), clients=sorted(clients), records=[row[2] for row in rows],
    )
    return data, truth


def select_sessions(sessions, pilot):
    cutoff = timestamp(pilot["evaluation_start"])
    limit = pilot["sessions_per_label_per_split"]
    candidates = defaultdict(list)
    for trace, rows in sessions.items():
        source_label = rows[0][3][0]
        if source_label not in LABELS:
            continue
        split = split_for(rows[0][3], pilot)
        rows.sort(key=lambda row: (row[0], row[2].line))
        order = [(row[0], row[2].line) for row in rows]
        if not in_time_range(split, order, cutoff):
            continue
        candidates[split, source_label].append(session_pair(trace, rows, split))

    patterns, dev_subjects, dev_clients = set(), set(), set()
    selected = {split: [] for split in SPLITS}
    for split in SPLITS:
        for label in LABELS:
            group = []
            for data, truth in sorted(candidates[split, label], key=lambda item: item[0].session_id):
                shape = pattern(data.events)
                if shape in patterns or (split == "evaluation" and
                        (dev_subjects.intersection(truth.subjects)
                         or dev_clients.intersection(truth.clients))):
                    continue
                patterns.add(shape)
                group.append((data, truth))
                if len(group) == limit:
                    break
            if len(group) != limit:
                raise ValueError("m7_insufficient_disjoint_sessions")
            selected[split].extend(group)
            if split == "development":
                for _, truth in group:
                    dev_subjects.update(truth.subjects)
                    dev_clients.update(truth.clients)
    return selected


def summarize(inputs, labels, contract):
    pilot = contract["pilot"]
    cutoff = timestamp(pilot["evaluation_start"])
    all_sessions = {row.session_id for rows in inputs.values() for row in rows}
    if len(all_sessions) != sum(map(len, inputs.values())):
        raise ValueError("m7_duplicate_session")
    truth = {row.session_id: row for row in labels}
    if len(truth) != len(labels) or truth.keys() != all_sessions:
        raise ValueError("m7_label_session_mismatch")

    evidence, lines, record_hashes, patterns = set(), set(), set(), set()
    subjects, clients, families, cohort = {}, {}, {}, {}
    for split, rows in inputs.items():
        counts = Counter()
        subjects[split], clients[split], families[split] = set(), set(), set()
        events = 0
        for row in rows:
            label = truth[row.session_id]
            family = label.source_label, label.category, label.subcategory
            if (label.split != split or label.expected_label != LABELS[label.source_label]
                    or split_for(family, pilot) != split):
                raise ValueError("m7_label_or_family_split_mismatch")
            order = [(timestamp(record.timestamp), record.line) for record in label.records]
            if order != sorted(order) or not in_time_range(split, order, cutoff):
                raise ValueError("m7_event_order_or_time_split")
            if [event.evidence_id for event in row.events] != [
                record.evidence_id for record in label.records
            ]:
                raise ValueError("m7_label_evidence_mismatch")
            for record in label.records:
                if record.evidence_id != evidence_id_for(row.session_id, record.line):
                    raise ValueError("m7_record_evidence_id_mismatch")
                if (record.line in lines or record.line > contract["source_counts"]["rows"]
                        or record.evidence_id in evidence or record.sha256 in record_hashes):
                    raise ValueError("m7_duplicate_or_out_of_range_record")
                lines.add(record.line)
                evidence.add(record.evidence_id)
                record_hashes.add(record.sha256)
            shape = pattern(row.events)
            if shape in patterns:
                raise ValueError("m7_duplicate_signal_pattern")
            patterns.add(shape)
            subjects[split].update(label.subjects)
            clients[split].update(label.clients)
            families[split].add(family)
            counts[label.expected_label] += 1
            events += len(row.events)
        if counts != dict.fromkeys(LABELS.values(), pilot["sessions_per_label_per_split"]):
            raise ValueError("m7_cohort_label_counts")
        cohort[split] = {"sessions": len(rows), "events": events, "labels": dict(counts),
                         "families": len(families[split])}

    if set(inputs) == {"development"}:
        return cohort, {}

    overlap = {name: len(groups["development"] & groups["evaluation"])
               for name, groups in (("subjects", subjects), ("clients", clients),
                                    ("families", families))}
    if any(overlap.values()):
        raise ValueError("m7_cross_split_identity_or_family_overlap")
    return cohort, overlap | {"sessions": 0, "records": 0, "signal_patterns": 0}


def read_rows(data, schema):
    return [schema.model_validate_json(line) for line in data.splitlines()]


def describe(files, contract):
    inputs = {split: read_rows(files[f"{split}.jsonl"], Session) for split in SPLITS}
    cohort, overlap = summarize(inputs, read_rows(files["labels.jsonl"], Label), contract)
    return {
        "schema": "m7-auth-pilot-1",
        "source_sha256": contract["sha256"],
        "source_contract_sha256": sha(canonical(contract)),
        "files": {name: sha(data) for name, data in files.items()},
        "cohort": cohort,
        "cross_split_overlap": overlap,
        "label_review": "publisher_labels_pending_independent_team_review",
    }


def verify(directory, contract):
    files = {name: (directory / name).read_bytes() for name in FILES}
    manifest = json.loads((directory / "manifest.json").read_bytes())
    if manifest != describe(files, contract):
        raise ValueError("m7_manifest_mismatch")
    return manifest


def enrich_sessions(source, sessions, scoring_labels, contract):
    """Project allowlisted observations from the pinned records of selected sessions."""
    if source.stat().st_size != contract["bytes"]:
        raise ValueError("m7_source_size")
    selected = {record.line for label in scoring_labels for record in label.records}
    rows = {}
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        for line, raw in enumerate(stream, 1):
            digest.update(raw)
            if line in selected:
                rows[line] = raw
    if digest.hexdigest() != contract["sha256"]:
        raise ValueError("m7_source_digest")
    if rows.keys() != selected:
        raise ValueError("m7_development_source_record_missing")

    labels = {label.session_id: label for label in scoring_labels}
    enriched = []
    for session in sessions:
        label = labels[session.session_id]
        previous = None
        events = []
        for event, record in zip(session.events, label.records, strict=True):
            raw = rows[record.line]
            if sha(raw.rstrip(b"\r\n")) != record.sha256:
                raise ValueError("m7_development_source_record_digest")
            row = json.loads(raw)
            if (session_id_for(row["trace_id"]) != session.session_id
                    or row["timestamp"] != record.timestamp
                    or Event(evidence_id=record.evidence_id,
                             **{field: row[field] for field in FEATURES}) != event):
                raise ValueError("m7_development_source_record_mismatch")
            if (row["label"], row["category"], row["subcategory"]) != (
                label.source_label, label.category, label.subcategory,
            ):
                raise ValueError("m7_development_source_label_mismatch")
            event_type = row.get("event_type")
            if not isinstance(event_type, str):
                event_type = ""
            reason = FAILURE_REASONS.get(event_type)
            payload = row.get("payload")
            if (event_type == "rp_unregistration_failed" and isinstance(payload, dict)
                    and payload.get("error") == "protected_client"):
                reason = "protected_client"
            current = timestamp(row["timestamp"])
            events.append(EnrichedEvent(
                **event.model_dump(),
                auth_stage=AUTH_STAGES.get(event_type, "unknown"),
                failure_reason=reason,
                since_previous_ms=(None if previous is None else
                                   (current - previous) // timedelta(milliseconds=1)),
            ))
            previous = current
        enriched.append(EnrichedSession(session_id=session.session_id, events=events))
    return enriched


def load_development(directory, *, source=None):
    """Verify the development input and its labels without opening evaluation observations."""
    contract = json.loads(SOURCE.read_bytes())
    manifest_data = (directory / "manifest.json").read_bytes()
    manifest = json.loads(manifest_data)
    observations = (directory / "development.jsonl").read_bytes()
    label_data = (directory / "labels.jsonl").read_bytes()
    file_hashes = {"development.jsonl": sha(observations), "labels.jsonl": sha(label_data)}
    if (manifest["schema"] != "m7-auth-pilot-1" or manifest["source_sha256"] != contract["sha256"]
            or manifest["source_contract_sha256"] != sha(canonical(contract))
            or any(manifest["files"][name] != value for name, value in file_hashes.items())):
        raise ValueError("m7_manifest_mismatch")

    sessions = read_rows(observations, Session)
    labels = read_rows(label_data, Label)
    if len({row.session_id for row in labels}) != len(labels):
        raise ValueError("m7_label_session_mismatch")
    development_labels = [row for row in labels if row.split == "development"]
    cohort, _ = summarize({"development": sessions}, development_labels, contract)
    if cohort["development"] != manifest["cohort"]["development"]:
        raise ValueError("m7_manifest_mismatch")
    fingerprints = {
        "dataset_sha256": file_hashes["development.jsonl"],
        "labels_sha256": file_hashes["labels.jsonl"],
        "split_manifest_sha256": sha(manifest_data),
    }
    if source is not None:
        sessions = enrich_sessions(source, sessions, development_labels, contract)
        fingerprints.update(
            base_dataset_sha256=file_hashes["development.jsonl"],
            dataset_sha256=sha(jsonl(sessions)),
            source_sha256=contract["sha256"],
        )
    return sessions, {row.session_id: row.expected_label for row in development_labels}, fingerprints


def jsonl(rows):
    return b"".join(canonical(row.model_dump(mode="json")) + b"\n" for row in rows)


def pilot_bundle(selected, contract):
    files = {}
    labels = []
    for split, rows in selected.items():
        rows.sort(key=lambda item: item[0].session_id)
        files[f"{split}.jsonl"] = jsonl(data for data, _ in rows)
        labels.extend(label for _, label in rows)
    files["labels.jsonl"] = jsonl(labels)
    manifest = describe(files, contract)
    files["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()
    return files, manifest


def build(source, contract):
    return pilot_bundle(select_sessions(read_source(source, contract), contract["pilot"]), contract)


def prepare(source, output, contract):
    if output.exists():
        raise ValueError("m7_output_requires_fresh_directory")
    files, manifest = build(source, contract)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".m7-", dir=output.parent) as temporary:
        stage = Path(temporary) / "pilot"
        stage.mkdir()
        for name, data in files.items():
            (stage / name).write_bytes(data)
        stage.rename(output)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "verify"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source", type=Path, help="Local pinned publisher JSONL")
    args = parser.parse_args()
    try:
        contract = json.loads(SOURCE.read_bytes())
        if args.mode == "prepare":
            if args.source is None:
                parser.error("--source is required for prepare")
            manifest = prepare(args.source, args.directory, contract)
        else:
            manifest = verify(args.directory, contract)
            if args.source is not None:
                files, _ = build(args.source, contract)
                if any((args.directory / name).read_bytes() != data for name, data in files.items()):
                    raise ValueError("m7_reproduction_mismatch")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"m7 dataset rejected: {type(exc).__name__}\n")
    print(json.dumps(manifest, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
