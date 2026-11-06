"""Bounded, explicit JSONL storage contract for stopped application recovery.

Preserve exact bytes and validate the application's existing hash chains and
case/outbox relationships. Missing files are never interpreted as empty logs.
This does not coordinate live writers or promise exactly-once remote delivery.
"""

import hashlib
import json
from pathlib import Path

from app.models import AnalysisResult, IncidentCase, IntegrationOutboxRecord
from app.services.cases import ALLOWED_TRANSITIONS
from app.services.integration_outbox import _cloud_event

FILES = {"audit": "audit.jsonl", "cases": "cases.jsonl", "outbox": "integration-outbox.jsonl"}
CONTRACT = {"schema": "app-jsonl-storage-1", "files": FILES}
MAX_LOG = 8 * 1024**2
MAX_LINE = 1024**2
MAX_RECORDS = 10000
MODELS = {"audit": AnalysisResult, "cases": IncidentCase, "outbox": IntegrationOutboxRecord}


class StorageError(ValueError):
    """Bounded public contract error; never include payloads or identifiers."""


def require(condition, code):
    if not condition:
        raise StorageError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "storage_duplicate_json_key")
        result[key] = value
    return result


def parse(raw):
    def invalid_constant(_value):
        raise StorageError("storage_nonfinite_json")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_constant)


def read(path, limit):
    require(path.is_file() and not path.is_symlink(), "storage_regular_file_required")
    require(path.stat().st_size <= limit, "storage_size_limit")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "storage_size_limit")
    return raw


def capture(directory):
    directory = Path(directory)
    contract = directory / "storage.json"
    if not contract.exists():
        require(not contract.is_symlink() and not any((directory / name).exists() or
                (directory / name).is_symlink() for name in FILES.values()), "storage_contract_missing")
        return {}
    raw = read(contract, 4096)
    require(parse(raw) == CONTRACT, "storage_contract_invalid")
    return {"storage.json": raw, **{name: read(directory / name, MAX_LOG) for name in FILES.values()}}


def records(raw, kind):
    require(not raw or raw.endswith(b"\n"), "storage_partial_line")
    lines = raw.splitlines()
    require(len(lines) <= MAX_RECORDS, "storage_record_limit")
    previous, latest = "0" * 64, {}
    for line in lines:
        require(0 < len(line) <= MAX_LINE, "storage_line_size")
        envelope = parse(line)
        require(isinstance(envelope, dict) and set(envelope) == {
            "schema_version", "payload", "previous_hash", "record_hash"}, "storage_envelope")
        require(type(envelope["schema_version"]) is int and envelope["schema_version"] == 1 and
                all(isinstance(envelope[key], str) for key in ("payload", "previous_hash", "record_hash")),
                "storage_envelope")
        payload = envelope["payload"]
        require(envelope["previous_hash"] == previous and envelope["record_hash"] ==
                digest((previous + "." + payload).encode()), "storage_hash_chain")
        decoded = parse(payload)
        record = MODELS[kind].model_validate(decoded)
        if kind == "audit":
            key = record.tenant_id, record.analysis_id
            old = latest.get(key)
            require(old is None or old.event_id == record.event_id, "storage_analysis_identity")
        else:
            key = ((record.tenant_id, record.case_id) if kind == "cases" else
                   (record.event.tenant_id, record.event.id))
            old = latest.get(key)
            require(record.version == (old.version + 1 if old else 1), "storage_version_sequence")
            if kind == "outbox" and old is None:
                require(record.status == "PENDING" and record.attempt_count == 0,
                        "storage_outbox_initial_state")
            if old:
                require(record.history[:-1] == old.history, "storage_history_rewritten")
                if kind == "cases":
                    mutable = {"status", "assignee", "updated_at", "version", "history"}
                    require(record.model_dump(exclude=mutable) == old.model_dump(exclude=mutable)
                            and record.status in ALLOWED_TRANSITIONS[old.status], "storage_case_transition")
                else:
                    require(record.event == old.event and record.max_attempts == old.max_attempts,
                            "storage_outbox_identity")
                    require(old.status not in {"DELIVERED", "DEAD_LETTER"} and
                            record.attempt_count == old.attempt_count + 1 and
                            (old.next_attempt_at is None or record.history[-1].recorded_at >= old.next_attempt_at),
                            "storage_outbox_transition")
        latest[key] = record
        previous = envelope["record_hash"]
    return {"bytes": len(raw), "sha256": digest(raw), "lines": len(lines), "head": previous}, latest


def inspect(directory):
    blobs = capture(directory)
    if not blobs:
        return None
    files, latest = {}, {}
    for kind, name in FILES.items():
        files[name], latest[kind] = records(blobs[name], kind)
    for record in latest["outbox"].values():
        case = latest["cases"].get((record.event.tenant_id, record.event.subject))
        require(case is not None and record.event.data.case_version <= case.version,
                "storage_outbox_case_missing")
        require(record.event == _cloud_event(case, record.event.data.case_version),
                "storage_outbox_case_mismatch")
    # A case commit may precede its outbox commit. Keep that gap observable;
    # the existing reconciler can create the same deterministic event ID later.
    missing = sum((case.tenant_id, _cloud_event(case, entry.sequence).id) not in latest["outbox"]
        for case in latest["cases"].values() for entry in case.history)
    return {"contract_sha256": digest(blobs["storage.json"]), "files": files,
            "missing_case_events": missing}


def verify_prefix(directory, expected):
    current = inspect(directory)
    require(current is not None and current["contract_sha256"] == expected["contract_sha256"],
            "storage_admission_contract")
    for name, entry in expected["files"].items():
        require(name in FILES.values(), "storage_admission_file_scope")
        raw = read(Path(directory) / name, MAX_LOG)
        require(type(entry["bytes"]) is int and 0 <= entry["bytes"] <= len(raw) and
                digest(raw[:entry["bytes"]]) == entry["sha256"], "storage_admission_prefix")
    require(set(expected["files"]) == set(FILES.values()), "storage_admission_file_scope")
    return current
