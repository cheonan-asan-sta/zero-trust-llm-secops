"""Preserve observed public activity for detection without publishing source identifiers."""

import json
import re
from collections import defaultdict
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

from scripts import m7_public_cloudtrail as cloudtrail
from scripts import m7_public_cowrie as cowrie
from scripts.evaluate_m6 import canonical, digest, unique_fields

MAX_TEXT_CHARS = 8192
MAX_RESOURCE_IDS = 128
MAX_EVENTS_PER_GROUP = 10_000
IDENTIFIER_FIELDS = (
    "userName", "roleName", "roleArn", "policyArn", "functionName", "instanceId", "secretId",
    "tableName", "resourceArn", "stackName", "name",
)
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
URL_AUTH = re.compile(r"(https?://)[^\s/@]+(?::[^\s/@]*)?@")


def pseudonym(namespace, value):
    if not isinstance(value, str) or not value:
        return None
    return digest(canonical([namespace, value]))


def scoped_pseudonym(namespace, value, account):
    value = cloudtrail.logged_identifier(value)
    if value is None:
        return None
    return digest(canonical([namespace, account, value]))


def observed_text(value):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > MAX_TEXT_CHARS:
        raise ValueError("public_behavior_text_shape")
    # Commands remain data. Preserve shell structure but remove embedded address and URL credentials.
    value = URL_AUTH.sub(r"\1redacted@", value)
    return IPV4.sub(lambda match: "host_" + pseudonym("address", match[0])[:16], value)


def _base_event(record, event_hash, kind, connection_id, principal_hash):
    timestamp = record.get("timestamp", record.get("eventTime"))
    if cloudtrail.utc_timestamp(timestamp) is None:
        raise ValueError("public_behavior_missing_timestamp")
    if not isinstance(kind, str) or not kind:
        raise ValueError("public_behavior_missing_kind")
    return {
        "id": event_hash, "timestamp": timestamp, "kind": kind,
        "connection_id": connection_id, "principal_hash": principal_hash,
        "command": None, "resource_hashes": [], "api_service": None, "api_action": None,
        "error_code": None, "outcome": "unknown", "download_path": None, "destination": None,
    }


def cowrie_event(record):
    if cowrie.ANNOTATION_FIELDS & record.keys():
        raise ValueError("public_behavior_annotation_in_cowrie_event")
    event_hash = digest(canonical(record))
    kind = record.get("eventid")
    event = _base_event(
        record, event_hash, kind,
        pseudonym("cowrie_connection", record.get("session")),
        pseudonym("cowrie_username", record.get("username")),
    )
    if kind in {"cowrie.command.input", "cowrie.command.failed", "cowrie.command.success"}:
        event["command"] = observed_text(record.get("input"))
    if kind in {"cowrie.login.failed", "cowrie.command.failed", "cowrie.session.file_download.failed"}:
        event["outcome"] = "failure"
    if kind in {"cowrie.login.success", "cowrie.command.success", "cowrie.session.file_download"}:
        event["outcome"] = "success"
    if kind in {"cowrie.session.file_download", "cowrie.session.file_download.failed"}:
        event["download_path"] = observed_text(record.get("destfile"))
        event["destination"] = observed_text(record.get("url"))
    if kind.startswith("cowrie.direct-tcpip"):
        event["destination"] = pseudonym("network_destination", record.get("dst_ip"))
    return event


def cloudtrail_resources(record):
    parameters = record.get("requestParameters")
    parameters = parameters if isinstance(parameters, dict) else {}
    identity = record.get("userIdentity") or {}
    account = cloudtrail.logged_identifier(identity.get("accountId"))
    resources = set()
    bucket, key = parameters.get("bucketName"), parameters.get("key")
    if isinstance(bucket, str):
        target = ["s3_object", bucket, key] if isinstance(key, str) else ["s3_bucket", bucket]
        resources.add(digest(canonical(target)))
    else:
        for name in IDENTIFIER_FIELDS:
            value = scoped_pseudonym(name, parameters.get(name), account)
            if value is not None:
                resources.add(value)
    for resource in record.get("resources") or []:
        if not isinstance(resource, dict):
            raise TypeError("public_behavior_resource_shape")
        arn = resource.get("ARN")
        value = pseudonym("resource_arn", arn)
        if value is not None:
            resources.add(value)
    if len(resources) > MAX_RESOURCE_IDS:
        raise ValueError("public_behavior_resource_limit")
    return sorted(resources)


def cloudtrail_event(raw):
    record = {key: value for key, value in raw.items() if key not in cloudtrail.ANNOTATIONS}
    identity = record.get("userIdentity") or {}
    if not isinstance(identity, dict):
        raise TypeError("public_behavior_identity_shape")
    account = cloudtrail.logged_identifier(identity.get("accountId"))
    event_hash = digest(canonical(record))
    event = _base_event(
        record, event_hash, record.get("eventType") or "aws.api",
        scoped_pseudonym("cloudtrail_credential", identity.get("accessKeyId"), account),
        scoped_pseudonym("cloudtrail_principal", identity.get("principalId") or identity.get("arn"), account),
    )
    for field, source in (("api_service", "eventSource"), ("api_action", "eventName")):
        value = record.get(source)
        if value is not None and (not isinstance(value, str) or not cloudtrail.ACTION_TOKEN.fullmatch(value)):
            raise ValueError("public_behavior_api_name")
        event[field] = value
    event["resource_hashes"] = cloudtrail_resources(record)
    response = record.get("responseElements")
    response = response if isinstance(response, dict) else {}
    error = record.get("errorCode") or response.get("errorCode")
    event["error_code"] = observed_text(error)
    # CloudTrail describes a completed API request. A reported error indicates failure.
    # Error-free completion is an operation outcome, not identity ownership or access approval.
    if error or record.get("errorMessage") or response.get("errorMessage"):
        event["outcome"] = "failure"
    elif record.get("eventType") in {"AwsApiCall", "AwsServiceEvent"}:
        event["outcome"] = "success"
    return event


def _join_observations(references, events_by_group):
    if set(events_by_group) != {row["original_group_id"] for row in references}:
        raise ValueError("public_behavior_group_mismatch")
    rows = []
    for reference in references:
        group_id = reference["original_group_id"]
        events = events_by_group[group_id]
        if (not events or len(events) > MAX_EVENTS_PER_GROUP
                or sorted(event["id"] for event in events) != reference["event_hashes"]):
            raise ValueError("public_behavior_event_coverage")
        # Python's stable sort preserves source order for equal timestamps.
        events.sort(key=lambda event: cloudtrail.utc_timestamp(event["timestamp"]))
        observation = {
            "source": reference["source"], "original_group_id": group_id, "events": events,
        }
        rows.append(reference | {"observation": observation})
    return rows


def load_cowrie_behavior(path: Path):
    references, metadata = cowrie.load_cowrie(path)
    events = defaultdict(list)
    with ZipFile(path) as archive:
        for round_number in range(1, 25):
            source = archive.read(cowrie.PREFIX + f"r{round_number:02}_cowrie.json")
            for line in source.splitlines():
                record = json.loads(line, object_pairs_hook=unique_fields)
                group_id = digest(canonical([
                    "cowrie", cowrie.COMMIT, round_number, record["src_ip"],
                ]))
                events[group_id].append(cowrie_event(record))
    return _join_observations(references, events), metadata | {
        "behavior_projection": "Ordered observed commands, authentication and transfer events",
        "redaction": (
            "Login password/message fields omitted; actor/connection IDs hashed; command IPs and URL "
            "credentials redacted. Other command arguments remain bounded untrusted public data."
        ),
    }


def load_cloudtrail_behavior(path: Path, *, expected_sha256=cloudtrail.ARCHIVE_SHA256):
    if path.stat().st_size > cloudtrail.MAX_ARCHIVE_BYTES:
        raise ValueError("public_behavior_archive_size")
    archive_bytes = path.read_bytes()
    if digest(archive_bytes) != expected_sha256:
        raise ValueError("public_behavior_archive_hash")
    with ZipFile(BytesIO(archive_bytes)) as archive:
        members = [item for item in archive.infolist()
                   if not item.is_dir() and item.filename.lower().endswith(".json")]
        if len(members) != 1 or members[0].file_size > cloudtrail.MAX_MEMBER_BYTES:
            raise ValueError("public_behavior_archive_member")
        raw = archive.read(members[0])
    payload = json.loads(raw, object_pairs_hook=unique_fields)
    if not isinstance(payload, dict) or not isinstance(payload.get("Records"), list):
        raise TypeError("public_behavior_archive_records")
    records = payload["Records"]
    references, metadata = cloudtrail.normalize_records(records)
    events = defaultdict(list)
    seen = set()
    for raw_record in records:
        record = {key: value for key, value in raw_record.items() if key not in cloudtrail.ANNOTATIONS}
        event_hash = digest(canonical(record))
        if event_hash in seen:
            continue
        seen.add(event_hash)
        group = cloudtrail.credential_group(record, event_hash)
        if group[0] != "event_only":
            group_id = digest(canonical(("cloudtrail", group)))
            events[group_id].append(cloudtrail_event(record))
    return _join_observations(references, events), metadata | {
        "archive_sha256": expected_sha256, "json_member_sha256": digest(raw),
        "behavior_projection": "Ordered API requests with explicit outcomes and pseudonymous resources",
        "redaction": "Account, credential, actor and target identifiers hashed; request bodies omitted",
    }
