import copy

from scripts.audit_m7_public_holdout import audit_records
from scripts.evaluate_m6 import canonical, digest
from scripts.m7_public_cloudtrail import credential_group


def record(event_id, *, key="ASIA-old", principal="principal-a", time="2026-01-01T00:00:00Z"):
    return {
        "eventID": event_id, "eventTime": time, "eventName": "GetObject",
        "eventSource": "s3.amazonaws.com", "eventType": "AwsApiCall",
        "userIdentity": {"type": "AssumedRole", "accountId": "account-a",
                         "principalId": principal, "accessKeyId": key},
        "should_sample": False,
    }


def group_id(raw):
    clean = {key: value for key, value in raw.items() if key not in {"should_sample", "attack_name"}}
    return digest(canonical(("cloudtrail", credential_group(clean, digest(canonical(clean))))))


def test_shared_temporary_key_excludes_entire_group_without_matching_event():
    old = record("old")
    new = record("new", time="2026-02-01T00:00:00Z")
    new2 = record("new-2", time="2026-02-01T00:01:00Z")
    report = audit_records([old], [new, new2])
    assert report["shared_raw_event_hashes"] == 0
    assert report["shared_temporary_access_keys"] == 1
    assert report["excluded_group_ids"] == [group_id(new)]
    assert report["retained_candidate_groups"] == 0


def test_previously_excluded_event_only_keys_and_ids_still_exclude_candidates():
    old = record("reused-id", key="AKIA-hidden", principal=None)
    old["userIdentity"]["type"] = "Unknown"
    same_key = record("fresh-id", key="AKIA-hidden")
    same_id = record("reused-id", key="ASIA-fresh", principal="principal-b")
    report = audit_records([old], [same_key, same_id])
    assert report["prior_candidate_groups"] == 0
    assert report["shared_raw_event_hashes"] == 0
    assert report["shared_event_ids_with_different_payloads"] == 1
    assert set(report["excluded_group_ids"]) == {group_id(same_key), group_id(same_id)}
    assert report["excluded_groups_by_reason"] == {"same_access_key": 1, "same_event_id": 1}


def test_repeated_principal_in_distinct_actor_window_is_reported_not_excluded():
    old = record("old", key=None)
    new = record("new", key=None, time="2026-01-01T01:00:00Z")
    event_only = record("anonymous", key=None, principal=None)
    report = audit_records([old], [new, event_only])
    assert report["shared_principals"] == 1
    assert report["retained_groups_with_shared_principal"] == 1
    assert report["retained_candidate_groups"] == 1
    assert report["excluded_group_ids"] == []
    assert report["holdout_event_only"]["total_rows"] == 1


def test_annotation_change_cannot_hide_duplicate_or_change_exclusion():
    old = record("same")
    new = copy.deepcopy(old)
    new["should_sample"], new["attack_name"] = True, "SyntheticAttack"
    report = audit_records([old], [new])
    assert report["shared_raw_event_hashes"] == 1
    assert report["shared_event_ids_with_different_payloads"] == 0
    assert report["excluded_group_ids"] == [group_id(old)]
    serialized = str(report)
    assert "principal-a" not in serialized
    assert "ASIA-old" not in serialized
    assert "SyntheticAttack" not in serialized
