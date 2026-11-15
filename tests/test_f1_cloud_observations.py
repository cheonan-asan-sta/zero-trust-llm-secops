import hashlib
import json

import pytest

from scripts.audit_cloud_training import audit
from scripts.f1_lab.cloud_observations import (
    label,
    observation,
    partition,
    partition_with_request_facts,
)


def record(mfa='false'):
    return {'eventID': 'event-1', 'eventTime': '2026-02-18T10:58:50Z', 'eventName': 'GetItem',
            'eventSource': 'dynamodb.amazonaws.com', 'readOnly': True, 'managementEvent': False,
            'userIdentity': {'type': 'AssumedRole', 'principalId': 'opaque-principal', 'sessionContext': {
                'sessionIssuer': {'type': 'Role', 'arn': 'arn:aws:iam::123456789012:role/Example'},
                'attributes': {'creationDate': '2026-02-18T10:00:00Z', 'mfaAuthenticated': mfa}}}}


def test_no_mfa_is_not_failed_mfa_or_unhealthy_inactive_identity():
    result = observation(record())
    assert result['features']['session_mfa_used'] is False
    assert all(value is None for value in result['unavailable_claims'].values())
    assert result['access_grants'] == result['session_changes'] == 0


@pytest.mark.parametrize('value', [None, 'False', 'yes', 0, []])
def test_unknown_mfa_values_not_coerced(value):
    assert observation(record(value))['features']['session_mfa_used'] is None


def test_positive_mfa_evidence_keeps_historical_scope_and_role_policy_missing():
    result = observation(record('true'))
    assert result['features']['session_mfa_used'] is True and result['features']['session_issuer_present']
    assert result['features']['historical_session_age_seconds'] == 3530
    assert result['unavailable_claims']['resource_required_role'] is None
    assert result['unavailable_claims']['identity_active'] is None
    assert 'opaque-principal' not in str(result) and 'role/Example' not in str(result)


def test_labels_and_response_credentials_never_change_inference_view():
    a, b = record(), record()
    a.update(should_sample=False)
    b.update(should_sample=True, attack_name='scenario', responseElements={'credentials': {'sessionToken': 'not-copied'}})
    first, gold_a = partition(a)
    second, gold_b = partition(b)
    assert first == second and gold_a['truth'] is False and gold_b['truth'] is True
    assert 'not-copied' not in str(second)
    with pytest.raises(ValueError, match='truth_in_inference'):
        observation(a)


def test_missing_label_or_conflicting_scenario_never_becomes_normal():
    assert label(record())['truth'] is None
    assert label({**record(), 'should_sample': 'false'})['truth'] is None
    assert label({**record(), 'should_sample': False, 'attack_name': 'contradiction'})['truth'] is None
    assert label({**record(), 'should_sample': True})['truth'] is None


def test_cloud_audit_keeps_known_label_observation_errors_and_unknown_rows(tmp_path):
    source = tmp_path/'source'
    source.mkdir()
    assets = []
    for index in range(2):
        data = [dict(record(), should_sample=False), record(), dict(record(), readOnly='false', should_sample=True, attack_name='scenario')]
        path = source/f'asset-{index}.json.source'
        path.write_text(json.dumps({'Records': data}))
        assets.append({'asset': {'path': f'TrainOn/file-{index}.zip'},
                       'member': {'bytes': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}})
    receipt = source/'acquisition.json'
    receipt.write_text(json.dumps({'completed': True, 'assets': assets, 'test_archive_downloaded': False}))
    result = audit(source, hashlib.sha256(receipt.read_bytes()).hexdigest(), tmp_path/'out')
    assert result['completed'] and result['test_records_read'] == 0 and not result['classifier_fitted']
    for asset in result['assets']:
        assert asset['counts']['records'] == 3 and asset['counts']['observation_errors'] == 1
        assert asset['counts']['truth_normal'] == asset['counts']['truth_unknown'] == asset['counts']['truth_attack'] == 1
    labels = [json.loads(row) for row in (tmp_path/'out/asset-0-truth.jsonl').read_bytes().splitlines()]
    assert len(labels) == 3 and labels[-1]['truth'] is True


def test_request_facts_keep_absence_unknown_and_do_not_copy_keys_or_credentials():
    item = {'eventName': 'PutObject', 'eventSource': 's3.amazonaws.com',
            'requestParameters': {'bucketName': 'secret-bucket', 'key': 'secret-path',
                                  'x-amz-acl': 'public-read', 'x-amz-server-side-encryption': 'AES256',
                                  'credentials': {'sessionToken': 'secret-token'}}}
    view, _ = partition_with_request_facts(item)
    assert view['features']['requested_s3_acl_scope'] == 'broad'
    assert view['features']['requested_s3_encryption_kind'] == 'AES256'
    assert 'secret-' not in str(view) and all(v is None for v in view['unavailable_claims'].values())
    absent, _ = partition_with_request_facts({**item, 'requestParameters': {}})
    assert absent['features']['requested_s3_acl_scope'] == absent['features']['requested_s3_encryption_kind'] == 'unknown'


def test_request_profile_is_label_independent_and_original_profile_stays_unchanged():
    first = {'eventName': 'PutObject', 'eventSource': 's3.amazonaws.com', 'should_sample': False,
             'requestParameters': {'x-amz-acl': 'private'}}
    second = {**first, 'should_sample': True, 'attack_name': 'scenario'}
    a, _ = partition_with_request_facts(first)
    b, _ = partition_with_request_facts(second)
    assert a == b and a['features']['requested_s3_acl_scope'] == 'limited'
    original, _ = partition(first)
    assert 'requested_s3_acl_scope' not in original['features']
    other, _ = partition_with_request_facts({**first, 'eventSource': 'other.amazonaws.com'})
    assert other['features']['requested_s3_acl_scope'] == 'unknown'
