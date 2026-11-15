import csv
import hashlib
import json

import pytest

from scripts.audit_contextual_source import audit, declared_claim_fields
from scripts.f1_lab.contextual_links import Components, links, truth


def message(user='alice'):
    return {'User': user, 'SessionId': 'session-a', 'Fingerprint': {'ua': 'browser', 'platform': 'platform', 'deviceType': 'desktop'},
            'RequestMetadata': {'method': 'GET', 'url': 'https://service/items/123?nonce=one'}, 'JSON': {'name': 'same'}}


def test_labels_and_derived_risk_fields_do_not_change_linkage():
    a = message()
    b = {**a, 'Suspicious': True, 'SuspiciousDescription': 'attack', 'HashCheck': False, 'EventType': 'BadRequest'}
    assert links(a) == links(b)


def test_unknown_truth_never_coerced_and_conflicting_aliases_not_chosen():
    for value in ({}, {'Suspicious': None}, {'Suspicious': 'false'}, {'Suspicious': 0},
                  {'Suspicious': True, 'suspicious': False}, {'Suspicious': []}):
        assert truth(value) is None
    assert truth({'Suspicious': False}) is False and truth({'Suspicious': True}) is True


def test_ip_is_not_assumed_to_be_device_identity():
    a = message()
    b = {**a, 'IP': '192.0.2.1', 'FingerprintHMAC': 'unverified', 'Fingerprint': {**a['Fingerprint'], 'ts': 'future'}}
    assert links(a) == links(b)


def test_request_payload_content_not_just_shared_route_or_json_schema():
    a = message()
    b = {**a, 'JSON': {'name': 'different'}}
    assert links(a)['request_template'] != links(b)['request_template']
    c = {**a, 'RequestMetadata': {'method': 'GET', 'url': 'https://other/items/456?nonce=two'}}
    assert links(a)['request_template'] == links(c)['request_template']


def test_bad_url_preserves_identity_and_counts_template_error():
    value = message()
    value['RequestMetadata']['url'] = 'https://[invalid'
    result = links(value)
    assert len(result['identity']) == 2 and result['template_error'] and result['request_template'] is None


def test_placeholder_identity_does_not_connect_every_anonymous_event():
    result = links({'User': 'anonymous', 'SessionId': '00000000-0000-0000-0000-000000000000'})
    assert result['identity'] == []


def test_taint_propagates_through_alias_edges_and_keeps_unlinked_separate():
    groups = Components()
    groups.add(['u:a'], development_probe=True)
    groups.add(['u:a', 's:b'], development_probe=False)
    groups.add(['s:b', 'u:c'], development_probe=False)
    groups.add([], development_probe=False)
    assert groups.summary()['probe_tainted_rows'] == 3
    assert groups.summary()['unlinked_rows'] == 1 and groups.summary()['remaining_linked_untouched_rows'] == 0
    assert not groups.summary()['final_partition_certified']


def test_untrusted_request_claims_are_not_counted_as_authoritative_metadata():
    value = {'JSON': {'isManaged': True, 'MFA': True}, 'UserContext': {'isActive': True},
             'SuspiciousDescription': {'businessApproval': True}}
    assert declared_claim_fields(value) == [('UserContext.isActive', 'bool')]


def source(tmp_path):
    path = tmp_path/'data.csv'
    a, b = message(), message('bobby')
    del b['SessionId']
    a['Suspicious'], b['Suspicious'] = True, False
    with path.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['time', 'host', 'source', 'sourcetype', 'message'])
        for value in (a, b, 'not json'):
            writer.writerow(['time', 'host', 'source', 'kind', json.dumps(value) if isinstance(value, dict) else value])
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_metadata_audit_retains_unknown_and_distinguishes_profile_from_identity(tmp_path):
    path, sha = source(tmp_path)
    result = audit(path, sha, tmp_path/'out', development_probe=1)
    assert result['completed'] and result['counts']['records'] == 3
    assert result['counts']['truth_unknown'] == result['counts']['truth_attack'] == result['counts']['truth_normal'] == 1
    assert result['linkage']['identity']['probe_tainted_rows'] == 1
    assert result['linkage']['identity_profile']['probe_tainted_rows'] == 2
    assert result['later_bodies_displayed'] == 0 and not result['classifier_fitted'] and not result['goal_qualified']
    assert 'alice' not in (tmp_path/'out/audit.json').read_text()


def test_wrong_source_hash_never_publishes_completed_audit(tmp_path):
    path, _sha = source(tmp_path)
    with pytest.raises(ValueError, match='context_csv_hash'):
        audit(path, '0'*64, tmp_path/'out')
    assert not json.loads((tmp_path/'out/audit.json').read_bytes())['completed']
