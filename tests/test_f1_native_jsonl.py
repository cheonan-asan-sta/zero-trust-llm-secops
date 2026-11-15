import hashlib
import json

import pytest

from scripts.f1_lab.native_jsonl import RawReference, alert, scan


def source(tmp_path, body):
    path = tmp_path/'source.jsonl'
    path.write_bytes(body)
    return path, hashlib.sha256(body).hexdigest()


def wazuh():
    return {'@timestamp': '2022-01-21T00:02:27.000000Z', 'agent': {'ip': '192.0.2.1'},
            'rule': {'level': 3, 'description': 'software update'}, 'location': '/var/log/syslog',
            'full_log': 'Jan 21 update completed'}


def aminer():
    return {'LogData': {'RawLogData': ['one', 'two'], 'LogResources': ['/var/log/auth.log'],
                        'Timestamps': [1642723201, 1642723203], 'DetectionTimestamp': [1642723210]},
            'AMiner': {'ID': '192.0.2.1'}, 'AnalysisComponent': {'AnalysisComponentName': 'new event'}}


def test_exact_source_and_every_physical_row(tmp_path):
    path, sha = source(tmp_path, b'{"a":1}\r\n\n{"a":2}')
    rows = []
    report = scan(path, sha, rows.append)
    assert report['physical_rows'] == 3 and report['parse_errors'] == 1
    assert [r.ordinal for r in rows] == [1, 2, 3]
    assert rows[0].sha256 == hashlib.sha256(b'{"a":1}\r\n').hexdigest()
    assert rows[1].error == 'invalid_json' and rows[2].value == {'a': 2}
    assert report['source_verified_before_and_after'] and not report['goal_qualified']


@pytest.mark.parametrize('body', [b'{"a":1,"a":2}\n', b'{"a":NaN}\n', b'{"a":1e999}\n',
                                  b'[]\n', b'null\n', b'\xff\n'])
def test_malformed_rows_count_and_continue(tmp_path, body):
    path, sha = source(tmp_path, body+b'{"ok":true}\n')
    rows = []
    report = scan(path, sha, rows.append)
    assert report['physical_rows'] == 2 and report['parse_errors'] == 1
    assert rows[0].value is None and rows[0].error and rows[1].value == {'ok': True}


def test_oversized_row_drained_boundedly_without_losing_next_row(tmp_path):
    body = b'x'*100+b'\n'
    path, sha = source(tmp_path, body+b'{}\n')
    rows = []
    report = scan(path, sha, rows.append, max_row_bytes=8)
    assert report['physical_rows'] == 2 and report['parse_errors'] == 1
    assert rows[0].error == 'row_bound' and rows[0].sha256 == hashlib.sha256(body).hexdigest()
    assert rows[1].value == {}


def test_wrong_anchor_rejected_before_callbacks(tmp_path):
    path, _ = source(tmp_path, b'{}\n')
    rows = []
    with pytest.raises(ValueError, match='file_hash'):
        scan(path, '0'*64, rows.append)
    assert not rows


def test_source_change_during_callback_invalidates_entire_scan(tmp_path):
    path, sha = source(tmp_path, b'{}\n{}\n')
    def changed(_row):
        # On a buffered reader a future line may already be cached; append is
        # still seen at EOF and the final byte count/hash must reject it.
        if path.stat().st_size == 6:
            with path.open('ab') as stream:
                stream.write(b'{}\n')
    with pytest.raises(ValueError, match='source_changed'):
        scan(path, sha, changed)


def test_row_budget_is_failure_not_a_truncated_success(tmp_path):
    path, sha = source(tmp_path, b'{}\n{}\n')
    with pytest.raises(ValueError, match='row_count_bound'):
        scan(path, sha, lambda _: None, max_rows=1)


def test_wazuh_only_explicit_observations_no_healthy_defaults():
    item = alert(wazuh(), 'wazuh')
    assert item.severity == 3 and item.entity_reference == '192.0.2.1'
    assert item.raw_references[0].text == 'Jan 21 update completed'
    assert all(v is None for v in item.trust_claims.values())
    features = item.model_features()
    assert features['sensor'] == 'wazuh' and features['severity'] == 3
    assert features['finding_families']['software_update']
    assert 'finding' not in features
    assert '192.0.2.1' not in json.dumps(features) and '2022' not in json.dumps(features)


def test_no_full_log_preserves_missing_reference():
    data = wazuh()
    del data['full_log']
    assert alert(data, 'wazuh').raw_references == ()


def test_description_identifiers_do_not_become_memorization_features():
    data = wazuh()
    data['rule']['description'] = 'Failed password for alice@company on 192.0.2.10 at 2022-01-21'
    features = alert(data, 'wazuh').model_features()
    assert features['finding_families']['authentication_failure']
    assert all(secret not in json.dumps(features) for secret in ['alice', 'company', '192.0.2.10', '2022'])


@pytest.mark.parametrize('key', ['labels', 'label', 'ground_truth', 'event_label', 'time_label'])
def test_no_truth_field_allowed_even_null(key):
    data = wazuh()
    data[key] = None
    with pytest.raises(ValueError, match='truth_in_input'):
        alert(data, 'wazuh')


@pytest.mark.parametrize('level', [True, -1, 17, '3', None])
def test_severity_not_coerced(level):
    data = wazuh()
    data['rule']['level'] = level
    with pytest.raises(ValueError, match='severity'):
        alert(data, 'wazuh')


def test_unzoned_time_not_local_timezone_guess():
    data = wazuh()
    data['@timestamp'] = '2022-01-21T00:02:27'
    with pytest.raises(ValueError, match='timezone_required'):
        alert(data, 'wazuh')


def test_aminer_keeps_observation_and_detection_time_separate():
    item = alert(aminer(), 'aminer')
    assert item.event_time == 1642723203 and item.detection_time == 1642723210
    assert item.severity is None and len(item.raw_references) == 2
    assert item.raw_references[1].source_location == '/var/log/auth.log'
    assert all(v is None for v in item.trust_claims.values())


def test_aminer_parallel_locations():
    data = aminer()
    data['LogData']['LogResources'] = ['/one', '/two']
    assert alert(data, 'aminer').raw_references[1].source_location == '/two'


@pytest.mark.parametrize('value', [[], [1, 2, 3]])
def test_aminer_ambiguous_locations_rejected(value):
    data = aminer()
    data['LogData']['LogResources'] = value
    with pytest.raises(ValueError, match='aminer_arrays'):
        alert(data, 'aminer')


def test_raw_join_does_not_strip_meaningful_spaces():
    assert RawReference('a\r\n', '/x').content_sha256 == RawReference('a', '/x').content_sha256
    assert RawReference('a ', '/x').content_sha256 != RawReference('a', '/x').content_sha256
