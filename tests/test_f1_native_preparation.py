import hashlib
import json

import pytest

from scripts.prepare_native_alerts import prepare


def test_gold_fields_never_copied_and_error_rows_remain(tmp_path):
    data = {'@timestamp': '2022-01-21T00:02:27Z', 'agent': {'ip': '192.0.2.1'},
            'rule': {'level': 3, 'description': 'software update'},
            'location': '/var/log/syslog', 'full_log': 'update done'}
    contaminated = {**data, 'ground_truth': 'benign'}
    source = tmp_path/'source'
    source.write_bytes(b'\n'.join(json.dumps(row).encode() for row in [data, contaminated])+b'\ninvalid\n')
    sha = hashlib.sha256(source.read_bytes()).hexdigest()
    output = tmp_path/'result'
    report = prepare(source, sha, 'wazuh', output)
    observations = [json.loads(row) for row in (output/'inputs.jsonl').read_bytes().splitlines()]
    refs = [json.loads(row) for row in (output/'references.jsonl').read_bytes().splitlines()]
    assert report['completed'] and report['scan']['physical_rows'] == 3
    assert len(observations) == len(refs) == 3
    assert observations[0]['features']['finding_families']['software_update']
    assert observations[1]['observation_error'] == 'unsupported_sensor_observation'
    assert observations[2]['observation_error'] == 'invalid_json'
    assert all(row['features'] is None for row in observations[1:])
    assert all(value is None for value in observations[0]['trust_claims'].values())
    assert not report['truth_in_inputs'] and not report['goal_qualified']
    assert '192.0.2.1' not in (output/'inputs.jsonl').read_text()
    assert 'ground_truth' not in (output/'inputs.jsonl').read_text()
    assert refs[0]['entity_reference'] == '192.0.2.1' and refs[0]['source_line'] == 1
    assert observations[0]['case_id'] == refs[0]['case_id']
    assert report['files']['inputs.jsonl']['sha256'] == hashlib.sha256((output/'inputs.jsonl').read_bytes()).hexdigest()


def test_failed_source_never_published_as_completed_inputs(tmp_path):
    source = tmp_path/'source'
    source.write_bytes(b'{}\n')
    output = tmp_path/'result'
    with pytest.raises(ValueError, match='file_hash'):
        prepare(source, '0'*64, 'wazuh', output)
    assert not (output/'inputs.jsonl').exists()
    assert not json.loads((output/'preparation.json').read_bytes())['completed']


def test_existing_output_not_overwritten(tmp_path):
    output = tmp_path/'result'
    output.mkdir()
    with pytest.raises(ValueError, match='fresh_directory'):
        prepare(tmp_path/'none', '0'*64, 'aminer', output)
