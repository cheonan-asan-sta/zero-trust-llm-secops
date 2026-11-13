import hashlib
from datetime import UTC, datetime

import pytest

from scripts import audit_vpn_observation_segments as driver
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import score, sha


def fixture(root):
    def write(name, value):
        path = root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical(value)+b'\n')
        return sha(path)
    frozen = write('freeze.json', {'archive_sha256': 'b'*64})
    raw_file = root/'raw/pair-0-raw.source'
    raw_file.parent.mkdir(parents=True)
    raw_file.write_text('2022-02-03 10:00:00 192.0.2.8:12345 TLS: Initial packet\n'
                        '2022-02-03 10:00:01 192.0.2.8:12345 TLS: Initial packet\n'
                        '2022-02-03 10:05:01 192.0.2.9:12345 TLS: Initial packet\n', encoding='utf8')
    raw_hash = sha(raw_file)
    audit_hash = write('raw/audit.json', {'completed': True, 'population': 3,
        'candidate_freeze_sha256': frozen, 'archive_sha256': 'b'*64,
        'timestamp_basis': 'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
        'pairs': [{'raw_rows': 3, 'provenance': {'kind': 'vpn', 'raw_sha256': raw_hash,
            'simulation_start': int(datetime(2022, 2, 3, tzinfo=UTC).timestamp()),
            'simulation_end': int(datetime(2022, 2, 5, tzinfo=UTC).timestamp())}}]})
    pred, truth = root/'prediction-packet/predictions.jsonl', root/'scoring/truth.jsonl'
    pred.parent.mkdir(parents=True)
    truth.parent.mkdir(parents=True)
    examples = [(False, True, True), (True, False, False), (False, True, False)]
    cases = [hashlib.sha256((raw_hash+':'+str(i+1)).encode()).hexdigest() for i in range(3)]
    pred.write_bytes(b''.join(canonical({'case_id': case, 'source_index': 0, 'before': before, 'after': after})+b'\n'
        for case, (_, before, after) in zip(cases, examples, strict=True)))
    truth.write_bytes(b''.join(canonical({'case_id': case, 'malicious': malicious})+b'\n'
        for case, (malicious, _, _) in zip(cases, examples, strict=True)))
    manifest = write('prediction-packet/prediction-manifest.json', {'phase': 'predictions_sealed',
        'candidate_freeze_sha256': frozen, 'raw_manifest_sha256': audit_hash, 'predictions_sha256': sha(pred)})
    scored = score(pred, truth, sha(pred), sha(truth))
    scored.update(completed=True, source_id='synthetic-vpn-support-control', prediction_manifest_sha256=manifest,
        candidate_freeze_sha256=frozen, truth_manifest={'truth_sha256': sha(truth)})
    return write('scoring/score.json', scored), manifest


def test_actual_sealed_file_path_preserves_line_metrics_and_exposes_mixed_segment(tmp_path):
    score_hash, manifest_hash = fixture(tmp_path)
    result = driver.run(tmp_path, score_hash, manifest_hash, tmp_path/'output')
    assert result['completed'] and result['vpn_population'] == result['whole_evaluation_population'] == 3
    item = result['per_source'][0]
    assert item['summary']['segments'] == 2 and item['summary']['mixed_label_segments'] == 1
    assert item['summary']['stages']['after']['threat_segments_missed'] == 1
    assert item['summary']['stages']['after']['threat_segments_with_only_normal_row_alerts'] == 1
    assert item['summary']['stages']['after']['normal_segments_quiet'] == 1
    assert item['line_metrics']['after']['fp'] == item['line_metrics']['after']['fn'] == 1
    assert sha(tmp_path/'scoring/score.json') == score_hash and not result['goal_qualified']
    assert result['rows_removed_from_evaluation'] == 0
    with pytest.raises(ValueError, match='fresh_output'):
        driver.run(tmp_path, score_hash, manifest_hash, tmp_path/'output')


@pytest.mark.parametrize('name', ['raw/pair-0-raw.source', 'prediction-packet/predictions.jsonl',
    'scoring/truth.jsonl', 'raw/audit.json', 'freeze.json', 'scoring/score.json',
    'prediction-packet/prediction-manifest.json'])
def test_tampering_never_publishes_a_support_result(tmp_path, name):
    score_hash, manifest_hash = fixture(tmp_path)
    path = tmp_path/name
    path.write_bytes(path.read_bytes()+b'\n')
    with pytest.raises(ValueError):
        driver.run(tmp_path, score_hash, manifest_hash, tmp_path/'output')
    assert not (tmp_path/'output').exists()
