import hashlib

import pytest

from scripts import run_dns_context_development as driver
from scripts.f1_lab.dns_context import PROFILE
from scripts.f1_lab.native_bayes import feature_domains
from scripts.f1_lab.native_binary_tree import NativeBinaryTree
from scripts.f1_lab.native_jsonl import decode
from scripts.f1_lab.operation_context import canonical, core_features
from scripts.f1_lab.raw_semantics import semantic_observations
from scripts.f1_lab.transfer_evaluation import sha


@pytest.mark.parametrize('host', [' resolver', ''])
def test_real_extraction_keeps_source_order_and_does_not_open_truth(tmp_path, host):
    raw_dir, prepared = tmp_path/'raw', tmp_path/'prepared'
    raw_dir.mkdir()
    prepared.mkdir()
    lines = [f'Jan 24 12:00:0{second}{host} dnsmasq[123]: query[A] n{index}.example from 192.0.2.1\n'
             for index, second in enumerate((0, 0, 1))]
    raw = raw_dir/'pair-0-raw.source'
    raw.write_text(''.join(lines), encoding='utf8', newline='')
    raw_hash = sha(raw)
    pairs = [{'raw_member': 'gather/resolver/logs/dnsmasq.log', 'raw_sha256': raw_hash, 'rows': 3}]
    audit = {'completed': True, 'timestamp_basis': 'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
        'pairs': [{'provenance': {**pairs[0], 'simulation_start': 1642982400, 'simulation_end': 1643068800}}]}
    (raw_dir/'audit.json').write_bytes(canonical(audit)+b'\n')
    cases = [hashlib.sha256((raw_hash+':'+str(index+1)).encode()).hexdigest() for index in range(3)]
    inputs = prepared/'inputs.jsonl'
    inputs.write_bytes(b''.join(canonical({'case_id': case, 'features': {**core_features(line), **semantic_observations(line)},
        'observation_error': None})+b'\n' for case, line in zip(cases, lines, strict=True)))
    # Deliberately invalid truth: extraction must not read it.
    (prepared/'truth.jsonl').write_bytes(b'not valid JSON and never an extraction input')
    preparation = {'pairs': pairs, 'source_manifest_sha256': sha(raw_dir/'audit.json'),
        'files': {'inputs.jsonl': {'sha256': sha(inputs)}}}
    (prepared/'preparation.json').write_bytes(canonical(preparation)+b'\n')
    baseline = tmp_path/'baseline.jsonl'
    baseline.write_bytes(b''.join(canonical({'case_id': case, 'source_index': 0, 'after': False,
        'after_score': .1, 'error': None})+b'\n' for case in cases))
    spec = {'prepared': str(prepared), 'raw_directory': str(raw_dir), 'baseline': str(baseline),
        'baseline_sha256': sha(baseline), 'preparation_sha256': sha(prepared/'preparation.json')}
    result = driver.extract(spec, tmp_path/'extracted')
    rows = list(driver.rows(tmp_path/'extracted/inputs.jsonl'))
    assert result['population'] == 3 and result['observation_errors'] == 0
    assert not result['labels_opened_by_extractor'] and [r['case_id'] for r in rows] == cases
    assert [r['features']['dns_peer_queries_1s'] for r in rows] == [0, 0, 1]
    assert not (tmp_path/'extracted/truth.jsonl').exists()
    raw.write_bytes(raw.read_bytes()+b'forged extra row')
    with pytest.raises(ValueError, match='raw_or_baseline_hash'):
        driver.extract(spec, tmp_path/'bad-extraction')


def tree_control():
    normal = {name: values[0] for name, values in feature_domains(PROFILE).items()}
    normal['dns_semantic_available'] = True
    abnormal = {**normal, 'dns_record_type': 'TXT'}
    tree = NativeBinaryTree(**driver.CONFIG)
    for _ in range(6):
        tree.observe_training(normal, False)
        tree.observe_training(abnormal, True)
    tree.fit()
    return tree, normal, abnormal


def test_additive_prediction_preserves_existing_alerts_and_every_error_row(tmp_path):
    tree, normal, abnormal = tree_control()
    inputs = tmp_path/'inputs.jsonl'
    values = [(normal, True, .96, None), (abnormal, False, .1, None),
              (normal, False, .1, None), (None, None, None, 'old_inference_error'),
              ({**abnormal, 'dns_semantic_available': False}, False, .1, None)]
    inputs.write_bytes(b''.join(canonical({'case_id': str(i)*64, 'source_index': 1, 'features': f,
        'before': decision, 'before_score': probability, 'error': error})+b'\n'
        for i, (f, decision, probability, error) in enumerate(values)))
    predictions = tmp_path/'predictions.jsonl'
    result = driver.predict(inputs, sha(inputs), tree, predictions)
    rows = list(driver.rows(predictions))
    assert [row['after'] for row in rows] == [True, True, False, None, False]
    assert result['population'] == 5 and result['inference_errors'] == 1
    assert rows[0]['after_score'] >= .96 and rows[1]['after_score'] == 1.
    assert not result['labels_opened_by_predictor'] and not result['automatic_enforcement_allowed']
    with pytest.raises(ValueError, match='input_hash'):
        driver.predict(inputs, 'a'*64, tree, tmp_path/'bad-predictions.jsonl')


def test_training_rejects_reordered_labels_instead_of_fitting(tmp_path):
    _, normal, abnormal = tree_control()
    inputs, truth = tmp_path/'inputs.jsonl', tmp_path/'truth.jsonl'
    inputs.write_bytes(b''.join(canonical({'case_id': str(i)*64, 'features': f, 'error': None})+b'\n'
        for i, f in enumerate((normal, abnormal))))
    truth.write_bytes(b''.join(canonical({'case_id': str(i)*64, 'malicious': bool(i)})+b'\n' for i in (1, 0)))
    with pytest.raises(ValueError, match='binding_or_error'):
        driver.fit(tmp_path, sha(inputs), sha(truth))
    assert decode(next(iter(inputs.read_bytes().splitlines())))['case_id'] == '0'*64
