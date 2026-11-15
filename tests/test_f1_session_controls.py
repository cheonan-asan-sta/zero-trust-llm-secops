import ast
import json
from pathlib import Path

import pytest

from scripts.f1_lab import session_controls as controls


@pytest.fixture
def dataset(tmp_path):
    directory = tmp_path / 'dataset'
    result = controls.prepare(directory, variants=1)
    return directory, result


def test_sessions_and_labels_are_separate_fixed_and_not_called_independent(dataset):
    directory, result = dataset
    manifest = controls.verify(directory, result['manifest_sha256'])
    assert manifest['sessions'] == manifest['family_count'] == 32
    assert manifest['normal'] == 14 and manifest['threat'] == 18
    assert manifest['independent_review'] == 'pending' and not manifest['new_independent_evaluation']
    inputs = [json.loads(line) for line in (directory / 'inputs.jsonl').read_bytes().splitlines()]
    for row in inputs:
        assert set(row) == {'case_id', 'session_id', 'tenant_id', 'events'}
        assert all('ground_truth' not in event and not event['behavior']['policy_exception_approved'] for event in row['events'])


def test_generator_never_imports_a_detector_or_scores_to_derive_labels():
    tree = ast.parse(Path(controls.__file__).read_text(encoding='utf8'))
    modules = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any('detector' in name or 'evaluate' in name or 'detection_benchmark' in name for name in modules)


def test_seed_changes_identity_order_without_changing_label_support():
    first = controls.build(variants=2, seed=1)
    second = controls.build(variants=2, seed=2)
    assert first[0] != second[0]
    assert sum(r['threat'] for r in first[1]) == sum(r['threat'] for r in second[1]) == 36
    assert {r['family_id'] for r in first[1]} == {r['family_id'] for r in second[1]}


def test_signed_looking_business_plan_is_not_a_perfect_normal_label_proxy():
    _inputs, labels, plans = controls.build(variants=1)
    truth = {row['case_id']: row['threat'] for row in labels}
    assert any(truth[plan['case_id']] for plan in plans)
    assert any(not truth[plan['case_id']] for plan in plans)
    assert all(plan['approval_source'] == 'simulated_operator_plan_not_real_organizational_approval' for plan in plans)


@pytest.mark.parametrize('name', controls.FILES)
def test_changed_frozen_input_truth_or_plan_bytes_are_rejected(dataset, name):
    directory, result = dataset
    with (directory / name).open('ab') as stream:
        stream.write(b'\n')
    with pytest.raises(ValueError):
        controls.verify(directory, result['manifest_sha256'])


def test_wrong_anchor_or_existing_output_is_rejected(dataset):
    directory, _result = dataset
    with pytest.raises(ValueError):
        controls.verify(directory, '0'*64)
    with pytest.raises(ValueError):
        controls.prepare(directory)


@pytest.mark.parametrize('variants', [0, -1, 9, True])
def test_unsupported_dataset_size_is_rejected(variants):
    with pytest.raises(ValueError):
        controls.build(variants=variants)
