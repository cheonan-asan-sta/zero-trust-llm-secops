import json
import shutil

import pytest

from scripts import prepare_f1_review as review


@pytest.fixture(scope='module')
def frozen(tmp_path_factory):
    destination = tmp_path_factory.mktemp('f1-baseline') / 'candidate'
    result = review.create(destination, author='implementation-author')
    return destination, result


@pytest.fixture
def kit(tmp_path, frozen):
    source, result = frozen
    destination = tmp_path / 'review'
    shutil.copytree(source, destination)
    return destination, result['freeze_sha256']


def lines(path):
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def write(directory, rows):
    (directory / 'reviews.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf8')


def completed(directory):
    rows = lines(directory / 'reviews.jsonl')
    for row in rows:
        row.update(reviewer_subject='test-reviewer', cause='other', label_assessment='insufficient',
                   evidence_case_ids=[row['case_ids'][0]], rationale='Fixture only; no actual human review.',
                   proposed_change='Inspect source evidence before any proposed change.',
                   counterexample='Compare an independent legitimate business session.')
    return rows


def test_baseline_freeze_reproduces_original_metrics_and_keeps_detector_unchanged(frozen):
    directory, result = frozen
    manifest = review.verify(directory, result['freeze_sha256'])
    assert result['quality_targets_met'] is False
    assert result['confusion'] == {
        'development': {'tp': 170, 'fp': 50, 'fn': 10, 'tn': 130},
        'holdout': {'tp': 90, 'fp': 50, 'fn': 90, 'tn': 130}}
    assert manifest['new_blind_evaluation'] is False
    assert manifest['independent_review'] == 'pending'
    for name, payload in review.sources().items():
        assert (directory / 'source' / name).read_bytes() == payload


def test_trace_exposes_missed_expected_rule_even_when_another_rule_fires(frozen):
    directory, _ = frozen
    row = next(r for r in lines(directory / 'evidence.jsonl') if r['family_id'] == 'lateral-slow-fanout')
    assert row['outcome'] == 'TP'
    assert row['missed_expected_rule_ids']
    missing = next(t for t in row['rule_traces'] if t['rule_id'] in row['missed_expected_rule_ids'])
    assert missing['matched'] is False
    assert missing['selectors']['selection_behavior']['matched'] is False
    assert 'ground_truth' not in row['observed_input']
    assert 'expected_rule_ids' not in row['observed_input']


def test_missing_threshold_is_a_mechanical_fact_not_automatic_cause_or_approval(frozen):
    directory, _ = frozen
    row = next(r for r in lines(directory / 'evidence.jsonl') if r['family_id'] == 'credential-distributed-slow')
    trace = row['rule_traces'][0]
    fields = trace['selectors']['selection_auth']['branches'][0]['fields']
    failed = next(f for f in fields if f['expression'] == 'unmapped.auth.failed_attempts|gte')
    assert failed['actual'] in {1, 2} and failed['expected'] == 3 and not failed['matched']
    assert row['diagnosis_status'] == 'mechanical_trace_only_pending_human_review'


@pytest.mark.parametrize('name', [
    'holdout.json', 'evidence.jsonl', 'review-index.json',
    'source/app/data/sigma/credential_anomaly.yml', 'source/app/data/benchmark/cases.jsonl',
    'source/app/services/ocsf.py'])
def test_frozen_report_source_or_evidence_tampering_is_rejected(kit, name):
    directory, anchor = kit
    with (directory / name).open('ab') as stream:
        stream.write(b'\n')
    with pytest.raises(ValueError, match='frozen_file_changed'):
        review.verify(directory, anchor)


def test_wrong_anchor_and_extra_file_cannot_rebaseline_the_bundle(kit):
    directory, anchor = kit
    with pytest.raises(ValueError, match='external_anchor'):
        review.verify(directory, '0' * 64)
    (directory / 'extra.json').write_text('{}')
    with pytest.raises(ValueError, match='file_inventory'):
        review.verify(directory, anchor)


def test_blank_reviews_are_pending_and_fixture_completion_never_certifies_a_person(kit):
    directory, anchor = kit
    initial = review.assess(directory, anchor)
    assert initial['pending'] == initial['review_families'] and initial['reviewed'] == 0
    assert initial['ready_for_team_adjudication'] is False
    write(directory, completed(directory))
    result = review.assess(directory, anchor)
    assert result['ready_for_team_adjudication'] and result['pending'] == 0
    assert result['independent_review_verified'] is False
    assert result['label_approval'] == 'pending'


@pytest.mark.parametrize('damage', ['self', 'other_case', 'duplicate_family', 'wrong_cases',
                                    'empty_reason', 'unknown_cause', 'extra_field', 'missing_row'])
def test_reviews_need_real_scope_evidence_reason_and_different_subject(kit, damage):
    directory, anchor = kit
    rows = completed(directory)
    if damage == 'self':
        rows[0]['reviewer_subject'] = ' IMPLEMENTATION-AUTHOR '
    elif damage == 'other_case':
        rows[0]['evidence_case_ids'] = rows[1]['evidence_case_ids']
    elif damage == 'duplicate_family':
        rows[0] = rows[1]
    elif damage == 'wrong_cases':
        rows[0]['case_ids'] = rows[1]['case_ids']
    elif damage == 'empty_reason':
        rows[0]['counterexample'] = ''
    elif damage == 'unknown_cause':
        rows[0]['cause'] = 'raise_score_without_evidence'
    elif damage == 'extra_field':
        rows[0]['approved'] = True
    else:
        rows.pop()
    write(directory, rows)
    with pytest.raises(ValueError):
        review.assess(directory, anchor)


def test_no_overwrite_of_existing_bundle(frozen):
    directory, _ = frozen
    with pytest.raises(ValueError, match='fresh_directory'):
        review.create(directory, author='implementation-author')


def test_source_change_during_generation_never_publishes_a_candidate(tmp_path, monkeypatch):
    original = review.sources
    calls = []

    def changed():
        captured = original()
        if calls:
            captured['app/models.py'] += b'\n'
        calls.append(True)
        return captured

    monkeypatch.setattr(review, 'sources', changed)
    destination = tmp_path / 'candidate'
    with pytest.raises(ValueError, match='source_changed_during_run'):
        review.create(destination, author='implementation-author')
    assert not destination.exists()
    assert not list(tmp_path.iterdir())
