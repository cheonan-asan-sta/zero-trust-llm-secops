import json
import sys
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.services.detection_benchmark import DetectionBenchmark
from scripts import prepare_f1_intake as intake


@pytest.fixture
def bundle(tmp_path):
    root = tmp_path/'bundle'
    root.mkdir()
    inputs, labels = [], []
    base = DetectionBenchmark().cases[0].event.analysis_payload()
    for index, split in enumerate(intake.SPLITS):
        for threat in (False, True):
            ident = ('threat-' if threat else 'normal-')+str(index)
            event = deepcopy(base)
            event.update(event_id='event-'+ident, timestamp=f'2026-11-0{index+1}T00:00:00Z', action='READ')
            event['user'].update(user_id='user-'+ident, active=not threat, role='employee')
            event['device'].update(device_id='device-'+ident, managed=True, security_posture='healthy')
            event['resource'].update(resource_id='resource-'+ident, sensitivity=('public', 'internal', 'high')[index], required_role='employee')
            event['auth_context'].update(mfa='success', authentication_result='success', failed_attempts=0)
            inputs.append({'case_id': ident, 'tenant_id': 'test-tenant', 'session_id': 'session-'+ident, 'events': [event]})
            labels.append({'case_id': ident, 'split': split, 'family_id': 'family-'+ident,
                'label': 'threat' if threat else 'normal', 'label_origin': 'author_assigned',
                'expected_rule_ids': [intake.RULE_IDS['credential']] if threat else [],
                'evidence_event_ids': [event['event_id']], 'rationale': 'Authored intake fixture, not an independent label.'})
    origin = {'kind': 'controlled_regression', 'creator_subject': 'test-author', 'reference': 'local test fixture',
        'license_or_permission': 'local test data only', 'collection_method': 'constructed solely for contract regression',
        'event_semantics_asserted': 'event_deltas', 'transformations': []}

    def write():
        raw = {'observations.jsonl': b''.join(intake.canonical(row)+b'\n' for row in inputs),
            'labels.jsonl': b''.join(intake.canonical(row)+b'\n' for row in labels), 'origin.json': intake.canonical(origin)}
        for name, body in raw.items():
            (root/name).write_bytes(body)
        manifest = {'schema_version': 'f1-raw-intake-1', 'metric_unit': 'session_any_alert',
            'data_role': 'candidate_before_independent_review', 'files': {n: intake.digest(v) for n, v in raw.items()}}
        payload = intake.canonical(manifest)
        (root/'manifest.json').write_bytes(payload)
        return intake.digest(payload)

    return root, inputs, labels, origin, write


def prepared(bundle, tmp_path):
    root, _inputs, _labels, _origin, write = bundle
    directory = tmp_path/'intake'
    result = intake.prepare(root, write(), directory)
    return directory, result['review_contract_sha256']


def test_intake_validates_structure_without_copying_inputs_or_claiming_quality(bundle, tmp_path):
    root, _inputs, _labels, _origin, write = bundle
    anchor = write()
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    destination = tmp_path/'intake'
    result = intake.prepare(root, anchor, destination)
    report = json.loads((destination/'intake-report.json').read_bytes())
    assert report['cases'] == 6 and report['events'] == 6 and report['structural_checks_passed']
    assert report['labels_asserted'] == {'normal': 3, 'threat': 3}
    assert report['material_security_fields_defaulted'] == report['raw_source_files_copied'] == report['inference_runs'] == 0
    assert report['metric_values'] is None and not report['final_evaluation_ready']
    assert not report['source_provenance_verified'] and not report['issuer_attestation_verified']
    assert not report['planned_target_support']['final_candidate']['planned_family_support_met']
    assert before == {p.name: p.read_bytes() for p in root.iterdir()}
    assert {p.name for p in destination.iterdir()} == {'contract.json', 'intake-report.json', 'reviews.jsonl'}
    assessment = intake.assess(destination, result['review_contract_sha256'], bundle=root)
    assert assessment['pending'] == 6 and assessment['review_records_complete'] == 0 and not assessment['goal_qualified']


@pytest.mark.parametrize('context,field', [('user', 'active'), ('device', 'managed'), ('auth_context', 'mfa'),
    ('auth_context', 'failed_attempts'), ('resource', 'sensitivity'), ('behavior', 'download_volume_mb')])
def test_missing_material_fields_are_not_filled_with_normal_defaults(bundle, tmp_path, context, field):
    root, inputs, _labels, _origin, write = bundle
    del inputs[0]['events'][0][context][field]
    with pytest.raises(ValueError, match='material_security_fields'):
        intake.prepare(root, write(), tmp_path/'intake')
    assert not (tmp_path/'intake').exists()


def test_nonboolean_claim_cannot_be_coerced_to_a_normal_security_state(bundle, tmp_path):
    root, inputs, _labels, _origin, write = bundle
    inputs[0]['events'][0]['user']['active'] = 'true'
    with pytest.raises(ValueError):
        intake.prepare(root, write(), tmp_path/'intake')


def test_opposite_label_patterns_and_unknowns_remain_visible_in_the_full_population(bundle, tmp_path):
    root, inputs, labels, _origin, write = bundle
    event = deepcopy(inputs[0]['events'][0])
    event['event_id'] = inputs[-1]['events'][0]['event_id']
    event['timestamp'] = inputs[-1]['events'][0]['timestamp']
    event['user']['user_id'] = inputs[-1]['events'][0]['user']['user_id']
    event['device']['device_id'] = inputs[-1]['events'][0]['device']['device_id']
    inputs[-1]['events'][0] = event
    labels[2].update(label='unknown', expected_rule_ids=[], label_origin='undetermined')
    intake.prepare(root, write(), tmp_path/'intake')
    report = json.loads((tmp_path/'intake/intake-report.json').read_bytes())
    assert report['cases'] == 6 and report['labels_asserted']['unknown'] == 1
    assert report['opposite_label_sequence_groups'] == 1
    assert 'opposite_labels_same_declared_sequence' in report['structural_blockers']
    assert 'unknown_labels_require_adjudication' in report['structural_blockers']
    assert not report['structural_checks_passed'] and report['metric_values'] is None


def test_subject_reuse_and_forward_time_leakage_are_reported_before_inference(bundle, tmp_path):
    root, inputs, _labels, _origin, write = bundle
    inputs[-1]['events'][0]['user']['user_id'] = inputs[0]['events'][0]['user']['user_id']
    inputs[-1]['events'][0]['timestamp'] = inputs[0]['events'][0]['timestamp']
    intake.prepare(root, write(), tmp_path/'intake')
    report = json.loads((tmp_path/'intake/intake-report.json').read_bytes())
    assert 'cross_split_overlap' in report['structural_blockers'] and 'forward_time_contract_failed' in report['structural_blockers']
    assert report['inference_runs'] == 0


def test_relabeling_source_kind_does_not_verify_real_organization_provenance(bundle, tmp_path):
    root, _inputs, _labels, origin, write = bundle
    origin['kind'] = 'organization_archive'
    intake.prepare(root, write(), tmp_path/'intake')
    report = json.loads((tmp_path/'intake/intake-report.json').read_bytes())
    assert report['source_kind_asserted'] == 'organization_archive'
    assert not report['source_provenance_verified'] and not report['independent_review_verified']


def test_hash_change_and_extra_inventory_file_cannot_enter_review(bundle, tmp_path):
    root, _inputs, _labels, _origin, write = bundle
    anchor = write()
    with (root/'observations.jsonl').open('ab') as stream:
        stream.write(b'\n')
    with pytest.raises(ValueError, match='file_hash'):
        intake.prepare(root, anchor, tmp_path/'intake')
    anchor = write()
    (root/'extra.txt').write_text('not in fixed inventory')
    with pytest.raises(ValueError, match='exact_file_inventory'):
        intake.prepare(root, anchor, tmp_path/'intake')


def fill_reviews(directory):
    contract = json.loads((directory/'contract.json').read_bytes())
    rows = []
    for case in contract['inventory']:
        rows.append({'case_id': case['case_id'], 'reviewer_subject': 'test-reviewer',
            'review_label': case['expected_label_asserted'], 'evidence_event_ids': case['event_ids'][:1],
            'rationale': 'Simulated complete record, never a verified independent person.',
            'reviewed_at': datetime.now(UTC).isoformat()})
    return rows


def save_reviews(directory, rows):
    (directory/'reviews.jsonl').write_bytes(b''.join(intake.canonical(row)+b'\n' for row in rows))


def test_complete_self_reported_records_do_not_become_verified_independent_review(bundle, tmp_path):
    root, _inputs, _labels, _origin, _write = bundle
    directory, anchor = prepared(bundle, tmp_path)
    before = (root/'labels.jsonl').read_bytes()
    save_reviews(directory, fill_reviews(directory))
    result = intake.assess(directory, anchor, bundle=root)
    assert result['review_records_complete'] == 6 and result['record_completion_ready_for_team_adjudication']
    assert not result['independent_review_verified'] and not result['final_evaluation_ready']
    assert not result['labels_automatically_changed'] and not result['goal_qualified']
    assert (root/'labels.jsonl').read_bytes() == before


@pytest.mark.parametrize('damage', ['creator', 'other_evidence', 'future', 'naive', 'deleted_case'])
def test_invalid_review_identity_evidence_time_or_population_is_rejected(bundle, tmp_path, damage):
    root, _inputs, _labels, _origin, _write = bundle
    directory, anchor = prepared(bundle, tmp_path)
    rows = fill_reviews(directory)
    if damage == 'creator':
        rows[0]['reviewer_subject'] = ' TEST-AUTHOR '
    elif damage == 'other_evidence':
        rows[0]['evidence_event_ids'] = rows[1]['evidence_event_ids']
    elif damage == 'future':
        rows[0]['reviewed_at'] = (datetime.now(UTC)+timedelta(days=1)).isoformat()
    elif damage == 'naive':
        rows[0]['reviewed_at'] = datetime.now(UTC).replace(tzinfo=None).isoformat()
    else:
        rows.pop()
    save_reviews(directory, rows)
    with pytest.raises(ValueError):
        intake.assess(directory, anchor, bundle=root)


def test_report_tampering_or_wrong_review_anchor_cannot_hide_split_failures(bundle, tmp_path):
    root, _inputs, _labels, _origin, _write = bundle
    directory, anchor = prepared(bundle, tmp_path)
    with pytest.raises(ValueError, match='external_contract_anchor'):
        intake.assess(directory, '0'*64, bundle=root)
    (directory/'intake-report.json').write_bytes(b'{"structural_checks_passed":true}')
    with pytest.raises(ValueError, match='analysis_changed'):
        intake.assess(directory, anchor, bundle=root)


def test_cli_rejection_never_echoes_raw_private_input_values(bundle, tmp_path, monkeypatch, capsys):
    root, inputs, _labels, _origin, write = bundle
    inputs[0]['events'][0]['auth_context']['mfa'] = 'private-input-marker-do-not-echo'
    anchor = write()
    monkeypatch.setattr(sys, 'argv', ['intake', 'prepare', '--bundle', str(root), '--expected-sha256', anchor,
                                    '--directory', str(tmp_path/'intake')])
    assert intake.main() == 1
    output = capsys.readouterr().out
    assert 'intake_rejected' in output and 'private-input-marker' not in output


def test_truth_fields_cannot_be_added_to_an_observation_record(bundle, tmp_path):
    root, inputs, _labels, _origin, write = bundle
    inputs[0]['expected_rule_ids'] = [intake.RULE_IDS['credential']]
    with pytest.raises(ValueError):
        intake.prepare(root, write(), tmp_path/'intake')


def test_explicit_unknown_claims_are_counted_separately_from_normal_defaults(bundle, tmp_path):
    root, inputs, _labels, _origin, write = bundle
    inputs[0]['events'][0]['device']['security_posture'] = 'unknown'
    inputs[0]['events'][0]['auth_context'].update(mfa='unknown', authentication_result='unknown')
    intake.prepare(root, write(), tmp_path/'intake')
    report = json.loads((tmp_path/'intake/intake-report.json').read_bytes())
    counts = report['explicit_unknown_or_untrusted_value_counts']
    assert counts['device_posture_unknown'] == counts['mfa_unknown'] == counts['authentication_result_unknown'] == 1
    assert report['material_security_fields_defaulted'] == 0 and not report['final_evaluation_ready']


@pytest.mark.parametrize('truth', [None, {'label': 'threat'}])
def test_even_a_null_ground_truth_field_cannot_ride_inside_observations(bundle, tmp_path, truth):
    root, inputs, _labels, _origin, write = bundle
    inputs[0]['events'][0]['ground_truth'] = truth
    with pytest.raises(ValueError, match='truth_must_be_separate'):
        intake.prepare(root, write(), tmp_path/'intake')


def test_shipped_format_example_has_stable_bytes_and_never_qualifies_as_final_data(tmp_path):
    example = Path(__file__).resolve().parents[1]/'infra/f1-lab/intake-example'
    anchor = 'e4532017c9663dbf71bdc3e36cf47f257186dcd2d17a74eec128e6fc8f2efbdf'
    result = intake.prepare(example, anchor, tmp_path/'intake')
    report = json.loads((tmp_path/'intake/intake-report.json').read_bytes())
    assert result['cases'] == 6 and report['structural_checks_passed']
    assert not report['planned_target_support']['final_candidate']['planned_family_support_met']
    assert not report['final_evaluation_ready'] and not report['source_provenance_verified']
