import hashlib
import json
from dataclasses import replace

import pytest

from scripts import audit_m7_splits as split
from scripts.prepare_m7 import SOURCE


def row(ident, label='benign', *, family=None, subjects=(), clients=(), sequence=None, first=1, last=1):
    return split.Summary(ident, label, family or 'family-'+ident, tuple(subjects), tuple(clients), sequence or 'sequence-'+ident,
                         first, last, 1, int(not subjects), int(not clients))


def test_transitive_group_overlap_is_one_component_without_relying_on_pairwise_folds():
    rows = [row('a', subjects=('user-a',)), row('b', subjects=('user-a', 'user-b')),
            row('c', subjects=('user-b',)), row('d')]
    result = split.components(rows, ('subjects',))
    assert result['components'] == 2 and result['largest_component_sessions'] == 3
    assert not result['necessary_nonempty_label_support_conditions_met']
    assert not result['balanced_split_constructed'] and not result['feasibility_proven']


def test_missing_identities_are_not_a_shared_group_or_proof_of_distinctness():
    rows = [row(str(index)) for index in range(4)]
    result = split.analyze(rows, 2)['all_publisher_classes']
    assert result['profiles']['known_subject']['components'] == 4
    assert result['profiles']['known_client']['components'] == 4
    assert result['known_identity_coverage']['sessions_without_known_subject'] == 4
    assert result['known_identity_coverage']['sessions_without_known_client'] == 4


def test_same_semantic_family_and_pattern_link_opposite_labels_without_becoming_predictor_inputs():
    rows = [row('a', family='same-family'), row('b', 'attack', family='same-family'),
            row('c', 'attack', sequence='same-pattern'), row('d', sequence='same-pattern')]
    result = split.analyze(rows, 2)['binary_benign_attack']
    assert result['profiles']['semantic_family']['components'] == 3
    assert result['profiles']['family_subject_client_sequence']['components'] == 2
    assert not result['profiles']['family_subject_client_sequence']['necessary_nonempty_label_support_conditions_met']


def test_anomaly_is_reported_separately_and_can_bridge_only_the_all_class_graph():
    rows = [row('a', subjects=('one',)), row('b', 'attack', subjects=('two',)),
            row('c', 'anomaly', subjects=('one', 'two'))]
    result = split.analyze(rows, 2)
    assert result['all_publisher_classes']['profiles']['known_subject']['components'] == 1
    binary = result['binary_benign_attack']
    assert binary['profiles']['known_subject']['components'] == 2 and binary['excluded_anomaly_sessions'] == 1
    assert binary['source_label_counts'] == {'attack': 1, 'benign': 1}


def test_fixed_time_cutoff_uses_entire_flow_and_reports_overlaps_without_selecting_or_dropping_rows():
    rows = [row('before', family='shared-family', subjects=('shared-user',), clients=('shared-client',), sequence='shared-sequence'),
            row('after', 'attack', family='shared-family', subjects=('shared-user',), clients=('shared-client',), sequence='shared-sequence', first=3, last=4),
            row('span', first=1, last=3), row('boundary', first=2, last=2)]
    result = split.time_overlap(rows, 2)
    assert (result['before_sessions'], result['after_sessions'], result['spanning_sessions']) == (1, 2, 1)
    for value in result['overlap'].values():
        assert value == {'shared_keys': 1, 'before_sessions_touching_shared_keys': 1, 'after_sessions_touching_shared_keys': 1}
    assert result['spanning_sessions_kept_separate'] and not result['populations_modified']
    assert len(rows) == 4


def test_passing_necessary_fold_conditions_is_never_a_balanced_independence_claim():
    rows = [row(str(i), 'attack' if i % 2 else 'benign') for i in range(6)]
    result = split.components(rows, ('family',))
    assert result['necessary_nonempty_label_support_conditions_met']
    assert not result['feasibility_proven'] and not result['balanced_split_constructed']


def test_public_aggregate_is_deterministic_and_exports_no_identity_or_session_values():
    rows = [row('private-session-a', subjects=('private-user',)), row('private-session-b', 'attack', subjects=('private-user',))]
    assert split.analyze(rows, 2) == split.analyze(list(reversed(rows)), 2)
    body = json.dumps(split.analyze(rows, 2))
    assert all(value not in body for value in ('private-session-a', 'private-session-b', 'private-user'))


@pytest.mark.parametrize('damage', ['empty', 'duplicate', 'label', 'clock', 'size'])
def test_summary_population_contract_rejects_invalid_graph_inputs(damage, monkeypatch):
    rows = [row('a')]
    if damage == 'empty':
        rows = []
    elif damage == 'duplicate':
        rows *= 2
    elif damage == 'label':
        rows = [replace(rows[0], label='unknown')]
    elif damage == 'clock':
        rows = [replace(rows[0], last=0)]
    else:
        monkeypatch.setattr(split, 'MAX_SESSIONS', 0)
    with pytest.raises(ValueError):
        split.analyze(rows, 2)


@pytest.fixture
def source(tmp_path):
    contract = json.loads(SOURCE.read_bytes())
    rows = []
    for ident, label, instant, subject, client in [
        ('a', 'benign', '2026-02-01T00:00:00Z', None, None),
        ('b', 'attack', '2026-03-02T00:00:00Z', None, None),
        ('c', 'anomaly', '2026-02-02T00:00:00Z', 'known-user', '192.0.2.1')]:
        rows.append({'trace_id': ident, 'label': label, 'category': 'same-semantic-family', 'subcategory': None,
            'module': 'auth', 'http_method': 'POST', 'http_status': 200, 'level': 'INFO', 'duration_ms': 12,
            'timestamp': instant, 'user_id': subject, 'action_by': None, 'client_ip': client,
            'event_type': 'outside-projection', 'message': 'never-export-this-message'})
    path = tmp_path/'raw.jsonl'
    data = b''.join(json.dumps(row).encode()+b'\n' for row in rows)
    path.write_bytes(data)
    contract.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                    source_counts={'rows': 3, 'sessions': {'benign': 1, 'attack': 1, 'anomaly': 1}})
    return path, contract


def test_disk_audit_preserves_source_and_skips_null_client_group(source, tmp_path):
    path, contract = source
    before = path.read_bytes()
    result = split.audit(path, tmp_path/'audit', contract)
    binary = result['analysis']['binary_benign_attack']
    assert binary['profiles']['known_client']['components'] == 2
    assert binary['profiles']['semantic_family']['components'] == 1
    assert binary['known_identity_coverage']['sessions_without_known_client'] == 2
    assert result['source_sha256'] == contract['sha256'] and path.read_bytes() == before
    assert result['detector_inference_runs'] == 0 and not result['goal_qualified'] and not result['new_split_selected']
    assert {p.name for p in (tmp_path/'audit').iterdir()} == {'audit.json', 'NOTICE.md'}
    assert 'never-export-this-message' not in (tmp_path/'audit/audit.json').read_text()
    assert not list(tmp_path.glob('.m7-splits-*'))


@pytest.mark.parametrize('damage', ['hash', 'after_ingest', 'existing'])
def test_disk_audit_fails_without_publishing_partial_analysis(source, tmp_path, monkeypatch, damage):
    path, contract = source
    destination = tmp_path/'audit'
    if damage == 'hash':
        contract['sha256'] = '0'*64
    elif damage == 'after_ingest':
        monkeypatch.setattr(split, 'stream_hash', lambda _path: (contract['bytes'], '0'*64))
    else:
        destination.mkdir()
    with pytest.raises(ValueError):
        split.audit(path, destination, contract)
    assert not (destination/'audit.json').exists() and not list(tmp_path.glob('.m7-splits-*'))
