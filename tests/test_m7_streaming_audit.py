import hashlib
import json

import pytest

from scripts import audit_m7_source as streamed
from scripts.prepare_m7 import SOURCE, build, prepare, split_for


@pytest.fixture
def source(tmp_path):
    contract = json.loads(SOURCE.read_bytes())
    contract['pilot']['sessions_per_label_per_split'] = 1

    def attack_subcategory(split):
        return next('fixture-'+str(i) for i in range(100)
                    if split_for(('attack', 'credential', 'fixture-'+str(i)), contract['pilot']) == split)

    rows = []
    for ident, label, category, subcategory, module, method, status, level, instant in [
        ('n-dev', 'benign', 'login', None, 'auth', 'POST', 200, 'INFO', '2026-02-01T00:00:00Z'),
        ('t-dev', 'attack', 'credential', attack_subcategory('development'), 'auth', 'POST', 401, 'WARNING', '2026-02-01T00:00:00Z'),
        ('n-eval', 'benign', 'account', None, 'request', 'GET', 200, 'INFO', '2026-03-02T00:00:00Z'),
        ('t-eval', 'attack', 'credential', attack_subcategory('evaluation'), 'admin', 'DELETE', 403, 'ERROR', '2026-03-02T00:00:00Z'),
        ('t-conflict', 'attack', 'credential', attack_subcategory('development'), 'auth', 'POST', 200, 'INFO', '2026-02-01T00:00:00Z'),
        ('a-same', 'anomaly', 'device_anomaly', None, 'auth', 'POST', 200, 'INFO', '2026-02-01T00:00:00Z'),
        ('a-other', 'anomaly', 'device_anomaly', None, 'ldap', 'POST', 500, 'ERROR', '2026-02-01T00:00:00Z')]:
        development = '02-01' in instant
        rows.append({'trace_id': ident, 'label': label, 'category': category, 'subcategory': subcategory,
            'module': module, 'http_method': method, 'http_status': status, 'level': level,
            'duration_ms': 13 if ident == 't-conflict' else 12, 'timestamp': instant,
            'user_id': 'dev-user' if development else 'eval-user', 'action_by': None,
            'client_ip': '192.0.2.1' if development else '198.51.100.1',
            'event_type': 'excluded-reference', 'message': 'must stay outside model inputs'})
    path = tmp_path/'source.jsonl'

    def write():
        data = b''.join(json.dumps(row).encode()+b'\n' for row in rows)
        path.write_bytes(data)
        contract['bytes'], contract['sha256'] = len(data), hashlib.sha256(data).hexdigest()
        counts = {}
        for row in rows:
            counts.setdefault(row['label'], set()).add(row['trace_id'])
        contract['source_counts'] = {'rows': len(rows), 'sessions': {k: len(v) for k, v in counts.items()}}

    write()
    return path, contract, rows, write


def test_disk_backed_reader_reproduces_the_original_builder_bytes(source, tmp_path):
    path, contract, _rows, _write = source
    expected, manifest = build(path, contract)
    result = streamed.audit(path, tmp_path/'audit', contract)
    assert result['pilot'] == manifest
    assert all((tmp_path/'audit/pilot'/name).read_bytes() == data for name, data in expected.items())
    assert result['population']['events'] == 7
    assert result['pilot_source_pattern_context']['selected_sessions_with_binary_source_pattern_conflict'] == 1
    assert result['detector_inference_runs'] == 0 and not result['goal_qualified']
    assert result['independent_review'] == 'pending' and not result['compatible_with_full_signed_security_events']
    assert not list(tmp_path.glob('.m7-audit-*'))


def test_selected_reference_is_compared_exactly_without_modifying_it(source, tmp_path):
    path, contract, _rows, _write = source
    reference = tmp_path/'reference'
    prepare(path, reference, contract)
    before = {p.name: p.read_bytes() for p in reference.iterdir()}
    result = streamed.audit(path, tmp_path/'audit', contract, reference=reference)
    assert result['reference_pilot_byte_identical'] is True
    assert before == {p.name: p.read_bytes() for p in reference.iterdir()}
    assert result['effects'] == {'network_calls': 0, 'paid_api_calls': 0, 'cloud_calls': 0, 'baseline_writes': 0}


def test_conflicting_projection_and_duration_shortcut_are_diagnostic_not_model_performance(source, tmp_path):
    path, contract, _rows, _write = source
    result = streamed.audit(path, tmp_path/'audit', contract)
    projections = result['analysis']['projections']
    simple = projections['module_method_status_level_sequence']['binary_authored_oracle_bound']
    duration = projections['same_plus_duration_sequence']['binary_authored_oracle_bound']
    assert simple['conflicting_groups'] == simple['minimum_misclassifications'] == 1
    assert simple['maximum_f1_oracle'] == pytest.approx(6/7)
    assert duration['maximum_f1_oracle'] == 1 and duration['not_model_performance']
    assert projections['same_plus_duration_sequence']['anomaly_excluded_from_binary_oracle'] == 2


def test_out_of_order_timezone_records_use_the_same_order_as_the_original_builder(source, tmp_path):
    path, contract, rows, write = source
    rows.append({**rows[0], 'timestamp': '2026-02-01T08:59:59+09:00', 'duration_ms': 10})
    write()
    expected, _manifest = build(path, contract)
    streamed.audit(path, tmp_path/'audit', contract)
    assert all((tmp_path/'audit/pilot'/name).read_bytes() == data for name, data in expected.items())


@pytest.mark.parametrize('damage', ['duplicate', 'conflicting_label', 'wrong_hash', 'line_size'])
def test_invalid_corpus_never_publishes_an_audit_or_partial_pilot(source, tmp_path, damage):
    path, contract, rows, write = source
    if damage == 'duplicate':
        rows.append(rows[0])
        write()
    elif damage == 'conflicting_label':
        rows.append({**rows[0], 'label': 'attack', 'subcategory': 'inconsistent'})
        write()
    elif damage == 'wrong_hash':
        path.write_bytes(path.read_bytes().replace(b'"duration_ms": 12', b'"duration_ms": 14'))
    else:
        path.write_bytes(b' '*(streamed.MAX_LINE+1)+b'\n')
        contract['bytes'] = path.stat().st_size
    with pytest.raises(ValueError):
        streamed.audit(path, tmp_path/'audit', contract)
    assert not (tmp_path/'audit').exists() and not list(tmp_path.glob('.m7-audit-*'))


def test_existing_output_and_oversized_source_contract_are_rejected(source, tmp_path):
    path, contract, _rows, _write = source
    (tmp_path/'existing').mkdir()
    with pytest.raises(ValueError, match='fresh_directory'):
        streamed.audit(path, tmp_path/'existing', contract)
    contract['bytes'] = streamed.MAX_BYTES+1
    with pytest.raises(ValueError, match='source_size'):
        streamed.audit(path, tmp_path/'audit', contract)


def test_source_changed_after_ingestion_is_detected_before_publication(source, tmp_path, monkeypatch):
    path, contract, _rows, _write = source
    monkeypatch.setattr(streamed, 'stream_hash', lambda _path: (contract['bytes'], '0'*64))
    with pytest.raises(ValueError, match='source_changed'):
        streamed.audit(path, tmp_path/'audit', contract)
    assert not (tmp_path/'audit').exists()
