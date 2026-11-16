import hashlib
import json
from pathlib import Path

import pytest

from scripts.f1_lab.shared_dns_native_review import PROFILE, SharedDnsNativeReview
from scripts.f1_lab.transfer_evaluation import sha
from scripts.run_shared_dns_native_review import predict


def service(kind, stamp, serial, unit, *, fields='pid=1 uid=0'):
    return (f'type={kind} msg=audit({stamp}:{serial}): {fields} auid=4294967295 ses=4294967295 '
            f'msg=\'unit={unit} comm="systemd" exe="/lib/systemd/systemd" res=success\'\n')


def prepare(folder, *, unit='novel-unit', bound_us=98500000, capture_ns=97000000000, change=None, prefix=None):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=False)
    raw = prefix or [service('SERVICE_START', '90', 1, 'prior-unit'), service('SERVICE_STOP', '90.001', 2, 'prior-unit')]
    raw += [service('SERVICE_START', '100', 3, unit), service('SERVICE_STOP', '100.001', 4, unit)]
    if change:
        raw = [change(s) for s in raw]
    pin = hashlib.sha256(''.join(raw).encode()).hexdigest()
    row = {'packet_ordinal': 10, 'capture_time_ns': capture_ns, 'frame_sha256': 'a' * 64,
           'qname_sha256': 'b' * 64, 'qtype': 1, 'wire_length': 150, 'payload_labels': 3,
           'non_hostname_base64_characters': True, 'encoded_shape': True,
           'source_decoder_bound': {'packet_ordinal': 10, 'capture_time_ns': capture_ns,
                'seen_no_later_than_us': bound_us, 'counter_ordinal': 100, 'counter_row_sha256': 'c' * 64,
                'application_receipt_time_proven': False, 'actor_or_authority_proven': False}}
    observed = folder / 'shared-dns-observations.jsonl'
    observed.write_text(json.dumps(row) + '\n', encoding='utf8')
    manifest = {'schema': 'staged-shared-dns-native-context-1', 'intake_sha256': 'd' * 64,
        'source_decoder_contract_verified': True, 'producer_profile': PROFILE, 'capture_sha256': 'e' * 64,
        'capture_packets': 100, 'audit_source_sha256': pin, 'observations_file': observed.name,
        'observations_sha256': sha(observed), 'observation_count': 1,
        'historical_application_receipt_proven': False, 'actor_or_authority_proven': False,
        'goal_qualified': False, 'new_independent_evaluation': False}
    path = folder / 'manifest.json'
    path.write_text(json.dumps(manifest), encoding='utf8')
    return raw, pin, path, manifest, row


def observe(data):
    raw, pin, path, _manifest, _row = data
    reader = SharedDnsNativeReview(pin, raw, path, sha(path))
    results = [reader.observe(n, s, source_sha256=pin) for n, s in enumerate(raw, 1)]
    reader.verify()
    return results


@pytest.mark.parametrize('unit', ['novel-unit', 'other-random-name', 'x-12001@demo'])
def test_first_observed_episode_uses_join_identity_without_name_exceptions(tmp_path, unit):
    result = observe(prepare(tmp_path / 'case', unit=unit))
    assert result[:2] == [None, None]
    for proof in result[2:]:
        assert proof['first_observed_source_unit_episode'] is True
        assert proof['historical_application_receipt_proven'] is False
        assert proof['actor_or_authority_proven'] is False and proof['automatic_enforcement_allowed'] is False
        assert unit not in json.dumps(proof)


def test_previously_observed_unit_not_labeled_new_due_to_unrelated_dns_activity(tmp_path):
    assert observe(prepare(tmp_path / 'case', unit='prior-unit')) == [None] * 4


def test_equal_time_fence_does_not_backfill_start_but_later_stop_can_see_it(tmp_path):
    result = observe(prepare(tmp_path / 'case', bound_us=100000000))
    assert result[2] is None and result[3] is not None


def test_future_native_bound_or_old_capture_cannot_create_current_review(tmp_path):
    assert observe(prepare(tmp_path / 'future', bound_us=101000000)) == [None] * 4
    assert observe(prepare(tmp_path / 'old', capture_ns=94000000000)) == [None] * 4


@pytest.mark.parametrize('old,new', [('pid=1 ', 'pid=2 '), ('uid=0 ', 'uid=1000 '),
    ('comm="systemd"', 'comm="other"'), ('/lib/systemd/systemd', '/other/systemd'), ('res=success', 'res=failed')])
def test_nonmanager_or_unsuccessful_records_cannot_start_an_eligible_episode(tmp_path, old, new):
    data = prepare(tmp_path / 'case', change=lambda s: s.replace(old, new))
    assert observe(data) == [None] * 4


def test_failed_start_cannot_lend_new_episode_status_to_successful_stop(tmp_path):
    data = prepare(tmp_path / 'case', change=lambda s: s.replace('res=success', 'res=failed')
                   if 'SERVICE_START msg=audit(100:' in s else s)
    assert observe(data) == [None] * 4


@pytest.mark.parametrize('fault', ['truth', 'packet_duplicate', 'bound_future_capture', 'authority_claim', 'profile', 'source'])
def test_bad_projection_or_scope_rejected_even_when_resigned(tmp_path, fault):
    raw, pin, path, manifest, row = prepare(tmp_path / 'case')
    if fault == 'truth': row['expected_alert'] = True
    if fault == 'bound_future_capture': row['source_decoder_bound']['seen_no_later_than_us'] = 1
    if fault == 'authority_claim': row['source_decoder_bound']['actor_or_authority_proven'] = True
    if fault == 'profile': manifest['producer_profile'] = 'unverified'
    if fault == 'source': manifest['audit_source_sha256'] = 'f' * 64
    observed = path.parent / manifest['observations_file']
    observed.write_text((json.dumps(row) + '\n') * (2 if fault == 'packet_duplicate' else 1), encoding='utf8')
    manifest['observations_sha256'] = sha(observed)
    manifest['observation_count'] = 2 if fault == 'packet_duplicate' else 1
    path.write_text(json.dumps(manifest), encoding='utf8')
    with pytest.raises(ValueError):
        SharedDnsNativeReview(pin, raw, path, sha(path))


@pytest.mark.parametrize('fault', ['ordinal', 'raw', 'source'])
def test_current_source_or_sequence_mismatch_disables_later_propagation(tmp_path, fault):
    raw, pin, path, _manifest, _row = prepare(tmp_path / 'case')
    reader = SharedDnsNativeReview(pin, raw, path, sha(path))
    assert reader.observe(1, raw[0], source_sha256=pin) is None
    ordinal, line, source = 2, raw[1], pin
    if fault == 'ordinal': ordinal = 3
    if fault == 'raw': line += 'changed'
    if fault == 'source': source = 'f' * 64
    assert reader.observe(ordinal, line, source_sha256=source) is None
    assert reader.disabled is True
    assert reader.observe(3, raw[2], source_sha256=pin) is None


def test_baseline_case_ids_errors_order_and_existing_alerts_retained(tmp_path):
    raw, pin, path, _manifest, _row = prepare(tmp_path / 'case')
    folder = tmp_path / 'raw'
    folder.mkdir()
    (folder / 'pair-0-raw.source').write_bytes(''.join(raw).encode())
    prep = {'pairs': [{'raw_member': 'gather/internal_share/logs/audit/audit.log', 'raw_sha256': pin, 'rows': len(raw)}]}
    baseline = tmp_path / 'baseline.jsonl'
    rows = [{'case_id': hashlib.sha256((pin + ':' + str(n)).encode()).hexdigest(), 'source_index': 0,
             'before': False, 'after': n == 4, 'before_score': 0.0, 'after_score': .95 if n == 4 else 0.0,
             'reason': 'unchanged', 'error': 'existing_error' if n == 2 else None} for n in range(1, 5)]
    baseline.write_bytes(b''.join((json.dumps(s) + '\n').encode() for s in rows))
    result = predict(prep, folder, baseline, sha(baseline), tmp_path / 'prediction.jsonl',
                     [{'source_index': 0, 'raw_source_sha256': pin, 'path': str(path), 'sha256': sha(path)}])
    actual = list(map(json.loads, (tmp_path / 'prediction.jsonl').read_bytes().splitlines()))
    assert [s['case_id'] for s in actual] == [s['case_id'] for s in rows]
    assert actual[1]['error'] == 'existing_error' and actual[1]['before'] is None and actual[1]['after'] is None
    assert actual[2]['before'] is False and actual[2]['after'] is True
    assert actual[3]['before'] is True and actual[3]['after'] is True
    assert result['population'] == 4 and result['changed_alerts'] == 1 and result['inference_errors'] == 1
