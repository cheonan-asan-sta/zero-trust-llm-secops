import hashlib
import json
from datetime import UTC, datetime

import pytest

from scripts.f1_lab.pcap_initial import initial, scan
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.vpn_initial_frame_link import FrameIndex
from scripts.link_vpn_initial_frames import load_frames, run
from tests.test_f1_pcap_initial import frame, pcap

START = 1700000000


def line():
    time = datetime.fromtimestamp(START, UTC).strftime('%Y-%m-%d %H:%M:%S')
    return time + ' 192.0.2.1:50000 TLS: Initial packet from [AF_INET]192.0.2.1:50000, sid=31323334 35363738\n'


def observed(*, moment=START * 1000000000 + 100, ordinal=1):
    value = initial(frame())
    return {'source_sha256': 'a' * 64, 'packet_ordinal': ordinal, 'capture_time_ns': moment,
            'frame_sha256': hashlib.sha256(frame()).hexdigest(), 'join_key': value['join_key'],
            'features': list(value['features'])}


@pytest.mark.parametrize('delta,relation', [(-100, 'capture_at_or_before_logged_lower_bound'),
                                         (0, 'capture_at_or_before_logged_lower_bound'),
                                         (100, 'capture_within_reported_second')])
def test_exact_reported_id_match_never_proves_clock_identity_or_predictor_admission(delta, relation):
    item = observed(moment=START * 1000000000 + delta)
    result = FrameIndex([item]).match(line(), START)
    assert result['matched'] and result['recorded_time_relation'] == relation
    assert result['frame']['frame_sha256'] == item['frame_sha256']
    assert result['temporal_availability_proven'] is False and result['admitted_to_predictor'] is False
    assert result['human_or_device_identity_verified'] is False


def test_future_duplicate_does_not_invalidate_an_earlier_candidate_but_current_ambiguity_does():
    first = observed()
    future = observed(moment=(START + 2) * 1000000000, ordinal=2)
    previous = FrameIndex([first]).match(line(), START)
    assert FrameIndex([first, future]).match(line(), START) == previous
    tied = observed(moment=START * 1000000000 + 200, ordinal=2)
    result = FrameIndex([first, tied]).match(line(), START)
    assert result['status'] == 'ambiguous_frame' and not result['matched']
    assert result['compatible_candidates'] == 2 and not result['admitted_to_predictor']


def test_later_frame_alone_cannot_match_and_existing_objects_do_not_mutate_index():
    assert not FrameIndex([observed(moment=(START + 1) * 1000000000)]).match(line(), START)['matched']
    item = observed(); index = FrameIndex([item]); item['features'][1] = 'ttl_9'
    first = index.match(line(), START); assert first['frame']['features'][1] == 'ttl_64'
    first['frame']['features'][1] = 'ttl_8'
    assert index.match(line(), START)['frame']['features'][1] == 'ttl_64'


@pytest.mark.parametrize('before,after', [
    ('sid=31323334 35363738', 'sid=AAAAAAAA BBBBBBBB'),
    ('sid=31323334 35363738', 'sid=00000000 00000000'),
    ('sid=31323334 35363738', 'sid=not-a-session'),
    ('[AF_INET]192.0.2.1:50000', '[AF_INET]192.0.2.2:50000'),
    ('[AF_INET]192.0.2.1:50000', '[AF_INET]192.0.2.1:50001'),
    ('[AF_INET]', '[AF_INET6]'),
    (' 192.0.2.1:50000 TLS:', ' user/192.0.2.1:50000 TLS:'),
    ('TLS: Initial packet', 'TLS: later packet'),
])
def test_unsupported_or_unbound_current_message_is_not_filled_from_other_frames(before, after):
    assert not FrameIndex([observed()]).match(line().replace(before, after), START)['matched']


@pytest.mark.parametrize('moment', [None, True, float('nan'), START + 1])
def test_missing_invalid_or_unbound_row_time_cannot_link(moment):
    result = FrameIndex([observed()]).match(line(), moment)
    assert not result['matched'] and not result['admitted_to_predictor']


@pytest.mark.parametrize('fault', ['extra_label', 'source', 'ordinal_bool', 'time_float', 'ttl', 'df', 'ihl', 'tos', 'duplicate'])
def test_input_contract_rejects_label_fields_invalid_features_and_duplicate_physical_rows(fault):
    item = observed(); rows = [item]
    if fault == 'extra_label': item['expected_alert'] = False
    if fault == 'source': item['source_sha256'] = 'invalid'
    if fault == 'ordinal_bool': item['packet_ordinal'] = True
    if fault == 'time_float': item['capture_time_ns'] = float(item['capture_time_ns'])
    if fault == 'ttl': item['features'][1] = 'ttl_0'
    if fault == 'df': item['features'][2] = 'df_root'
    if fault == 'ihl': item['features'][3] = 'ihl_21'
    if fault == 'tos': item['features'][4] = 'tos_256'
    if fault == 'duplicate': rows.append(item.copy())
    with pytest.raises(ValueError):
        FrameIndex(rows)


def fixture(tmp_path):
    raw = tmp_path / 'raw'; raw.mkdir()
    rows = [line(), line().split(' TLS:')[0] + ' VERIFY KU OK\n', 'unparseable physical row\n']
    source = raw / 'pair-0-raw.source'; source.write_bytes(''.join(rows).encode())
    member = 'gather/vpn/logs/openvpn.log'
    manifest = {'completed': True, 'timestamp_basis':
        'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
        'pairs': [{'provenance': {'raw_member': member, 'raw_sha256': sha(source),
                    'simulation_start': START - 1, 'simulation_end': START + 100}}]}
    (raw / 'audit.json').write_text(json.dumps(manifest), encoding='utf8')
    prep = tmp_path / 'preparation.json'
    prep.write_text(json.dumps({'completed': True, 'inputs_contain_truth': False,
        'source_manifest_sha256': sha(raw / 'audit.json'),
        'pairs': [{'raw_member': member, 'raw_sha256': sha(source), 'rows': 3}]}), encoding='utf8')
    folder = tmp_path / 'intake'; folder.mkdir(); members = []
    for n, packets in enumerate(([(START, 10, frame())], [])):
        p = folder / f'member-{n}.pcap'; p.write_bytes(pcap(packets))
        observations = folder / f'member-{n}-initial.jsonl'; parsed = scan(p, sha(p), observations)
        members.append({'path': p.name, 'observations': observations.name, 'sha256': sha(p),
                        'crc_verified': True, **parsed})
    value = {'schema': 'verified-vpn-packet-members-1', 'completed': True, 'role': 'training',
             'scenario': 'russellmitchell', 'publisher_md5_verified': True, 'same_vpn_log_bytes_verified': True,
             'vpn_raw_sha256': sha(source), 'new_independent_evaluation': False, 'goal_qualified': False, 'members': members}
    intake = folder / 'run.json'; intake.write_text(json.dumps(value), encoding='utf8')
    return raw, prep, intake, value


def test_full_diagnostic_keeps_all_original_ids_order_errors_and_never_becomes_predictions(tmp_path):
    raw, prep, intake, _ = fixture(tmp_path)
    result = run(prep, sha(prep), raw, intake, sha(intake), tmp_path / 'result')
    rows = list(map(json.loads, (tmp_path / 'result/links.jsonl').read_bytes().splitlines()))
    digest = sha(raw / 'pair-0-raw.source')
    assert [r['case_id'] for r in rows] == [hashlib.sha256((digest + ':' + str(n)).encode()).hexdigest() for n in (1, 2, 3)]
    assert result['population'] == 3 and result['raw_time_errors'] == 1 and rows[0]['matched']
    assert rows[2]['status'] == 'raw_time_unavailable'
    assert all(r['admitted_to_predictor'] is False and 'after' not in r for r in rows)
    assert not result['model_fit_or_prediction_performed'] and not result['validation_labels_opened']


@pytest.mark.parametrize('fault', ['incomplete', 'raw_source', 'traversal', 'count_bool', 'observation_pin'])
def test_unverified_or_changed_intake_cannot_be_used(tmp_path, fault):
    raw, _, intake, value = fixture(tmp_path)
    if fault == 'incomplete': value['completed'] = False
    if fault == 'raw_source': value['vpn_raw_sha256'] = 'f' * 64
    if fault == 'traversal': value['members'][0]['observations'] = '../outside.jsonl'
    if fault == 'count_bool': value['members'][0]['packets'] = True
    if fault == 'observation_pin': value['members'][0]['observations_sha256'] = 'f' * 64
    intake.write_text(json.dumps(value), encoding='utf8')
    with pytest.raises(ValueError):
        load_frames(intake, sha(intake), sha(raw / 'pair-0-raw.source'))


def test_extra_label_in_pinned_observations_is_still_rejected(tmp_path):
    raw, _, intake, value = fixture(tmp_path)
    obs = intake.parent / 'member-0-initial.jsonl'; row = json.loads(obs.read_bytes())
    row['malicious'] = False; obs.write_text(json.dumps(row) + '\n', encoding='utf8')
    value['members'][0]['observations_sha256'] = sha(obs); intake.write_text(json.dumps(value), encoding='utf8')
    with pytest.raises(ValueError, match='wire_link_fields'):
        load_frames(intake, sha(intake), sha(raw / 'pair-0-raw.source'))


def test_raw_clock_regression_is_reported_without_reordering_or_admission(tmp_path):
    raw, prep, intake, value = fixture(tmp_path)
    source = raw / 'pair-0-raw.source'; lines = source.read_text(encoding='utf8').splitlines(keepends=True)
    earlier = datetime.fromtimestamp(START - 1, UTC).strftime('%Y-%m-%d %H:%M:%S')
    lines[1] = earlier + lines[1][19:]; source.write_text(''.join(lines), encoding='utf8')
    manifest = json.loads((raw / 'audit.json').read_bytes())
    manifest['pairs'][0]['provenance']['raw_sha256'] = sha(source)
    (raw / 'audit.json').write_text(json.dumps(manifest), encoding='utf8')
    preparation = json.loads(prep.read_bytes()); preparation['pairs'][0]['raw_sha256'] = sha(source)
    preparation['source_manifest_sha256'] = sha(raw / 'audit.json'); prep.write_text(json.dumps(preparation), encoding='utf8')
    value['vpn_raw_sha256'] = sha(source); intake.write_text(json.dumps(value), encoding='utf8')
    result = run(prep, sha(prep), raw, intake, sha(intake), tmp_path / 'regression')
    rows = list(map(json.loads, (tmp_path / 'regression/links.jsonl').read_bytes().splitlines()))
    assert result['raw_time_regressions'] == 1 and rows[1]['raw_time_regressed'] is True
    assert [r['ordinal'] for r in rows] == [1, 2, 3]
    assert not result['admitted_to_predictor'] and all(not r['admitted_to_predictor'] for r in rows)


def test_manifest_mutation_during_join_cannot_publish_completed_links(tmp_path, monkeypatch):
    raw, prep, intake, _ = fixture(tmp_path)
    original = FrameIndex.match

    def mutate(index, text, moment):
        (raw / 'audit.json').write_bytes(b'changed UTC/provenance manifest')
        return original(index, text, moment)

    monkeypatch.setattr(FrameIndex, 'match', mutate)
    with pytest.raises(ValueError, match='wire_link_source_drift'):
        run(prep, sha(prep), raw, intake, sha(intake), tmp_path / 'drift')
    assert not (tmp_path / 'drift/links.jsonl').exists()
    assert not (tmp_path / 'drift/run.json').exists()
