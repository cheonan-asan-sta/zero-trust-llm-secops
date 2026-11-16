import hashlib
import json
import zipfile

import pytest

from scripts import prepare_shared_dns_transactions as intake
from scripts import stage_shared_dns_replay as staging
from scripts.f1_lab.dns_transaction_fence import PROFILE
from scripts.f1_lab.shared_dns_transaction_review import SharedDnsTransactionReview, open_review
from scripts.f1_lab.transfer_evaluation import sha
from tests.test_dns_capture import runtime
from tests.test_dns_transaction_sources import events
from tests.test_shared_dns_capture_intake import make_lab
from tests.test_shared_dns_native_review import prepare as packet_fixture


def prepare(folder, **kwargs):
    raw, pin, path, _old_manifest, old = packet_fixture(folder, **kwargs)
    prior_bound = old['source_decoder_bound']
    row = {'transaction_ordinal': 10, 'eve_ordinal': 30, 'event_time_us': old['capture_time_ns'] // 1000,
        'row_sha256': 'a' * 64, 'qname_sha256': 'b' * 64, 'query_shape_supported': True, 'payload_labels': 3,
        'non_hostname_base64_characters': True, 'encoded_shape': True,
        'source_transaction_bound': {'transaction_ordinal': 10, 'event_time_us': old['capture_time_ns'] // 1000,
            'seen_no_later_than_us': prior_bound['seen_no_later_than_us'], 'counter_ordinal': 100,
            'counter_row_sha256': 'c' * 64, 'application_receipt_time_proven': False, 'actor_or_authority_proven': False}}
    observed = path.parent / 'shared-dns-transactions.jsonl'
    observed.write_text(json.dumps(row) + '\n', encoding='utf8')
    manifest = {'schema': 'staged-shared-dns-transactions-1', 'intake_sha256': 'd' * 64,
        'source_transaction_contract_verified': True, 'producer_profile': PROFILE, 'eve_sha256': 'e' * 64,
        'transaction_count': 100, 'audit_source_sha256': pin, 'observations_file': observed.name,
        'observations_sha256': sha(observed), 'observation_count': 1, 'scenario': 'fox',
        'role': 'observed_nontraining_calibration', 'historical_application_receipt_proven': False,
        'actor_or_authority_proven': False, 'goal_qualified': False, 'new_independent_evaluation': False}
    path.write_text(json.dumps(manifest), encoding='utf8')
    return raw, pin, path, manifest, row


def observe(data):
    raw, pin, path, _manifest, _row = data
    reader = open_review(pin, raw, path, sha(path))
    assert isinstance(reader, SharedDnsTransactionReview)
    result = [reader.observe(n, line, source_sha256=pin) for n, line in enumerate(raw, 1)]
    reader.verify()
    return result


def test_same_frozen_episode_rule_has_transaction_proof_without_fake_packet_fields(tmp_path):
    result = observe(prepare(tmp_path / 'case'))
    assert result[:2] == [None, None] and all(result[2:])
    for proof in result[2:]:
        assert proof['transaction_ordinal'] == 10 and proof['eve_ordinal'] == 30
        assert not {'packet_ordinal', 'frame_sha256', 'capture_time_ns'} & proof.keys()
        assert proof['historical_application_receipt_proven'] is False and proof['actor_or_authority_proven'] is False
        assert proof['automatic_enforcement_allowed'] is False


@pytest.mark.parametrize('bound,capture', [(100000000, 97000000000), (101000000, 97000000000), (98500000, 94000000000)])
def test_equal_future_or_stale_transaction_evidence_cannot_backfill_start(tmp_path, bound, capture):
    result = observe(prepare(tmp_path / 'case', bound_us=bound, capture_ns=capture))
    assert result[2] is None
    assert (result[3] is not None) == (bound == 100000000)


def test_normal_preexisting_unit_does_not_borrow_background_dns_shape(tmp_path):
    assert observe(prepare(tmp_path / 'case', unit='prior-unit')) == [None] * 4


@pytest.mark.parametrize('fault', ['training_role', 'future_final', 'fake_packet', 'future_event',
    'truth', 'shape', 'authority', 'app_receipt', 'duplicate', 'wrong_source', 'profile'])
def test_resigned_but_wrong_role_source_shape_or_proof_is_rejected(tmp_path, fault):
    raw, pin, path, manifest, row = prepare(tmp_path / 'case')
    if fault == 'training_role': manifest['role'] = 'training'
    if fault == 'future_final': manifest['role'] = 'final_reserved'
    if fault == 'fake_packet': row['packet_ordinal'] = row.pop('transaction_ordinal')
    if fault == 'future_event': row['source_transaction_bound']['event_time_us'] += 1
    if fault == 'truth': row['malicious'] = True
    if fault == 'shape': row['encoded_shape'] = False
    if fault == 'authority': row['source_transaction_bound']['actor_or_authority_proven'] = True
    if fault == 'app_receipt': manifest['historical_application_receipt_proven'] = True
    if fault == 'wrong_source': manifest['audit_source_sha256'] = 'f' * 64
    if fault == 'profile': manifest['producer_profile'] = 'packet-decoder-prefix'
    observed = path.parent / manifest['observations_file']
    observed.write_text((json.dumps(row) + '\n') * (2 if fault == 'duplicate' else 1), encoding='utf8')
    manifest['observation_count'] = 2 if fault == 'duplicate' else 1
    manifest['observations_sha256'] = sha(observed)
    path.write_text(json.dumps(manifest), encoding='utf8')
    with pytest.raises(ValueError):
        SharedDnsTransactionReview(pin, raw, path, sha(path))


@pytest.fixture
def lab(tmp_path, monkeypatch):
    lab = make_lab(tmp_path, monkeypatch)
    rows = events()
    for row in rows:
        row['timestamp'] = row['timestamp'].replace('1970-01-01T00:01:', '2022-01-20T13:16:')
    lab.values[intake.EVE] = b''.join((json.dumps(row) + '\n').encode() for row in rows)
    lab.values[intake.RUNTIME] = runtime(count=4)
    original = lab.package

    def package():
        original()
        receipt = json.loads(lab.acquisition.read_bytes())
        monkeypatch.setattr(intake, 'ASSETS', {'russellmitchell': {'role': 'training',
            'receipt_schema': receipt['schema'], 'asset': receipt['asset']}})
    lab.package = package
    package()
    monkeypatch.setattr(intake, 'get_settings', lambda: type('Settings', (), {'app_environment': 'test'})())
    return lab


def run(lab, tmp_path):
    return intake.run('russellmitchell', lab.acquisition, sha(lab.acquisition), lab.archive,
                      lab.prep, sha(lab.prep), lab.raw, tmp_path / 'tx-result')


def test_intake_opens_only_native_allowlist_and_keeps_roles_without_labels_or_pcaps(lab, tmp_path, monkeypatch):
    original, opened = zipfile.ZipFile.open, []

    def check(self, member, *args, **kwargs):
        name = member.filename if isinstance(member, zipfile.ZipInfo) else member
        assert name in {intake.AUDIT, intake.FACTS, intake.RUNTIME, intake.EVE}
        opened.append(name)
        return original(self, member, *args, **kwargs)
    monkeypatch.setattr(zipfile.ZipFile, 'open', check)
    result = run(lab, tmp_path)
    assert result['completed'] and result['source_transaction_contract_verified']
    assert result['role'] == 'training' and result['labels_opened'] is False
    assert result['projection']['dns_udp_transactions'] == 3 and result['producer']['profile'] == PROFILE
    assert result['historical_application_receipt_proven'] is False and result['new_independent_evaluation'] is False
    assert opened == [intake.AUDIT, intake.FACTS, intake.RUNTIME, intake.EVE]


@pytest.mark.parametrize('fault', ['audit', 'timezone', 'worker', 'counter', 'missing_counter'])
def test_unverified_native_contract_keeps_intake_incomplete(lab, tmp_path, fault):
    if fault == 'audit': lab.values[intake.AUDIT] = b'different source'
    if fault == 'timezone': lab.values[intake.FACTS] = b'{"date_time":{"tz":"other","tz_offset":"+0000"}}'
    if fault == 'worker': lab.values[intake.RUNTIME] = runtime(4).replace(b'all 1 packet', b'all 2 packet')
    if fault in {'counter', 'missing_counter'}:
        rows = list(map(json.loads, lab.values[intake.EVE].splitlines()))
        if fault == 'counter': rows[-1]['stats']['app_layer']['tx']['dns_udp'] = 2
        else: del rows[0]['stats']['app_layer']['tx']['dns_udp']
        lab.values[intake.EVE] = b''.join((json.dumps(row) + '\n').encode() for row in rows)
    lab.package()
    with pytest.raises((ValueError, KeyError)):
        run(lab, tmp_path)
    result = json.loads((tmp_path / 'tx-result/run.json').read_bytes())
    assert result['completed'] is False and result['source_transaction_contract_verified'] is False


def test_local_mode_gate_rejected_before_admission(lab, tmp_path, monkeypatch):
    monkeypatch.setattr(intake, 'get_settings', lambda: type('Settings', (), {'app_environment': 'production'})())
    with pytest.raises(ValueError, match='local_test_only'):
        run(lab, tmp_path)
    assert not (tmp_path / 'tx-result').exists()


def test_modified_archive_rejected_before_admission(lab, tmp_path):
    with lab.archive.open('ab') as sink:
        sink.write(b'changed')
    with pytest.raises(ValueError, match='archive_file'):
        run(lab, tmp_path)
    assert not (tmp_path / 'tx-result').exists()


def test_same_size_archive_tamper_rejected_by_full_checksum(lab, tmp_path):
    with lab.archive.open('r+b') as stream:
        stream.seek(10)
        value = stream.read(1)[0]
        stream.seek(10)
        stream.write(bytes([value ^ 1]))
    with pytest.raises(ValueError, match='verified_archive'):
        run(lab, tmp_path)
    assert not (tmp_path / 'tx-result').exists()


def test_transaction_stage_preserves_observed_role_and_never_stages_stats_or_archive(lab, tmp_path):
    run(lab, tmp_path)
    prep = json.loads(lab.prep.read_bytes())
    prep['pairs'][0]['rows'] = 1
    lab.prep.write_text(json.dumps(prep), encoding='utf8')
    manifest = json.loads((lab.raw / 'audit.json').read_bytes())
    manifest['pairs'][0]['provenance'].update(simulation_start=1642684600, simulation_end=1642684700)
    (lab.raw / 'audit.json').write_text(json.dumps(manifest), encoding='utf8')
    prep['source_manifest_sha256'] = sha(lab.raw / 'audit.json')
    lab.prep.write_text(json.dumps(prep), encoding='utf8')
    # Rebind the synthetic test's prepared metadata before staging; no source or
    # label changes. This fixture is functional and never counted in F1.
    receipt_path = tmp_path / 'tx-result/run.json'
    receipt = json.loads(receipt_path.read_bytes())
    receipt.update(scenario='fox', role='observed_nontraining_calibration', preparation_sha256=sha(lab.prep))
    receipt_path.write_text(json.dumps(receipt), encoding='utf8')
    pin = prep['pairs'][0]['raw_sha256']
    baseline = tmp_path / 'before.jsonl'
    baseline.write_text(json.dumps({'case_id': hashlib.sha256((pin + ':1').encode()).hexdigest(),
        'source_index': 0, 'before': False, 'after': False, 'before_score': 0.0, 'after_score': 0.0,
        'reason': 'unchanged', 'error': None}) + '\n', encoding='utf8')
    catalog = {'schema': 'vpn-protocol-replay-catalog-1', 'goal_qualified': False, 'scope': 'observed_development',
        'scenarios': [{'name': 'fox', 'preparation': str(lab.prep), 'preparation_sha256': sha(lab.prep),
                       'raw': str(lab.raw), 'baseline': str(baseline), 'baseline_sha256': sha(baseline), 'population': 1}],
        'shared_dns_support': [{'scenario': 'fox', 'source_index': 0,
                               'intake': str(receipt_path), 'intake_sha256': sha(receipt_path)}]}
    path = tmp_path / 'catalog.json'
    path.write_text(json.dumps(catalog), encoding='utf8')
    result = staging.stage(path, sha(path), tmp_path / 'package')
    assert result['completed'] and result['frozen_training_parameters_staged'] is False
    staged = tmp_path / 'package/inputs/native-dns/source-0'
    assert {p.name for p in staged.iterdir()} == {'manifest.json', 'shared-dns-transactions.jsonl'}
    value = json.loads((staged / 'manifest.json').read_bytes())
    assert value['role'] == 'observed_nontraining_calibration' and value['scenario'] == 'fox'
    assert 'capture_packets' not in value and not value['new_independent_evaluation']


def test_reader_rechecks_pinned_inputs_and_disables_changed_raw_sequence(tmp_path):
    raw, pin, path, _manifest, _row = prepare(tmp_path / 'case')
    reader = SharedDnsTransactionReview(pin, raw, path, sha(path))
    assert reader.observe(1, raw[0], source_sha256=pin) is None
    assert reader.observe(2, raw[1] + 'changed', source_sha256=pin) is None
    assert reader.disabled is True and reader.observe(3, raw[2], source_sha256=pin) is None
    path.write_bytes(b'changed')
    with pytest.raises(ValueError):
        reader.verify()


def test_unsupported_native_name_is_not_an_alert_candidate(tmp_path):
    raw, pin, path, manifest, row = prepare(tmp_path / 'case')
    row.update(query_shape_supported=False, payload_labels=0, non_hostname_base64_characters=False, encoded_shape=False)
    (path.parent / manifest['observations_file']).write_text(json.dumps(row) + '\n', encoding='utf8')
    manifest['observations_sha256'] = sha(path.parent / manifest['observations_file'])
    path.write_text(json.dumps(manifest), encoding='utf8')
    assert observe((raw, pin, path, manifest, row)) == [None] * 4
