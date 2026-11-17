import hashlib
import json
import zipfile
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from scripts import prepare_shared_dns_capture as intake
from scripts import prepare_vpn_packet_members as archive_reader
from scripts.f1_lab.transfer_evaluation import sha
from tests.test_dns_capture import frame, runtime
from tests.test_f1_pcap_initial import pcap


def make_lab(tmp_path, monkeypatch):
    raw = tmp_path / 'raw'
    raw.mkdir()
    audit = raw / 'pair-0-raw.source'
    audit.write_bytes(b'type=SERVICE_START msg=audit(1642684615.5:1): pid=1 uid=0 auid=4294967295\n')
    manifest = {'completed': True, 'timestamp_basis':
        'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
        'pairs': [{'provenance': {'raw_member': intake.AUDIT, 'raw_sha256': sha(audit)}}]}
    (raw / 'audit.json').write_text(json.dumps(manifest), encoding='utf8')
    prep = tmp_path / 'preparation.json'
    prep.write_text(json.dumps({'completed': True, 'inputs_contain_truth': False,
        'pairs': [{'raw_member': intake.AUDIT, 'raw_sha256': sha(audit)}],
        'source_manifest_sha256': sha(raw / 'audit.json')}), encoding='utf8')
    eve = b''.join((json.dumps({'timestamp': f'2022-01-20T13:16:{53 if n == 1 else 55}.500000+0000',
        'event_type': 'stats', 'stats': {'capture': {'kernel_packets': n, 'kernel_drops': 0},
        'decoder': {'pkts': n}, 'uptime': n}}) + '\n').encode() for n in (1, 2))
    values = {intake.AUDIT: audit.read_bytes(), intake.FACTS: b'{"ansible_facts":{"date_time":{"tz":"UTC","tz_offset":"+0000"}}}',
              intake.RUNTIME: runtime(), intake.PCAP: pcap([(1642684613, 0, frame()), (1642684614, 0, b'')]),
              intake.EVE: eve, 'labels/internal_share/logs/audit/audit.log': b'this label must not be opened'}
    archive, acquisition = tmp_path / 'capture.zip', tmp_path / 'acquisition.json'

    def resign():
        asset = replace(intake.ASSET, bytes=archive.stat().st_size,
                        publisher_md5=hashlib.md5(archive.read_bytes(), usedforsecurity=False).hexdigest())
        monkeypatch.setattr(intake, 'ASSET', asset)
        monkeypatch.setattr(archive_reader, 'ASSET', asset)
        receipt = {'schema': 'pinned-packet-training-acquisition-1', 'completed': True,
                   'asset': asdict(asset), 'role': 'training', 'purpose': 'noncommercial_research',
                   'publisher_md5_verified': True, 'local_sha256': sha(archive), 'bytes_received': asset.bytes,
                   'archive_extracted': False, 'code_executed_from_asset': False,
                   'goal_qualified': False, 'new_independent_evaluation': False}
        acquisition.write_text(json.dumps(receipt), encoding='utf8')

    def package():
        with zipfile.ZipFile(archive, 'w') as target:
            for name, body in values.items():
                target.writestr(name, body)
        resign()

    package()
    monkeypatch.setattr(intake, 'get_settings', lambda: SimpleNamespace(app_environment='test'))
    monkeypatch.setattr(intake.shutil, 'disk_usage', lambda _: SimpleNamespace(free=4 * 1024**3))
    return SimpleNamespace(raw=raw, prep=prep, values=values, archive=archive,
                           acquisition=acquisition, package=package, resign=resign)


@pytest.fixture
def lab(tmp_path, monkeypatch):
    return make_lab(tmp_path, monkeypatch)


def run(lab, tmp_path):
    return intake.run(lab.acquisition, sha(lab.acquisition), lab.archive, lab.prep, sha(lab.prep),
                      lab.raw, tmp_path / 'result')


def test_whole_native_contract_and_source_pins_without_labels_or_app_receipt_claim(lab, tmp_path, monkeypatch):
    original = zipfile.ZipFile.open
    opened = []

    def observe(self, name, *args, **kwargs):
        selected = name.filename if isinstance(name, zipfile.ZipInfo) else name
        assert not selected.startswith('labels/')
        opened.append(selected)
        return original(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, 'open', observe)
    result = run(lab, tmp_path)
    assert result['completed'] and result['source_decoder_contract_verified']
    assert result['admitted_to_offline_native_replay'] is True
    assert result['historical_application_receipt_proven'] is False
    assert result['actor_or_authority_proven'] is False and result['goal_qualified'] is False
    assert result['capture']['packets'] == 2 and result['capture']['dns_queries'] == 1
    assert result['stats_rows'] == 2 and result['labels_opened'] is False
    assert opened == [intake.AUDIT, intake.FACTS, intake.RUNTIME, intake.PCAP, intake.EVE]
    row = json.loads((tmp_path / 'result/observations.jsonl').read_bytes())
    assert row['source_decoder_bound']['seen_no_later_than_us'] == 1642684613500000
    assert row['source_decoder_bound']['application_receipt_time_proven'] is False


@pytest.mark.parametrize('fault', ['role', 'size', 'completion', 'checksum', 'code', 'goal'])
def test_invalid_acquisition_scope_rejected_before_reading(lab, tmp_path, fault):
    row = json.loads(lab.acquisition.read_bytes())
    key, value = {'role': ('role', 'final'), 'size': ('bytes_received', 0), 'completion': ('completed', False),
                  'checksum': ('publisher_md5_verified', False), 'code': ('code_executed_from_asset', True),
                  'goal': ('goal_qualified', True)}[fault]
    row[key] = value
    lab.acquisition.write_text(json.dumps(row), encoding='utf8')
    with pytest.raises(ValueError):
        run(lab, tmp_path)
    assert not (tmp_path / 'result').exists()


@pytest.mark.parametrize('fault', ['audit', 'timezone', 'worker', 'extra_capture', 'drop', 'missing_drop',
                                  'truth', 'terminal_count', 'bad_eve'])
def test_incomplete_native_evidence_cannot_publish_verified_context(lab, tmp_path, fault):
    if fault == 'audit': lab.values[intake.AUDIT] = b'other audit row\n'
    if fault == 'timezone': lab.values[intake.FACTS] = b'{"date_time":{"tz":"other","tz_offset":"+0000"}}'
    if fault == 'worker': lab.values[intake.RUNTIME] = runtime().replace(b'all 1 packet', b'all 2 packet')
    if fault == 'extra_capture': lab.values[intake.PCAP + '.extra'] = lab.values[intake.PCAP]
    if fault in {'drop', 'missing_drop', 'truth', 'terminal_count'}:
        rows = list(map(json.loads, lab.values[intake.EVE].splitlines()))
        if fault == 'drop': rows[-1]['stats']['capture']['kernel_drops'] = 1
        if fault == 'missing_drop': del rows[-1]['stats']['capture']['kernel_drops']
        if fault == 'truth': rows[-1]['ground_truth'] = False
        if fault == 'terminal_count': rows[-1]['stats']['decoder']['pkts'] = 1
        lab.values[intake.EVE] = b''.join((json.dumps(row) + '\n').encode() for row in rows)
    if fault == 'bad_eve': lab.values[intake.EVE] = b'{not json}\n'
    lab.package()
    with pytest.raises((ValueError, KeyError)):
        run(lab, tmp_path)
    result = json.loads((tmp_path / 'result/run.json').read_bytes())
    assert result['completed'] is False and result['source_decoder_contract_verified'] is False
    assert result['admitted_to_offline_native_replay'] is False


def test_manifest_changed_during_scan_cannot_publish_completed(lab, tmp_path, monkeypatch):
    original = intake.scan

    def change(*args):
        result = original(*args)
        (lab.raw / 'audit.json').write_bytes(b'changed')
        return result

    monkeypatch.setattr(intake, 'scan', change)
    with pytest.raises(ValueError, match='input_drift'):
        run(lab, tmp_path)
    assert json.loads((tmp_path / 'result/run.json').read_bytes())['completed'] is False


def test_low_disk_headroom_keeps_intake_incomplete(lab, tmp_path, monkeypatch):
    monkeypatch.setattr(intake.shutil, 'disk_usage', lambda _: SimpleNamespace(free=0))
    with pytest.raises(ValueError, match='disk_headroom'):
        run(lab, tmp_path)
    assert json.loads((tmp_path / 'result/run.json').read_bytes())['completed'] is False
