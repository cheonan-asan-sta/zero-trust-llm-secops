import hashlib
import io
import json
import struct
import zipfile
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from scripts import prepare_vpn_packet_members as intake
from scripts.f1_lab import bounded_zip
from scripts.f1_lab.transfer_evaluation import sha
from tests.test_f1_pcap_initial import frame, pcap


@pytest.fixture
def lab(tmp_path, monkeypatch):
    raw = tmp_path / 'original-vpn.source'; raw.write_bytes(b'original physical VPN row\n')
    archive = tmp_path / 'packets.zip'
    values = {intake.VPN_LOG: raw.read_bytes(), intake.MEMBERS[0]: pcap([(1, 1, frame())]),
              intake.MEMBERS[1]: pcap([]), 'labels/vpn/logs/openvpn.log': b'not opened\n'}

    def package():
        with zipfile.ZipFile(archive, 'w') as z:
            for name, body in values.items():
                z.writestr(name, body)
        return resign()

    def resign():
        asset = replace(intake.ASSET, bytes=archive.stat().st_size,
                        publisher_md5=hashlib.md5(archive.read_bytes(), usedforsecurity=False).hexdigest())
        monkeypatch.setattr(intake, 'ASSET', asset)
        receipt = {'schema': 'pinned-packet-training-acquisition-1', 'completed': True,
                   'asset': asdict(asset), 'purpose': 'noncommercial_research', 'role': 'training',
                   'publisher_md5_verified': True, 'local_sha256': sha(archive), 'bytes_received': asset.bytes,
                   'archive_extracted': False, 'code_executed_from_asset': False,
                   'goal_qualified': False, 'new_independent_evaluation': False}
        path = tmp_path / 'acquisition.json'; path.write_text(json.dumps(receipt), encoding='utf8')
        return path, receipt

    acquisition, receipt = package()
    monkeypatch.setattr(intake, 'get_settings', lambda: SimpleNamespace(app_environment='test'))
    monkeypatch.setattr(intake.shutil, 'disk_usage', lambda _: SimpleNamespace(free=4 * 1024**3))
    return SimpleNamespace(raw=raw, archive=archive, acquisition=acquisition, receipt=receipt,
                           values=values, package=package, resign=resign)


def run(lab, tmp_path):
    return intake.run(lab.acquisition, sha(lab.acquisition), lab.archive, lab.raw, sha(lab.raw), tmp_path / 'result')


def test_full_archive_member_crc_exact_old_log_and_pcap_pin_without_opening_labels(lab, tmp_path, monkeypatch):
    opened = []
    original = zipfile.ZipFile.open

    def observe(self, name, *args, **kwargs):
        selected = name.filename if isinstance(name, zipfile.ZipInfo) else name
        assert not selected.startswith('labels/')
        opened.append(selected)
        return original(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, 'open', observe)
    result = run(lab, tmp_path)
    assert result['completed'] and result['same_vpn_log_bytes_verified'] and result['publisher_md5_verified']
    assert opened == [intake.VPN_LOG, *intake.MEMBERS]
    assert all(m['crc_verified'] and m['sha256'] == m['source_sha256'] for m in result['members'])
    assert [m['initial_frames'] for m in result['members']] == [1, 0]
    assert result['validation_labels_opened'] is False and result['new_independent_evaluation'] is False
    assert result['paid_api_calls'] == result['aws_calls'] == 0
    assert not list((tmp_path / 'result').rglob('*labels*'))
    assert bounded_zip.MAX_ARCHIVE == 2 * 1024**3


@pytest.mark.parametrize('fault', ['incomplete', 'role', 'license', 'checksum', 'code_executed', 'size', 'goal'])
def test_wrong_receipt_scope_never_starts_member_copy(lab, tmp_path, fault):
    row = lab.receipt
    if fault == 'incomplete': row['completed'] = False
    if fault == 'role': row['role'] = 'evaluation'
    if fault == 'license': row['asset']['license_id'] = 'other'
    if fault == 'checksum': row['publisher_md5_verified'] = False
    if fault == 'code_executed': row['code_executed_from_asset'] = True
    if fault == 'size': row['bytes_received'] -= 1
    if fault == 'goal': row['goal_qualified'] = True
    lab.acquisition.write_text(json.dumps(row), encoding='utf8')
    with pytest.raises(ValueError):
        run(lab, tmp_path)
    assert not (tmp_path / 'result').exists()


@pytest.mark.parametrize('fault', ['archive_sha', 'raw_pin', 'acquisition_pin'])
def test_external_pins_and_archive_identity_are_required(lab, tmp_path, fault):
    receipt_pin, raw_pin = sha(lab.acquisition), sha(lab.raw)
    if fault == 'archive_sha':
        lab.archive.write_bytes(lab.archive.read_bytes() + b'changed')
    if fault == 'raw_pin': raw_pin = 'f' * 64
    if fault == 'acquisition_pin': receipt_pin = 'f' * 64
    with pytest.raises(ValueError):
        intake.run(lab.acquisition, receipt_pin, lab.archive, lab.raw, raw_pin, tmp_path / 'result')
    assert not (tmp_path / 'result').exists()


@pytest.mark.parametrize('fault', ['raw_bytes', 'missing_member', 'disk'])
def test_missing_or_mismatched_archive_members_keep_incomplete_report(lab, tmp_path, monkeypatch, fault):
    if fault == 'raw_bytes': lab.values[intake.VPN_LOG] = b'different raw VPN file\n'
    if fault == 'missing_member': del lab.values[intake.MEMBERS[1]]
    if fault == 'disk': monkeypatch.setattr(intake.shutil, 'disk_usage', lambda _: SimpleNamespace(free=0))
    lab.package()
    with pytest.raises(ValueError):
        run(lab, tmp_path)
    assert json.loads((tmp_path / 'result/run.json').read_bytes())['completed'] is False


def test_bad_member_crc_cannot_be_published_as_verified_even_with_whole_archive_pin(lab, tmp_path):
    with zipfile.ZipFile(lab.archive) as z:
        info = z.getinfo(intake.MEMBERS[0])
    body = bytearray(lab.archive.read_bytes())
    nlen, xlen = struct.unpack('<2H', body[info.header_offset + 26:info.header_offset + 30])
    body[info.header_offset + 30 + nlen + xlen + info.file_size - 1] ^= 1
    lab.archive.write_bytes(body); lab.resign()
    with pytest.raises(zipfile.BadZipFile):
        run(lab, tmp_path)
    assert json.loads((tmp_path / 'result/run.json').read_bytes())['completed'] is False
    assert not (tmp_path / 'result/member-0.pcap').exists()


def test_later_member_failure_cannot_mark_partial_pipeline_complete(lab, tmp_path):
    lab.values[intake.MEMBERS[1]] = b'not a pcap'; lab.package()
    with pytest.raises(ValueError):
        run(lab, tmp_path)
    report = json.loads((tmp_path / 'result/run.json').read_bytes())
    assert report['completed'] is False and len(report['members']) == 1


@pytest.mark.parametrize('fault', ['index_size', 'member_count', 'disk'])
def test_archive_index_bounds_precede_zipfile_allocation(lab, fault):
    body = bytearray(lab.archive.read_bytes()); start = len(body) - 22
    if fault == 'index_size': body[start + 12:start + 16] = struct.pack('<I', 17 * 1024**2)
    if fault == 'member_count': body[start + 8:start + 12] = struct.pack('<2H', 50001, 50001)
    if fault == 'disk': body[start + 4:start + 6] = struct.pack('<H', 1)
    with pytest.raises(ValueError):
        intake.index_bound(io.BytesIO(body))


def test_bounded_zip64_index_without_relaxing_generic_reader(lab, monkeypatch):
    prefix = b'x' * 20 + b'y' * 10
    record = struct.pack('<4sQ2H2I4Q', b'PK\x06\x06', 44, 45, 45, 0, 0, 1, 1, 10, 20)
    locator = struct.pack('<4sIQI', b'PK\x06\x07', 0, len(prefix), 1)
    end = struct.pack('<4s4H2IH', b'PK\x05\x06', 0, 0, 65535, 65535, 4294967295, 4294967295, 0)
    body = prefix + record + locator + end
    monkeypatch.setattr(intake, 'ASSET', replace(intake.ASSET, bytes=len(body)))
    assert intake.index_bound(io.BytesIO(body)) == (1, 20)
    assert bounded_zip.MAX_ARCHIVE == 2 * 1024**3
