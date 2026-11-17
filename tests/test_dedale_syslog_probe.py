import bz2
import hashlib
import json
import stat
import zipfile
from pathlib import Path

import pytest

from scripts import inspect_dedale_syslog as intake

ROOT = Path(__file__).resolve().parents[1]


def write_json(path, value):
    path.write_text(json.dumps(value), encoding='utf8')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(tmp_path, extra=None):
    source = tmp_path / 'source.zip'
    selected = 'daily_syslog/first.jsonl.bz2'
    body = bz2.compress(b'{"message":"native","process":{"pid":1}}\n' * 130)
    with zipfile.ZipFile(source, 'w') as archive:
        archive.writestr('z-later.jsonl.bz2', bz2.compress(b'{"future":true}\n'))
        archive.writestr(selected, body)
        if extra is not None:
            if isinstance(extra, str):
                info = zipfile.ZipInfo()
                info.filename = info.orig_filename = extra
                extra = info
            archive.writestr(extra, b'not imported, executed or selected')
    base = json.loads((ROOT / 'infra/f1-lab/dedale-syslog-intake-v126.json').read_bytes())
    codec = json.loads((ROOT / 'infra/f1-lab/dedale-syslog-decoding-v126.json').read_bytes())
    base['file']['bytes'] = source.stat().st_size
    base['file']['publisher_md5'] = hashlib.md5(source.read_bytes(), usedforsecurity=False).hexdigest()
    codec.update({'archive_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                  'member': selected, 'compressed_member_sha256': hashlib.sha256(body).hexdigest(),
                  'compressed_member_bytes': len(body)})
    base_path, codec_path = tmp_path / 'base.json', tmp_path / 'codec.json'
    base_sha = write_json(base_path, base)
    codec['original_contract_sha256'] = base_sha
    codec_sha = write_json(codec_path, codec)
    return [source, base_path, base_sha, codec_path, codec_sha, tmp_path / 'out']


def test_full_zip_and_nested_stream_verified_before_publishing_prefix(tmp_path):
    args = fixture(tmp_path)
    result = intake.inspect(*args)
    assert result['complete'] and result['probe_lines'] == 128 and result['parse_errors'] == 0
    assert result['archive_members'] == 2 and result['member'].endswith('first.jsonl.bz2')
    assert result['publisher_md5_verified'] is True
    assert result['role'] == 'development_schema_probe_only'
    assert result['native_ground_truth_bodies_opened'] == result['simulator_bodies_opened'] == 0
    assert result['metric_or_population_change'] is False
    assert json.loads((args[-1] / 'run.json').read_bytes()) == result
    assert hashlib.sha256((args[-1] / 'probe.jsonl').read_bytes()).hexdigest() == result['probe_sha256']


@pytest.mark.parametrize('which', [1, 3])
def test_contract_byte_mutation_rejected_before_publication(tmp_path, which):
    args = fixture(tmp_path)
    args[which].write_bytes(args[which].read_bytes() + b' ')
    with pytest.raises(ValueError, match='probe_contract_hash'):
        intake.inspect(*args)
    assert not args[-1].exists()


def test_changed_source_cannot_reuse_pins(tmp_path):
    args = fixture(tmp_path)
    data = bytearray(args[0].read_bytes())
    data[35] ^= 1
    args[0].write_bytes(data)
    with pytest.raises(ValueError, match='probe_archive_hash'):
        intake.inspect(*args)
    assert not args[-1].exists()


@pytest.mark.parametrize('field,value', [('role', 'final_reserved'), ('selection_unchanged', False),
    ('independent_final_qualification', True), ('model_training_prediction_or_metric_change', True),
    ('maximum_observed_physical_lines', 129), ('member', 'z-later.jsonl.bz2'),
    ('compressed_member_sha256', 'a' * 64)])
def test_reanchored_contract_cannot_expand_role_or_switch_member(tmp_path, field, value):
    args = fixture(tmp_path)
    codec = json.loads(args[3].read_bytes())
    codec[field] = value
    args[4] = write_json(args[3], codec)
    with pytest.raises(ValueError):
        intake.inspect(*args)
    assert not args[-1].exists()


@pytest.mark.parametrize('extra', ['../escape', '/absolute', 'C:/absolute', 'windows\\escape', 'aaa-labels.jsonl'])
def test_unsafe_paths_or_inserted_earlier_member_do_not_trigger_fallback(tmp_path, extra):
    args = fixture(tmp_path, extra)
    with pytest.raises(ValueError):
        intake.inspect(*args)
    assert not args[-1].exists()


def test_no_overwrite_of_existing_result(tmp_path):
    args = fixture(tmp_path)
    args[-1].mkdir()
    marker = args[-1] / 'keep'
    marker.write_bytes(b'keep')
    with pytest.raises(ValueError, match='probe_output_exists'):
        intake.inspect(*args)
    assert marker.read_bytes() == b'keep'


def test_source_mutation_during_decoding_cannot_publish(tmp_path, monkeypatch):
    args = fixture(tmp_path)
    original = intake.probe

    def changed(*a, **kw):
        result = original(*a, **kw)
        data = bytearray(args[0].read_bytes())
        data[35] ^= 1
        args[0].write_bytes(data)
        return result

    monkeypatch.setattr(intake, 'probe', changed)
    with pytest.raises(ValueError, match='probe_archive_changed'):
        intake.inspect(*args)
    assert not args[-1].exists()


def test_symlink_archive_member_cannot_be_interpreted(tmp_path):
    info = zipfile.ZipInfo('other-link')
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    args = fixture(tmp_path, info)
    with pytest.raises(ValueError, match='probe_member_link'):
        intake.inspect(*args)
    assert not args[-1].exists()


def repin_archive(args):
    base = json.loads(args[1].read_bytes())
    codec = json.loads(args[3].read_bytes())
    base['file']['bytes'] = args[0].stat().st_size
    base['file']['publisher_md5'] = hashlib.md5(args[0].read_bytes(), usedforsecurity=False).hexdigest()
    args[2] = write_json(args[1], base)
    codec['original_contract_sha256'] = args[2]
    codec['archive_sha256'] = hashlib.sha256(args[0].read_bytes()).hexdigest()
    args[4] = write_json(args[3], codec)


def test_duplicate_zip_names_cannot_silently_select_last_entry(tmp_path):
    args = fixture(tmp_path)
    with pytest.warns(UserWarning, match='Duplicate name'), zipfile.ZipFile(args[0], 'a') as archive:
        archive.writestr('daily_syslog/first.jsonl.bz2', bz2.compress(b'{}\n'))
    repin_archive(args)
    with pytest.raises(ValueError, match='probe_archive_inventory'):
        intake.inspect(*args)
    assert not args[-1].exists()


def test_zip_crc_mismatch_is_not_ignored_even_with_reanchored_archive_hash(tmp_path):
    args = fixture(tmp_path)
    codec = json.loads(args[3].read_bytes())
    with zipfile.ZipFile(args[0]) as archive:
        item = archive.getinfo(codec['member'])
        offset = item.header_offset + 30 + len(item.filename.encode()) + len(item.extra)
    data = bytearray(args[0].read_bytes())
    data[offset + 10] ^= 1
    args[0].write_bytes(data)
    repin_archive(args)
    with pytest.raises(zipfile.BadZipFile, match='CRC'):
        intake.inspect(*args)
    assert not args[-1].exists()
