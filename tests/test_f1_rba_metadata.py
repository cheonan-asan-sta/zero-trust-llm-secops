import csv
import hashlib
import io
import json
import sqlite3
import zipfile

import pytest

from scripts.f1_lab.rba_metadata import audit, partition, user_reference
from scripts.f1_lab.rba_probe import probe

HEADER = ['index', 'Login Timestamp', 'User ID', 'Round-Trip Time [ms]', 'IP Address', 'Country', 'Region', 'City',
          'ASN', 'User Agent String', 'Browser Name and Version', 'OS Name and Version', 'Device Type',
          'Login Successful', 'Is Attack IP', 'Is Account Takeover']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(directory, *, reverse_ato=False, malformed=False, record_limit=100):
    directory.mkdir(parents=True)
    rows = [
        ['0', '2020-01-01 10:00:00', '100', '', 'example-ip', 'EX', 'region', 'city', '100',
         'secret-case-marker', 'browser', 'os', 'desktop', 'True', 'False', 'False'],
        ['1', '2020-01-01 09:59:00', '200', '12.5', 'other-ip', 'EX', 'region', 'city', '100',
         'agent', 'browser', 'os', 'desktop', 'False', 'True', 'True'],
        ['2', '2020-01-01 10:01:00', '100', 'NaN', 'example-ip', 'EX', 'region', 'city', '100',
         'agent', 'browser', 'os', 'desktop', 'False', 'false', 'maybe']]
    if reverse_ato:
        for row in rows:
            if row[-1] in ('True', 'False'):
                row[-1] = 'False' if row[-1] == 'True' else 'True'
    if malformed:
        rows.append(['unaligned'])
    text = io.StringIO(newline='')
    writer = csv.writer(text)
    writer.writerow(HEADER)
    writer.writerows(rows)
    path = directory/'source.zip'
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_STORED) as archive:
        archive.writestr('source.csv', text.getvalue())
    probe(path, digest(path), 'source.csv', directory/'probe', limit=1)
    with zipfile.ZipFile(path) as archive:
        info = archive.getinfo('source.csv')
        member_bytes, crc = info.file_size, f'{info.CRC:08x}'
    protocol = {'schema': 'f1-rba-metadata-audit-1', 'archive_sha256': digest(path), 'archive_bytes': path.stat().st_size,
                'csv_member': 'source.csv', 'csv_bytes': member_bytes, 'csv_crc32': crc,
                'probe_receipt_sha256': digest(directory/'probe/probe.json'), 'header': HEADER,
                'maximum_rows': record_limit, 'batch_rows': 2, 'maximum_seconds': 30}
    contract = directory/'protocol.json'
    contract.write_text(json.dumps(protocol))
    return path, contract, directory/'probe/probe.json'


def run_fixture(directory, **kwargs):
    path, contract, observed = fixture(directory, **kwargs)
    result = audit(path, contract, digest(contract), observed, directory/'out')
    return result


def test_full_metadata_audit_preserves_every_label_state_and_verifies_crc_at_eof(tmp_path):
    result = run_fixture(tmp_path/'fixture')
    assert result['completed'] and result['records'] == 3 and result['full_csv_crc_verified_at_eof']
    assert result['all_later_rows_mechanically_parsed_for_metadata']
    assert sum(part['ato_true'] for part in result['partitions'].values()) == 1
    assert sum(part['ato_false'] for part in result['partitions'].values()) == 1
    assert sum(part['ato_unknown'] for part in result['partitions'].values()) == 1
    assert sum(part['rows'] for part in result['partitions'].values()) == 3
    assert sum(part['rows'] for part in result['users_by_partition'].values()) == 3
    assert result['missing_by_field']['Round-Trip Time [ms]'] == 1
    assert result['backwards_timestamps'] == {'iso_timezone_missing': 1}
    assert not result['final_partition_certified'] and not result['classifier_fitted']


def test_observed_user_is_tainted_for_all_rows_and_metadata_does_not_export_cases(tmp_path):
    directory = tmp_path/'fixture'
    result = run_fixture(directory)
    with sqlite3.connect(directory/'out/metadata.sqlite3') as db:
        row = db.execute('SELECT partition,rows,probe_tainted FROM users WHERE reference=?',
                         (hashlib.sha256(b'rba-user:100').digest(),)).fetchone()
    assert row == ('development', 2, 1) and result['probe_user_rows'] == 2
    assert 'secret-case-marker' not in json.dumps(result)
    assert b'secret-case-marker' not in (directory/'out/metadata.sqlite3').read_bytes()


def test_source_labels_cannot_change_user_partition_assignment(tmp_path):
    a, b = tmp_path/'first', tmp_path/'opposite'
    run_fixture(a)
    run_fixture(b, reverse_ato=True)
    assignments, label_counts = [], []
    for directory in (a, b):
        with sqlite3.connect(directory/'out/metadata.sqlite3') as db:
            assignments.append(db.execute('SELECT reference,partition,rows FROM users ORDER BY reference').fetchall())
            label_counts.append(db.execute('SELECT reference,ato_true,ato_false FROM users ORDER BY reference').fetchall())
    assert assignments[0] == assignments[1]
    assert label_counts[0] != label_counts[1]


def test_structurally_bad_record_is_unassigned_unknown_not_dropped_or_called_normal(tmp_path):
    result = run_fixture(tmp_path/'fixture', malformed=True)
    assert result['completed'] and result['records'] == 4 and result['structural_errors'] == 1
    part = result['partitions']['unassigned']
    assert part['rows'] == part['ato_unknown'] == 1 and part['ato_false'] == part['ato_true'] == 0
    assert sum(row['rows'] for row in result['users_by_partition'].values()) == 3


def test_record_limit_keeps_failure_receipt_without_promoting_partial_metadata(tmp_path):
    directory = tmp_path/'fixture'
    result = run_fixture(directory, record_limit=2)
    assert not result['completed'] and result['failure_type'] == 'ValueError'
    assert not result['full_csv_crc_verified_at_eof']
    assert not (directory/'out/metadata.sqlite3').exists() and (directory/'out/audit.json').exists()


def test_member_crc_failure_cannot_be_reported_as_verified_metadata(tmp_path):
    directory = tmp_path/'fixture'
    path, contract, observed = fixture(directory)
    original = path.read_bytes()
    assert original.count(b'secret-case-marker') == 1
    path.write_bytes(original.replace(b'secret-case-marker', b'secret-case-markeX'))
    value = json.loads(contract.read_bytes())
    value['archive_sha256'] = digest(path)
    probe_data = json.loads(observed.read_bytes())
    probe_data['archive_sha256'] = value['archive_sha256']
    observed.write_text(json.dumps(probe_data))
    value['probe_receipt_sha256'] = digest(observed)
    contract.write_text(json.dumps(value))
    result = audit(path, contract, digest(contract), observed, directory/'out')
    assert not result['completed'] and result['failure_type'] == 'BadZipFile'
    assert not result['full_csv_crc_verified_at_eof'] and not (directory/'out/metadata.sqlite3').exists()


def test_changed_probe_cannot_silently_change_observed_user_taint(tmp_path):
    directory = tmp_path/'fixture'
    path, contract, observed = fixture(directory)
    data = json.loads(observed.read_bytes())
    data['development_probe_user_references'] = []
    observed.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='probe_hash'):
        audit(path, contract, digest(contract), observed, directory/'out')
    assert not (directory/'out').exists()


def test_missing_user_cannot_fall_back_to_a_shared_global_identity():
    assert user_reference('') is None and user_reference('unknown') is None
    assert partition(None, set()) == 'unassigned'
    assert user_reference('01') != user_reference('1')
