import csv
import hashlib
import io
import zipfile

import pytest

from scripts.f1_lab.rba_probe import probe

HEADER = ['User ID', 'Login Timestamp', 'Login Successful', 'Is Attack IP', 'Is Account Takeover', 'User Agent String']


def archive(tmp_path, *, header=None, rows=None, suffix=b'', name='rba-dataset.csv'):
    text = io.StringIO(newline='')
    writer = csv.writer(text)
    writer.writerow(HEADER if header is None else header)
    writer.writerows(rows if rows is not None else [
        ['private-user-1', '2020-01-01 10:00:00', 'True', 'False', 'False', 'agent'],
        ['private-user-2', '2020-01-01 10:01:00', 'False', 'True', 'True', 'agent']])
    path = tmp_path/'source.zip'
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as stream:
        stream.writestr(name, text.getvalue().encode()+suffix)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_bounded_probe_keeps_later_records_unparsed_and_does_not_claim_full_csv_crc(tmp_path):
    path, anchor = archive(tmp_path, suffix=b'not-a-csv-record,\xff\n')
    result = probe(path, anchor, 'rba-dataset.csv', tmp_path/'out', limit=2)
    assert result['completed'] and result['development_records_parsed'] == 2
    assert result['later_csv_records_parsed'] == 0 and result['decompressor_prefetch_may_exceed_prefix']
    assert not result['full_csv_crc_verification_claimed'] and not result['whole_csv_requested_or_extracted']
    assert len(result['development_probe_user_references']) == 2 and 'private-user-' not in str(result)
    assert result['timestamp_shapes'] == {'iso_timezone_missing': 2}


def test_quoted_multiline_record_and_unknown_booleans_are_not_silently_normal(tmp_path):
    path, anchor = archive(tmp_path, rows=[['one', '12345', '', 'False', 'maybe', 'first\nsecond']])
    result = probe(path, anchor, 'rba-dataset.csv', tmp_path/'out', limit=1)
    assert result['literal_boolean_states']['Login Successful'] == {'unknown': 1}
    assert result['literal_boolean_states']['Is Account Takeover'] == {'unknown': 1}
    assert result['timestamp_shapes'] == {'integer_units_unverified': 1}
    assert result['prefix_physical_lines'] == 3
    assert not result['binary_truth_contract_selected'] and not result['goal_qualified']


@pytest.mark.parametrize('fault', ['duplicate_header', 'missing_header', 'misaligned_row', 'short_prefix'])
def test_schema_or_population_errors_never_publish_success(tmp_path, fault):
    header, rows, limit = HEADER, None, 2
    if fault == 'duplicate_header':
        header = HEADER+['User ID']
    elif fault == 'missing_header':
        header = HEADER[:-2]
    elif fault == 'misaligned_row':
        rows = [['one']]
    else:
        limit = 3
    path, anchor = archive(tmp_path, header=header, rows=rows)
    old_limit = csv.field_size_limit()
    with pytest.raises((ValueError, csv.Error)):
        probe(path, anchor, 'rba-dataset.csv', tmp_path/'out', limit=limit)
    assert not (tmp_path/'out/probe.json').exists() and csv.field_size_limit() == old_limit


def test_long_physical_line_cannot_expand_parser_past_its_bound(tmp_path):
    path, anchor = archive(tmp_path, rows=[['user', '12345', 'True', 'False', 'False', 'x'*70000]])
    with pytest.raises(ValueError, match='prefix_bound'):
        probe(path, anchor, 'rba-dataset.csv', tmp_path/'out', limit=1)
    assert not (tmp_path/'out').exists()


def test_changed_archive_or_unexpected_member_never_reads_unanchored_cases(tmp_path):
    path, anchor = archive(tmp_path)
    with pytest.raises(ValueError, match='archive_hash'):
        probe(path, '0'*64, 'rba-dataset.csv', tmp_path/'out-a', limit=1)
    with pytest.raises(ValueError, match='member'):
        probe(path, anchor, 'other.csv', tmp_path/'out-b', limit=1)


def test_probe_record_limit_cannot_be_widened_to_a_final_dataset_read(tmp_path):
    path, anchor = archive(tmp_path)
    with pytest.raises(ValueError, match='record_limit'):
        probe(path, anchor, 'rba-dataset.csv', tmp_path/'out', limit=129)
