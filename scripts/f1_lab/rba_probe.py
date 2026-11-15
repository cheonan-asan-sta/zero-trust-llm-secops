"""Bounded CSV schema probe inside an anchored ZIP; no full member extraction."""

import csv
import hashlib
import json
import re
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path

from scripts.f1_lab.bounded_zip import MAX_ARCHIVE, entry, fingerprint, index_bounds
from scripts.f1_lab.native_jsonl import require

MAX_PREFIX = 1024**2
MAX_LINE = 65536
MAX_CSV_DECLARED = 32*1024**3
REQUIRED = {'User ID', 'Login Timestamp', 'Login Successful', 'Is Attack IP', 'Is Account Takeover'}
BOOLEANS = ('Login Successful', 'Is Attack IP', 'Is Account Takeover')


class BoundedLines:
    def __init__(self, stream):
        self.stream, self.bytes, self.lines = stream, 0, 0
        self.sha = hashlib.sha256()

    def __iter__(self):
        return self

    def __next__(self):
        raw = self.stream.readline(MAX_LINE+1)
        if not raw:
            raise StopIteration
        require(len(raw) <= MAX_LINE and self.bytes+len(raw) <= MAX_PREFIX, 'rba_probe_prefix_bound')
        self.sha.update(raw)
        self.bytes += len(raw)
        self.lines += 1
        return raw.decode('utf-8-sig' if self.lines == 1 else 'utf-8')


def boolean(value):
    return True if value in {'True', 'true'} else False if value in {'False', 'false'} else None


def timestamp_shape(value):
    if re.fullmatch(r'-?\d+', value):
        return 'integer_units_unverified'
    try:
        instant = datetime.fromisoformat(value)
        return 'iso_with_timezone' if instant.tzinfo is not None else 'iso_timezone_missing'
    except ValueError:
        return 'unsupported'


def probe(path, expected_sha256, archive_name, output, *, limit=128):
    path, output = Path(path), Path(output)
    require(type(limit) is int and 1 <= limit <= 128, 'rba_probe_record_limit')
    require(isinstance(expected_sha256, str) and re.fullmatch(r'[a-f0-9]{64}', expected_sha256), 'rba_probe_external_anchor')
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_ARCHIVE, 'rba_probe_archive')
    require(not output.exists() and not output.is_symlink(), 'fresh_rba_probe_output')
    missing, labels, time_shapes, users = Counter(), {name: Counter() for name in BOOLEANS}, Counter(), set()
    with path.open('rb') as raw_archive:
        require(fingerprint(raw_archive) == expected_sha256, 'rba_probe_archive_hash')
        bounds = index_bounds(raw_archive)
        raw_archive.seek(0)
        with zipfile.ZipFile(raw_archive) as archive:
            infos = archive.infolist()
            require(len(infos) == bounds['members'], 'rba_probe_index_population')
            entries = [entry(info, bounds['index_offset']) for info in infos]
            require(len({row['name'] for row in entries}) == len(entries), 'rba_probe_duplicate_member')
            selected = [row for row in entries if row['archive_name'] == archive_name]
            require(len(selected) == 1 and selected[0]['kind'] == 'regular' and not selected[0]['encrypted']
                    and selected[0]['name'].lower().endswith('.csv') and 0 < selected[0]['bytes'] <= MAX_CSV_DECLARED
                    and selected[0]['compression'] in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}, 'rba_probe_member')
            # This dedicated prefix reader deliberately does not use or widen
            # the generic512MiB whole-member copy path.
            old_limit = csv.field_size_limit()
            try:
                csv.field_size_limit(MAX_LINE)
                with archive.open(archive_name) as source:
                    lines = BoundedLines(source)
                    reader = csv.reader(lines, strict=True)
                    header = next(reader)
                    require(1 <= len(header) <= 128 and len(set(header)) == len(header) and REQUIRED <= set(header)
                            and all(len(name) <= 128 for name in header), 'rba_probe_header')
                    for _ in range(limit):
                        values = next(reader)
                        require(len(values) == len(header), 'rba_probe_row_alignment')
                        row = dict(zip(header, values, strict=True))
                        for name, value in row.items():
                            missing[name] += value == ''
                        for name in BOOLEANS:
                            value = boolean(row[name])
                            labels[name]['unknown' if value is None else 'true' if value else 'false'] += 1
                        time_shapes[timestamp_shape(row['Login Timestamp'])] += 1
                        user = row['User ID']
                        require(len(user) <= 256, 'rba_probe_user_bound')
                        if user:
                            users.add(hashlib.sha256(('rba-user:'+user).encode()).hexdigest())
            except StopIteration as error:
                raise ValueError('rba_probe_prefix_shorter_than_declared_limit') from error
            finally:
                csv.field_size_limit(old_limit)
        require(fingerprint(raw_archive) == expected_sha256, 'rba_probe_archive_changed')
    result = {'schema': 'f1-rba-development-probe-1', 'completed': True, 'archive_sha256': expected_sha256,
              'archive_member': selected[0], 'header': header, 'development_records_parsed': limit,
              'prefix_bytes_returned_to_csv_parser': lines.bytes, 'prefix_physical_lines': lines.lines,
              'prefix_sha256': lines.sha.hexdigest(), 'missing_by_field': dict(missing),
              'literal_boolean_states': {name: dict(counts) for name, counts in labels.items()},
              'timestamp_shapes': dict(time_shapes), 'development_probe_user_references': sorted(users),
              'probe_disposition': 'Development only; these users cannot be reported as unseen-user final data',
              'case_values_displayed': 0, 'later_csv_records_parsed': 0, 'decompressor_prefetch_may_exceed_prefix': True,
              'whole_csv_requested_or_extracted': False, 'full_csv_crc_verification_claimed': False,
              'binary_truth_contract_selected': False, 'classifier_fitted': False, 'final_partition_certified': False,
              'original_six_domain_goal_replaced': False, 'paid_api_calls': 0, 'aws_sdk_calls': 0, 'goal_qualified': False}
    output.mkdir(parents=True, mode=0o700)
    (output/'probe.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n', encoding='utf-8')
    return result
