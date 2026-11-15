"""Streaming publisher-label/support audit; never an independent-performance score."""

import csv
import hashlib
import json
import math
import re
import shutil
import sqlite3
import time
import zipfile
from collections import Counter
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from scripts.f1_lab.bounded_zip import MAX_ARCHIVE, entry, fingerprint, index_bounds
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.rba_probe import BOOLEANS, MAX_LINE, boolean

PARTITIONS = ('development', 'calibration', 'reserved_candidate', 'unassigned')
MAX_CSV = 16*1024**3
MAX_DB = 1024**3
PROGRESS_ROWS = 100000


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


@lru_cache(maxsize=32768)
def user_reference(value):
    if not isinstance(value, str) or not re.fullmatch(r'-?[0-9]{1,20}', value):
        return None
    return hashlib.sha256(('rba-user:'+value).encode()).digest()


def partition(reference, probe_users):
    if reference is None:
        return 'unassigned'
    if reference in probe_users:
        return 'development'
    bucket = int.from_bytes(reference[:8], 'big') % 100
    return 'development' if bucket < 70 else 'calibration' if bucket < 85 else 'reserved_candidate'


def time_value(value):
    if len(value) > 128:
        return 'unsupported', None
    if re.fullmatch(r'-?\d+', value):
        return 'integer_units_unverified', None
    try:
        instant = datetime.fromisoformat(value)
    except ValueError:
        return 'unsupported', None
    if instant.tzinfo is None:
        return 'iso_timezone_missing', instant.isoformat(timespec='microseconds')
    return 'iso_with_timezone', instant.astimezone(UTC).isoformat(timespec='microseconds')


def rtt_state(value):
    if value == '':
        return 'missing'
    try:
        number = float(value) if len(value) <= 64 else float('nan')
    except ValueError:
        number = float('nan')
    return 'within_publisher_range' if math.isfinite(number) and 1 <= number <= 8600000 else 'unsupported_or_outside_publisher_range'


class AuditLines:
    def __init__(self, source, maximum):
        self.source, self.maximum, self.bytes, self.lines = source, maximum, 0, 0
        self.sha = hashlib.sha256()

    def __iter__(self):
        return self

    def __next__(self):
        raw = self.source.readline(MAX_LINE+1)
        if not raw:
            raise StopIteration
        require(len(raw) <= MAX_LINE and self.bytes+len(raw) <= self.maximum, 'rba_metadata_csv_bound')
        self.bytes += len(raw)
        self.lines += 1
        self.sha.update(raw)
        return raw.decode('utf-8-sig' if self.lines == 1 else 'utf-8')


def distribution():
    return {'rows': 0, 'ato_true': 0, 'ato_false': 0, 'ato_unknown': 0,
            'labels': {name: Counter() for name in BOOLEANS}, 'label_cross_table': Counter(),
            'timestamp_shapes': Counter(), 'time_ranges': {}, 'rtt_states': Counter()}


def load_contract(path, expected):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536, 'rba_metadata_protocol')
    body = path.read_bytes()
    require(hashlib.sha256(body).hexdigest() == expected, 'rba_metadata_protocol_hash')
    value = decode(body)
    require(value['schema'] == 'f1-rba-metadata-audit-1' and type(value['maximum_rows']) is int
            and 1 <= value['maximum_rows'] <= 40000000 and type(value['batch_rows']) is int
            and 1 <= value['batch_rows'] <= 25000 and type(value['maximum_seconds']) is int
            and 1 <= value['maximum_seconds'] <= 3600 and type(value['csv_bytes']) is int
            and 0 < value['csv_bytes'] <= MAX_CSV, 'rba_metadata_protocol_limits')
    require(isinstance(value['header'], list) and len(value['header']) == len(set(value['header']))
            and set(BOOLEANS) | {'User ID', 'Login Timestamp', 'Round-Trip Time [ms]'} <= set(value['header']),
            'rba_metadata_protocol_header')
    require(isinstance(value['archive_sha256'], str) and re.fullmatch('[a-f0-9]{64}', value['archive_sha256'])
            and isinstance(value['probe_receipt_sha256'], str) and re.fullmatch('[a-f0-9]{64}', value['probe_receipt_sha256']),
            'rba_metadata_protocol_anchors')
    return value


def audit(archive_path, protocol_path, expected_protocol_sha256, probe_path, output):
    archive_path, probe_path, output = Path(archive_path), Path(probe_path), Path(output)
    protocol = load_contract(protocol_path, expected_protocol_sha256)
    require(archive_path.is_file() and not archive_path.is_symlink()
            and archive_path.stat().st_size == protocol['archive_bytes'] <= MAX_ARCHIVE, 'rba_metadata_archive')
    require(probe_path.is_file() and not probe_path.is_symlink() and probe_path.stat().st_size <= 65536, 'rba_metadata_probe')
    probe_body = probe_path.read_bytes()
    require(hashlib.sha256(probe_body).hexdigest() == protocol['probe_receipt_sha256'], 'rba_metadata_probe_hash')
    probe = decode(probe_body)
    require(probe['completed'] is True and probe['archive_sha256'] == protocol['archive_sha256'], 'rba_metadata_probe_anchor')
    references = probe['development_probe_user_references']
    require(isinstance(references, list) and len(references) <= 128
            and all(isinstance(v, str) and re.fullmatch('[a-f0-9]{64}', v) for v in references), 'rba_metadata_probe_users')
    probe_users = {bytes.fromhex(value) for value in references}
    require(not output.exists() and not output.is_symlink(), 'fresh_rba_metadata_output')
    output.parent.mkdir(parents=True, exist_ok=True)
    require(shutil.disk_usage(output.parent).free > MAX_DB+128*1024**2, 'rba_metadata_disk_headroom')
    output.mkdir(mode=0o700)
    started, connection, lines = time.monotonic(), None, None
    report = {'schema': 'f1-rba-metadata-audit-1', 'completed': False, 'protocol_sha256': expected_protocol_sha256,
              'archive_sha256': protocol['archive_sha256'], 'probe_sha256': protocol['probe_receipt_sha256'],
              'records': 0, 'structural_errors': 0, 'unsupported_user_ids': 0, 'probe_user_rows': 0,
              'missing_by_field': Counter(), 'backwards_timestamps': Counter(),
              'partitions': {name: distribution() for name in PARTITIONS},
              'all_later_rows_mechanically_parsed_for_metadata': False, 'case_values_displayed_or_exported': 0,
              'full_csv_crc_verified_at_eof': False, 'classifier_fitted': False, 'binary_truth_contract_selected': False,
              'device_template_or_future_time_independence_certified': False, 'final_partition_certified': False,
              'original_six_domain_goal_replaced': False, 'paid_api_calls': 0, 'aws_sdk_calls': 0, 'goal_qualified': False}
    batch, previous = {}, {}
    database = output/'metadata.sqlite3.part'
    def flush():
        if not batch:
            return
        connection.executemany('''INSERT INTO users VALUES(?,?,?,?,?,?,?) ON CONFLICT(reference) DO UPDATE SET
            partition=CASE WHEN users.partition=excluded.partition THEN users.partition ELSE NULL END,
            rows=users.rows+excluded.rows, ato_true=users.ato_true+excluded.ato_true,
            ato_false=users.ato_false+excluded.ato_false, ato_unknown=users.ato_unknown+excluded.ato_unknown,
            probe_tainted=MAX(users.probe_tainted,excluded.probe_tainted)''',
            [(key, value[0], *value[1:]) for key, value in sorted(batch.items())])
        connection.commit()
        batch.clear()
    old_field_limit = csv.field_size_limit()
    try:
        connection = sqlite3.connect(database)
        connection.execute('PRAGMA page_size=4096')
        connection.execute('PRAGMA max_page_count=262144')
        connection.execute('PRAGMA cache_size=-16384')
        connection.execute('PRAGMA synchronous=NORMAL')
        connection.execute('''CREATE TABLE users(reference BLOB PRIMARY KEY, partition TEXT NOT NULL,
            rows INTEGER NOT NULL, ato_true INTEGER NOT NULL, ato_false INTEGER NOT NULL,
            ato_unknown INTEGER NOT NULL, probe_tainted INTEGER NOT NULL) WITHOUT ROWID''')
        csv.field_size_limit(MAX_LINE)
        with archive_path.open('rb') as raw_archive:
            require(fingerprint(raw_archive) == protocol['archive_sha256'], 'rba_metadata_archive_hash')
            bounds = index_bounds(raw_archive)
            raw_archive.seek(0)
            with zipfile.ZipFile(raw_archive) as archive:
                infos = archive.infolist()
                require(len(infos) == bounds['members'], 'rba_metadata_index')
                entries = [entry(info, bounds['index_offset']) for info in infos]
                require(len({v['name'] for v in entries}) == len(entries), 'rba_metadata_duplicate_member')
                selected = [v for v in entries if v['archive_name'] == protocol['csv_member']]
                require(len(selected) == 1 and selected[0]['kind'] == 'regular' and not selected[0]['encrypted']
                        and selected[0]['compression'] in {zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED}
                        and selected[0]['bytes'] == protocol['csv_bytes'] and selected[0]['crc32'] == protocol['csv_crc32'],
                        'rba_metadata_member')
                with archive.open(protocol['csv_member']) as source:
                    lines = AuditLines(source, protocol['csv_bytes'])
                    reader = csv.reader(lines, strict=True)
                    header = next(reader)
                    require(header == protocol['header'], 'rba_metadata_header')
                    columns = {name: i for i, name in enumerate(header)}
                    for values in reader:
                        report['records'] += 1
                        require(report['records'] <= protocol['maximum_rows'], 'rba_metadata_record_bound')
                        if len(values) != len(header):
                            report['structural_errors'] += 1
                            reference, part, labels = None, 'unassigned', [None, None, None]
                        else:
                            for name, position in columns.items():
                                if values[position] == '':
                                    report['missing_by_field'][name] += 1
                            reference = user_reference(values[columns['User ID']])
                            part = partition(reference, probe_users)
                            report['unsupported_user_ids'] += reference is None
                            labels = [boolean(values[columns[name]]) for name in BOOLEANS]
                            report['probe_user_rows'] += reference in probe_users
                            shape, key = time_value(values[columns['Login Timestamp']])
                            target = report['partitions'][part]
                            target['timestamp_shapes'][shape] += 1
                            target['rtt_states'][rtt_state(values[columns['Round-Trip Time [ms]']])] += 1
                            if key is not None:
                                current = target['time_ranges'].setdefault(shape, {'min': key, 'max': key})
                                current['min'], current['max'] = min(current['min'], key), max(current['max'], key)
                                report['backwards_timestamps'][shape] += shape in previous and key < previous[shape]
                                previous[shape] = key
                        target = report['partitions'][part]
                        target['rows'] += 1
                        states = ['unknown' if value is None else 'true' if value else 'false' for value in labels]
                        for name, state in zip(BOOLEANS, states, strict=True):
                            target['labels'][name][state] += 1
                        target['label_cross_table']['|'.join(states)] += 1
                        ato = labels[2]
                        ato_key = 'ato_unknown' if ato is None else 'ato_true' if ato else 'ato_false'
                        target[ato_key] += 1
                        if reference is not None:
                            # Fixed position counters: partition, rows, true,
                            # false, unknown, probe. No raw IDs or cases saved.
                            value = batch.setdefault(reference, [part, 0, 0, 0, 0, int(reference in probe_users)])
                            value[1] += 1
                            value[4 if ato is None else 2 if ato else 3] += 1
                        if report['records'] % protocol['batch_rows'] == 0:
                            require(time.monotonic()-started <= protocol['maximum_seconds'], 'rba_metadata_time_bound')
                            flush()
                        if report['records'] % PROGRESS_ROWS == 0:
                            (output/'progress.json').write_bytes(canonical({'records': report['records'],
                                'uncompressed_bytes': lines.bytes, 'elapsed_seconds': round(time.monotonic()-started, 2)}))
                    require(lines.bytes == protocol['csv_bytes'], 'rba_metadata_csv_size')
                    report['full_csv_crc_verified_at_eof'] = True
            require(fingerprint(raw_archive) == protocol['archive_sha256'], 'rba_metadata_archive_changed')
        flush()
        report['users_by_partition'] = {row[0]: {'users': row[1], 'rows': row[2], 'users_with_ato_true': row[3],
                'probe_users': row[4]} for row in connection.execute('''SELECT partition,COUNT(*),SUM(rows),
                    SUM(ato_true>0),SUM(probe_tainted) FROM users GROUP BY partition''')}
        database_rows = sum(v['rows'] for v in report['users_by_partition'].values())
        require(database_rows+report['partitions']['unassigned']['rows'] == report['records'], 'rba_metadata_row_conservation')
        require(sum(v['rows'] for v in report['partitions'].values()) == report['records'], 'rba_metadata_partition_conservation')
        connection.close()
        connection = None
        database.rename(output/'metadata.sqlite3')
        report['uncompressed_csv_sha256'] = lines.sha.hexdigest()
        report['uncompressed_csv_bytes'], report['physical_lines'] = lines.bytes, lines.lines
        report['all_later_rows_mechanically_parsed_for_metadata'] = True
        report['completed'] = True
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, csv.Error, sqlite3.Error, zipfile.BadZipFile, StopIteration) as error:
        report['failure_type'] = type(error).__name__
    finally:
        csv.field_size_limit(old_field_limit)
        user_reference.cache_clear()
        if connection is not None:
            connection.close()
        report['elapsed_seconds'] = round(time.monotonic()-started, 3)
        (output/'audit.json').write_bytes(canonical(report)+b'\n')
    return report
