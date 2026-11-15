"""Evaluation-only exact-line truth index for publisher-trimmed AIT log pairs.

Labels never enter the sensor adapter or model feature view. Unmatched or
contradictory content remains unknown; last-write-wins label guessing is banned.
"""

import hashlib
import json
import re
import sqlite3
from pathlib import Path, PurePosixPath

from scripts.f1_lab.native_jsonl import MAX_FILE, MAX_ROW, MAX_ROWS, require, scan, text


def anchor(value):
    require(isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value), 'truth_anchor')
    return value


def annotations(path, expected_sha256):
    lines = {}
    def collect(row):
        require(row.error is None and row.value is not None, 'annotation_parse')
        number, names = row.value.get('line'), row.value.get('labels')
        require(type(number) is int and 1 <= number <= MAX_ROWS and number not in lines, 'annotation_line')
        require(isinstance(names, list) and 1 <= len(names) <= 64
                and all(isinstance(name, str) and 1 <= len(name) <= 128 for name in names)
                and len(set(names)) == len(names), 'annotation_labels')
        lines[number] = tuple(names)
    report = scan(path, expected_sha256, collect)
    return lines, report


def pair_members(raw_member, label_member):
    # The publisher labels directory must mirror the complete gather suffix.
    # A basename-only match can attach another host's labels and is forbidden.
    for name in (raw_member, label_member):
        require(isinstance(name, str) and '\\' not in name and ':' not in name
                and not any(ord(char) < 32 for char in name), 'pair_member')
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts and path.as_posix() == name, 'pair_member')
    raw_parts = PurePosixPath(raw_member).parts
    require(raw_parts.count('gather') == 1, 'exact_pair_member')
    position = raw_parts.index('gather')
    require(len(raw_parts) > position+3 and raw_parts[position+2] == 'logs', 'exact_pair_member')
    expected = (*raw_parts[:position], 'labels', *raw_parts[position+1:])
    require(PurePosixPath(label_member).parts == expected, 'exact_pair_member')


class LineTruthIndex:
    def __init__(self, path):
        path = Path(path)
        require(not path.exists() and not path.is_symlink(), 'fresh_truth_index')
        self.connection = sqlite3.connect(path)
        self.connection.executescript('''
            CREATE TABLE pairs (id TEXT PRIMARY KEY, provenance TEXT NOT NULL, rows INTEGER NOT NULL);
            CREATE TABLE evidence (pair_id TEXT NOT NULL, entity TEXT NOT NULL, location TEXT NOT NULL,
                content_sha TEXT NOT NULL, positives INTEGER NOT NULL, negatives INTEGER NOT NULL,
                PRIMARY KEY (pair_id, entity, location, content_sha));
            CREATE INDEX content_lookup ON evidence(entity, location, content_sha);
        ''')

    def close(self):
        self.connection.close()

    def add_pair(self, raw_path, raw_sha256, label_path, label_sha256, *, entity, location,
                 raw_member, label_member, archive_sha256, simulation_start, simulation_end,
                 publisher_trimmed_pair):
        """Index a verified publisher pair; no normal inference without coverage.

        `publisher_trimmed_pair=True` is an explicit caller assertion based on
        the publisher's paired-file contract, not a claim read from log content.
        The returned provenance retains that assumption for later review.
        """
        require(publisher_trimmed_pair is True, 'paired_coverage_required')
        pair_members(raw_member, label_member)
        for value in (raw_sha256, label_sha256, archive_sha256):
            anchor(value)
        require(type(simulation_start) is int and type(simulation_end) is int
                and 0 <= simulation_start < simulation_end < 4102444800, 'simulation_bounds')
        entity, location = text(entity, maximum=128), text(location, maximum=4096)
        raw_path = Path(raw_path)
        require(raw_path.is_file() and not raw_path.is_symlink() and raw_path.stat().st_size <= MAX_FILE, 'raw_pair_file')
        labels, label_report = annotations(label_path, label_sha256)
        provenance = {'archive_sha256': archive_sha256, 'raw_sha256': raw_sha256,
                      'label_sha256': label_sha256, 'raw_member': raw_member, 'label_member': label_member,
                      'simulation_start': simulation_start, 'simulation_end': simulation_end,
                      'coverage': 'publisher says paired labeled logs are trimmed to simulation bounds',
                      'timestamp_audit_performed': False, 'entity': entity, 'location': location}
        pair_id = hashlib.sha256(json.dumps(provenance, sort_keys=True).encode()).hexdigest()
        require(self.connection.execute('SELECT 1 FROM pairs WHERE id=?', (pair_id,)).fetchone() is None,
                'duplicate_pair')
        sha, rows, total = hashlib.sha256(), 0, 0
        with self.connection:
            with raw_path.open('rb') as source:
                while body := source.readline(MAX_ROW+1):
                    rows += 1
                    total += len(body)
                    require(len(body) <= MAX_ROW and rows <= MAX_ROWS and total <= MAX_FILE, 'raw_pair_bound')
                    sha.update(body)
                    content = hashlib.sha256(body.rstrip(b'\r\n')).hexdigest()
                    positive = int(rows in labels)
                    self.connection.execute('''INSERT INTO evidence VALUES (?,?,?,?,?,?)
                        ON CONFLICT (pair_id,entity,location,content_sha) DO UPDATE SET
                        positives=positives+excluded.positives, negatives=negatives+excluded.negatives''',
                        (pair_id, entity, location, content, positive, 1-positive))
            require(sha.hexdigest() == raw_sha256, 'raw_pair_hash')
            require(not labels or max(labels) <= rows, 'annotation_outside_raw')
            self.connection.execute('INSERT INTO pairs VALUES (?,?,?)',
                                    (pair_id, json.dumps(provenance, sort_keys=True), rows))
        return {'schema': 'f1-native-pair-index-1', 'pair_id': pair_id, 'provenance': provenance,
                'raw_rows': rows, 'malicious_rows': len(labels), 'normal_rows': rows-len(labels),
                'annotation_scan': label_report, 'goal_qualified': False}

    def lookup(self, entity, location, content_sha256):
        anchor(content_sha256)
        positive, negative, pairs = self.connection.execute('''
            SELECT COALESCE(SUM(positives),0),COALESCE(SUM(negatives),0),COUNT(*)
            FROM evidence WHERE entity=? AND location=? AND content_sha=?''',
            (entity, location, content_sha256)).fetchone()
        truth = True if positive and not negative else False if negative and not positive else None
        return {'truth': truth, 'reason': 'conflicting_exact_lines' if positive and negative
                else 'exact_publisher_pair' if pairs else 'no_exact_publisher_pair',
                'matching_positive_rows': positive, 'matching_normal_rows': negative, 'matching_pairs': pairs}
