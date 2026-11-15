"""Prepare all pinned paired raw rows using bounded, disk-ordered HTTP history.

No base input cache is materialized. Its exact bytes are hashed during extraction.
Truth and references remain separate from the feature spool and model inputs.
An interrupted attempt is never reused as complete; retry in a fresh directory.
"""

import argparse
import hashlib
import json
import shutil
import sqlite3
from collections import Counter
from contextlib import ExitStack
from dataclasses import asdict, dataclass
from pathlib import Path

from scripts.f1_lab.line_truth import anchor, annotations, pair_members
from scripts.f1_lab.native_jsonl import MAX_FILE, MAX_ROW, MAX_ROWS, decode, require
from scripts.f1_lab.raw_context import PROFILE, extra_observations
from scripts.f1_lab.raw_observations import raw_features, raw_time
from scripts.f1_lab.raw_semantics import PROFILE as SEMANTIC_PROFILE
from scripts.f1_lab.raw_semantics import ordered_auth_context, semantic_observations
from scripts.f1_lab.streaming_context import IncrementalHTTPWindow, http_fields


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


@dataclass(frozen=True)
class StreamLimits:
    database_bytes: int = 4*1024**3
    output_bytes: int = 8*1024**3
    min_free_bytes: int = 5*1024**3
    active_http_events: int = 500_000

    def validate(self):
        require(type(self.database_bytes) is int and 65536 <= self.database_bytes <= 16*1024**3
                and type(self.output_bytes) is int and 1 <= self.output_bytes <= 32*1024**3
                and type(self.min_free_bytes) is int and self.min_free_bytes >= 0
                and type(self.active_http_events) is int and 1 <= self.active_http_events <= 500_000,
                'stream_limits')


class OutputBudget:
    def __init__(self, maximum):
        self.maximum, self.used = maximum, 0

    def write(self, stream, body):
        require(self.used+len(body) <= self.maximum, 'stream_output_bound')
        stream.write(body)
        self.used += len(body)


def connect(path, maximum):
    require(not path.exists() and not path.is_symlink(), 'fresh_stream_database')
    connection = sqlite3.connect(path)
    connection.execute('PRAGMA page_size=4096')
    connection.execute(f'PRAGMA max_page_count={maximum//4096}')
    connection.execute('PRAGMA cache_size=-16384')
    connection.execute('PRAGMA mmap_size=0')
    connection.execute('PRAGMA temp_store=FILE')
    connection.execute('PRAGMA journal_mode=DELETE')
    connection.executescript('''
        CREATE TABLE observations (ordinal INTEGER PRIMARY KEY, features BLOB NOT NULL, error TEXT);
        CREATE TABLE http (ordinal INTEGER PRIMARY KEY, moment REAL, client TEXT, target BLOB, error INTEGER);
        CREATE INDEX http_time ON http((moment IS NULL), moment, ordinal);
        CREATE TABLE windows (ordinal INTEGER PRIMARY KEY, features BLOB NOT NULL);
    ''')
    return connection


def prepare(directory, expected_manifest_sha256, output, *, profile=SEMANTIC_PROFILE, limits=None, include_truth=True):
    limits = StreamLimits() if limits is None else limits
    limits.validate()
    require(type(include_truth) is bool, 'stream_truth_mode')
    require(profile in {PROFILE, SEMANTIC_PROFILE}, 'stream_feature_profile')
    directory, output = Path(directory), Path(output)
    anchor(expected_manifest_sha256)
    manifest_path = directory/'audit.json'
    require(manifest_path.is_file() and not manifest_path.is_symlink() and manifest_path.stat().st_size <= 1024**2,
            'stream_manifest_file')
    body = manifest_path.read_bytes()
    require(hashlib.sha256(body).hexdigest() == expected_manifest_sha256, 'stream_manifest_hash')
    manifest = decode(body)
    require(manifest.get('completed') is True and 1 <= len(manifest['pairs']) <= 64, 'completed_pair_manifest')
    require(manifest['timestamp_basis'] == 'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
            'raw_timezone_intake_contract')
    require(all(type(pair['raw_rows']) is int and 1 <= pair['raw_rows'] <= MAX_ROWS for pair in manifest['pairs'])
            and sum(pair['raw_rows'] for pair in manifest['pairs']) <= MAX_ROWS, 'stream_population_bound')
    require(not output.exists() and not output.is_symlink(), 'fresh_stream_output')
    output.mkdir(parents=True, mode=0o700)
    report = {'schema': 'f1-native-raw-input-1', 'completed': False, 'source_manifest_sha256': expected_manifest_sha256,
              'row_policy': 'every paired raw row retained', 'scope': manifest['scope'], 'feature_profile': profile,
              'inputs_contain_truth': False, 'labels_changed': False, 'historical_replay_only': True,
              'paid_api_calls': 0, 'aws_sdk_calls': 0, 'goal_qualified': False, 'pairs': [], 'files': {},
              'streaming': {'schema': 'bounded-native-context-1', 'limits': asdict(limits), 'sources': [],
                            'recovery': 'retain failed attempt; rerun with the same anchors in a fresh directory',
                            'observations_extracted_once_per_source': True, 'base_input_materialized': False},
              'context': 'HTTP per physical source and client; event-time order with original ordinal ties; current and past only'}
    if profile == SEMANTIC_PROFILE:
        report['semantic_context'] = 'bounded HTTP semantic shapes; explicit local log account 60-second history within one source; equal timestamps follow original source ordinal; no authority claims'
    if not include_truth:
        report.update(schema='f1-native-raw-observations-1', labels_loaded=False,
                      label_population_known=False, truth_sidecar_written=False)
    base_sha, base_bytes, budget = hashlib.sha256(), 0, OutputBudget(limits.output_bytes)
    names = ('inputs.jsonl', 'truth.jsonl', 'references.jsonl') if include_truth else ('inputs.jsonl', 'references.jsonl')
    hashes = {name: hashlib.sha256() for name in names}
    sizes = Counter()

    def headroom():
        require(shutil.disk_usage(output).free >= limits.min_free_bytes, 'stream_disk_headroom')

    def write(name, value, streams):
        data = canonical(value)+b'\n'
        budget.write(streams[name], data)
        hashes[name].update(data)
        sizes[name] += len(data)

    connection = None
    try:
        # Covers output, DB and its rollback journal; no quota depends on compression.
        require(shutil.disk_usage(output).free >= limits.min_free_bytes+limits.output_bytes+2*limits.database_bytes,
                'stream_admission_headroom')
        with ExitStack() as stack:
            streams = {name: stack.enter_context((output/(name+'.part')).open('xb')) for name in names}
            for index, pair in enumerate(manifest['pairs']):
                provenance = pair['provenance']
                pair_members(provenance['raw_member'], provenance['label_member'])
                raw_path, label_path = directory/f'pair-{index}-raw.source', directory/f'pair-{index}-labels.source'
                require(raw_path.is_file() and not raw_path.is_symlink() and raw_path.stat().st_size <= MAX_FILE,
                        'raw_pair_file')
                start, end = provenance['simulation_start'], provenance['simulation_end']
                require(type(start) is int and type(end) is int and 0 <= start < end, 'raw_simulation_bounds')
                labels = annotations(label_path, provenance['label_sha256'])[0] if include_truth else None
                database = output/f'spool-{index}.sqlite3'
                connection = connect(database, limits.database_bytes)
                sha, count, byte_count, requests = hashlib.sha256(), 0, 0, 0
                time_errors = feature_errors = outside = backward = 0
                minimum = maximum = previous = None
                auth_records, auth_bytes = [], 0
                feature_counts = Counter()
                with raw_path.open('rb') as source:
                    while raw := source.readline(MAX_ROW+1):
                        count += 1
                        byte_count += len(raw)
                        require(count <= pair['raw_rows'] and byte_count <= MAX_FILE and len(raw) <= MAX_ROW,
                                'raw_pair_bound')
                        sha.update(raw)
                        case = hashlib.sha256((provenance['raw_sha256']+':'+str(count)).encode()).hexdigest()
                        features = moment = observation_error = time_error = None
                        line = raw.decode('utf-8', errors='replace')
                        try:
                            line = raw.decode('utf-8')
                            features = raw_features(line)
                            feature_counts.update(name for name, value in features.items() if value is True)
                            try:
                                moment = raw_time(line, start, end, source_timezone='UTC')
                            except (ValueError, RecursionError):
                                time_error = 'unparsed_historical_time'
                        except (UnicodeError, ValueError, RecursionError):
                            observation_error = 'unparsed_raw_observation'
                        feature_errors += observation_error is not None
                        time_errors += time_error is not None or moment is None
                        if moment is not None:
                            outside += not start <= moment <= end
                            backward += previous is not None and moment < previous
                            minimum = moment if minimum is None else min(minimum, moment)
                            maximum = moment if maximum is None else max(maximum, moment)
                            previous = moment
                        base = canonical({'case_id': case, 'features': features, 'observation_error': observation_error})+b'\n'
                        base_sha.update(base)
                        base_bytes += len(base)
                        fields = http_fields(line)
                        context_time = moment
                        if moment is None and (fields is not None or provenance['raw_member'].endswith('/auth.log')):
                            try:
                                context_time = raw_time(line, start, end, source_timezone='UTC')
                            except (ValueError, RecursionError):
                                context_time = None
                        if fields is not None:
                            client, target, error = fields
                            connection.execute('INSERT INTO http VALUES (?,?,?,?,?)',
                                               (count, context_time, client, target, int(error)))
                            requests += 1
                        if profile == SEMANTIC_PROFILE and provenance['raw_member'].endswith('/auth.log'):
                            auth_bytes += len(raw)
                            require(len(auth_records) < 100000 and auth_bytes <= 64*1024**2, 'context_auth_bound')
                            auth_records.append((count, context_time, line))
                        if features is not None:
                            features = {**features, **extra_observations(line)}
                            if profile == SEMANTIC_PROFILE:
                                features.update(semantic_observations(line))
                        connection.execute('INSERT INTO observations VALUES (?,?,?)',
                                           (count, canonical(features), observation_error))
                        if include_truth:
                            write('truth.jsonl', {'case_id': case, 'malicious': count in labels, 'attack_labels': labels.get(count, ())}, streams)
                        write('references.jsonl', {'case_id': case, 'pair_id': pair['pair_id'], 'source_line': count,
                                                  'source_row_sha256': hashlib.sha256(raw).hexdigest(),
                                                  'event_time': moment, 'time_error': time_error}, streams)
                        if count % 4096 == 0:
                            connection.commit()
                            headroom()
                        if count % 50000 == 0:
                            print(json.dumps({'stage': 'extract_source', 'source_index': index, 'rows': count}), flush=True)
                require(sha.hexdigest() == provenance['raw_sha256'] and count == pair['raw_rows'], 'raw_pair_hash_or_rows')
                require(not labels or max(labels) <= count, 'annotation_outside_raw')
                connection.commit()
                window = IncrementalHTTPWindow(max_active=limits.active_http_events)
                query = 'SELECT ordinal, moment, client, target, error FROM http ORDER BY (moment IS NULL), moment, ordinal'
                plan = [row[-1] for row in connection.execute('EXPLAIN QUERY PLAN '+query)]
                require(any('http_time' in step for step in plan) and not any('TEMP B-TREE' in step for step in plan),
                        'stream_http_indexed_order')
                for ordinal, moment, client, target, error in connection.execute(query):
                    observed = window.observe_fields(client, target, bool(error), moment)
                    connection.execute('INSERT INTO windows VALUES (?,?)', (ordinal, canonical(observed)))
                    if ordinal % 4096 == 0:
                        headroom()
                connection.commit()
                auth_windows = ordered_auth_context(auth_records) if profile == SEMANTIC_PROFILE else {}
                histogram, emitted = Counter(), 0
                for ordinal, value, error, history in connection.execute('''
                    SELECT o.ordinal, o.features, o.error, w.features FROM observations o
                    LEFT JOIN windows w ON w.ordinal=o.ordinal ORDER BY o.ordinal'''):
                    features = decode(value)
                    if features is not None:
                        if history is not None:
                            features.update(decode(history))
                        features.update(auth_windows.get(ordinal, {}))
                        histogram.update(name for name, value in features.items() if value is True)
                    case = hashlib.sha256((provenance['raw_sha256']+':'+str(ordinal)).encode()).hexdigest()
                    write('inputs.jsonl', {'case_id': case, 'features': features, 'observation_error': error}, streams)
                    emitted += 1
                    if emitted % 4096 == 0:
                        headroom()
                require(emitted == count, 'stream_emitted_population')
                report['pairs'].append({'raw_member': provenance['raw_member'], 'raw_sha256': sha.hexdigest(),
                                        'rows': count, 'malicious': len(labels) if include_truth else None,
                                        'normal': count-len(labels) if include_truth else None,
                                        'feature_errors': feature_errors, 'time_errors': time_errors,
                                        'outside_simulation': outside, 'backward_time_steps': backward,
                                        'minimum_event_time': minimum, 'maximum_event_time': maximum,
                                        'positive_feature_counts': dict(feature_counts)})
                report['streaming']['sources'].append({'raw_member': provenance['raw_member'], 'rows': count,
                    'requests': requests, 'active_http_peak': window.peak_events, 'http_group_peak': window.peak_groups,
                    'http_processed': window.events, 'auth_rows': len(auth_records), 'database_bytes': database.stat().st_size,
                    'ordering_plan': plan, 'positive_feature_counts': dict(histogram)})
                connection.close()
                connection = None
                # Only the exact temporary DB created in this fresh output directory.
                require(database.parent == output and database.is_file() and not database.is_symlink(), 'stream_owned_spool')
                database.unlink()
                print(json.dumps({'stage': 'prepared_source', 'source_index': index, 'rows': count, 'http_requests': requests}), flush=True)
        for name, sha in hashes.items():
            partial = output/(name+'.part')
            partial.rename(output/name)
            report['files'][name] = {'sha256': sha.hexdigest(), 'bytes': sizes[name]}
        report['streaming']['base_inputs'] = {'sha256': base_sha.hexdigest(), 'bytes': base_bytes}
        report['streaming']['output_bytes'] = budget.used
        report['completed'] = True
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        if connection is not None:
            connection.close()
        (output/'preparation.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pairs-directory', required=True, type=Path)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--feature-profile', choices=(PROFILE, SEMANTIC_PROFILE), default=SEMANTIC_PROFILE)
    parser.add_argument('--observations-only', action='store_true', help='Never open labels or emit a truth sidecar')
    args = parser.parse_args()
    report = prepare(args.pairs_directory, args.expected_manifest_sha256, args.output,
                     profile=args.feature_profile, include_truth=not args.observations_only)
    print(json.dumps({'completed': report['completed'], 'files': report['files'], 'rows': sum(p['rows'] for p in report['pairs']),
                      'goal_qualified': report['goal_qualified']}))


if __name__ == '__main__':
    main()
