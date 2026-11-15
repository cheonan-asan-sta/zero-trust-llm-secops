"""Disk-backed publisher-source audit and byte-exact M7 pilot reproduction, offline."""

import argparse
import hashlib
import json
import sqlite3
import tempfile
from collections import Counter
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from scripts.audit_f1_features import bounds
from scripts.f1_lab.provenance import git_context
from scripts.prepare_m7 import (
    FEATURES,
    LABELS,
    SOURCE,
    SPLITS,
    Event,
    Label,
    Record,
    Session,
    canonical,
    describe,
    evidence_id_for,
    in_time_range,
    jsonl,
    pattern,
    session_id_for,
    sha,
    split_for,
    timestamp,
    verify,
)

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 128*1024**2
MAX_LINE = 128*1024
MAX_SPOOL = 512*1024**2
MAX_EVENTS_PER_SESSION = 1000


def microseconds(value):
    delta = value.astimezone(UTC)-datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days*86400+delta.seconds)*1000000+delta.microseconds


def stream_hash(path):
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        while chunk := stream.read(1024*1024):
            size += len(chunk)
            if size > MAX_BYTES:
                raise ValueError('m7_audit_source_bound')
            digest.update(chunk)
    return size, digest.hexdigest()


def ingest(source, database, contract):
    if (source.is_symlink() or type(contract['bytes']) is not int or not 0 < contract['bytes'] <= MAX_BYTES
            or source.stat().st_size != contract['bytes']):
        raise ValueError('m7_audit_source_size')
    database.executescript('''
        CREATE TABLE sessions (id TEXT PRIMARY KEY, family TEXT NOT NULL, count INTEGER NOT NULL);
        CREATE TABLE events (line INTEGER PRIMARY KEY, sid TEXT NOT NULL, instant INTEGER NOT NULL,
            input TEXT NOT NULL, record TEXT NOT NULL, subjects TEXT NOT NULL, client TEXT NOT NULL,
            raw_sha TEXT NOT NULL UNIQUE);
        CREATE INDEX event_order ON events(sid,instant,line);
        CREATE TABLE patterns (projection TEXT NOT NULL, digest TEXT NOT NULL,
            benign INTEGER NOT NULL, attack INTEGER NOT NULL, anomaly INTEGER NOT NULL,
            PRIMARY KEY(projection,digest));
        CREATE TABLE candidates (split TEXT NOT NULL, label TEXT NOT NULL, sid TEXT PRIMARY KEY,
            input TEXT NOT NULL, truth TEXT NOT NULL, pattern TEXT NOT NULL);
    ''')
    digest, size, line = hashlib.sha256(), 0, 0
    keys = set()
    with source.open('rb') as stream:
        while raw := stream.readline(MAX_LINE+1):
            line += 1
            size += len(raw)
            if len(raw) > MAX_LINE or size > contract['bytes'] or line > contract['source_counts']['rows']:
                raise ValueError('m7_audit_line_or_population_bound')
            digest.update(raw)
            row = json.loads(raw)
            keys.update(row)
            trace = row['trace_id']
            if not isinstance(trace, str) or not trace or len(trace) > 1024:
                raise ValueError('m7_audit_trace')
            family = row['label'], row['category'], row['subcategory']
            if family[0] not in {'benign', 'attack', 'anomaly'}:
                raise ValueError('m7_audit_source_label')
            sid = session_id_for(trace)
            encoded_family = canonical(family).decode()
            original = database.execute('SELECT family,count FROM sessions WHERE id=?', (sid,)).fetchone()
            if original is not None and original[0] != encoded_family:
                raise ValueError('m7_conflicting_session_labels')
            if original is not None and original[1] >= MAX_EVENTS_PER_SESSION:
                raise ValueError('m7_audit_session_bound')
            database.execute('INSERT INTO sessions VALUES (?,?,1) ON CONFLICT(id) DO UPDATE SET count=count+1',
                             (sid, encoded_family))
            event = Event(evidence_id=evidence_id_for(sid, line), **{field: row[field] for field in FEATURES})
            record = Record(line=line, evidence_id=event.evidence_id, sha256=sha(raw.rstrip(b'\r\n')),
                            timestamp=row['timestamp'])
            subjects = sorted({sha(canonical(['subject', row[key]])) for key in ('user_id', 'action_by') if row[key] is not None})
            client = sha(canonical(['client', row['client_ip']]))
            try:
                database.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?,?)', (line, sid,
                    microseconds(timestamp(record.timestamp)), canonical(event.model_dump(mode='json')).decode(),
                    canonical(record.model_dump()).decode(), canonical(subjects).decode(), client, record.sha256))
            except sqlite3.IntegrityError:
                raise ValueError('m7_duplicate_raw_record') from None
            if line % 2000 == 0:
                pages, page_size = database.execute('PRAGMA page_count').fetchone()[0], database.execute('PRAGMA page_size').fetchone()[0]
                if pages*page_size > MAX_SPOOL:
                    raise ValueError('m7_audit_spool_bound')
    if size != contract['bytes'] or digest.hexdigest() != contract['sha256']:
        raise ValueError('m7_audit_source_hash')
    counts = Counter()
    for family, count in database.execute('SELECT family,count(*) FROM sessions GROUP BY family'):
        counts[json.loads(family)[0]] += count
    if {'rows': line, 'sessions': dict(counts)} != contract['source_counts']:
        raise ValueError('m7_audit_source_population')
    return {'events': line, 'session_labels': dict(counts), 'source_top_level_fields': sorted(keys),
            'consumed_source_sha256': digest.hexdigest()}


def analyze_sessions(database, contract):
    cutoff = timestamp(contract['pilot']['evaluation_start'])
    family_counts = Counter()
    for sid, encoded_family in database.execute('SELECT id,family FROM sessions ORDER BY id'):
        family = tuple(json.loads(encoded_family))
        family_counts[family] += 1
        rows = database.execute('SELECT input,record,subjects,client FROM events WHERE sid=? ORDER BY instant,line', (sid,)).fetchall()
        events = [Event.model_validate_json(row[0]) for row in rows]
        records = [Record.model_validate_json(row[1]) for row in rows]
        shape = pattern(events)
        projections = {'module_method_status_level_sequence': shape,
            'same_plus_duration_sequence': [(*values, event.duration_ms) for values, event in zip(shape, events)]}
        for name, values in projections.items():
            counts = {label: int(family[0] == label) for label in ('benign', 'attack', 'anomaly')}
            database.execute('INSERT INTO patterns VALUES (?,?,?,?,?) ON CONFLICT(projection,digest) '
                'DO UPDATE SET benign=benign+excluded.benign,attack=attack+excluded.attack,anomaly=anomaly+excluded.anomaly',
                (name, sha(canonical(values)), counts['benign'], counts['attack'], counts['anomaly']))
        if family[0] not in LABELS:
            continue
        split = split_for(family, contract['pilot'])
        order = [(timestamp(record.timestamp), record.line) for record in records]
        if not in_time_range(split, order, cutoff):
            continue
        data = Session(session_id=sid, events=events)
        truth = Label(session_id=sid, split=split, expected_label=LABELS[family[0]], source_label=family[0],
            category=family[1], subcategory=family[2], records=records,
            subjects=sorted({subject for row in rows for subject in json.loads(row[2])}),
            clients=sorted({row[3] for row in rows}))
        database.execute('INSERT INTO candidates VALUES (?,?,?,?,?,?)', (split, family[0], sid,
            data.model_dump_json(), truth.model_dump_json(), sha(canonical(shape))))
    result = {}
    for name, in database.execute('SELECT DISTINCT projection FROM patterns ORDER BY projection'):
        groups = [{'positive': attack, 'negative': benign} for benign, attack in database.execute(
            'SELECT benign,attack FROM patterns WHERE projection=? AND benign+attack>0', (name,))]
        total_patterns, = database.execute('SELECT count(*) FROM patterns WHERE projection=?', (name,)).fetchone()
        result[name] = {'three_class_patterns': total_patterns, 'binary_authored_oracle_bound': bounds(groups),
            'anomaly_excluded_from_binary_oracle': contract['source_counts']['sessions'].get('anomaly', 0),
            'not_trained_or_measured_detector_performance': True}
    return {'projections': result, 'families': [{'source_label': f[0], 'category': f[1], 'subcategory': f[2],
                'sessions': count} for f, count in sorted(family_counts.items(), key=lambda pair: canonical(pair[0]))]}


def select(database, contract):
    patterns, subjects, clients = set(), set(), set()
    inputs, labels, source_context = {}, [], []
    limit = contract['pilot']['sessions_per_label_per_split']
    for split in SPLITS:
        selected = []
        for source_label in LABELS:
            group = []
            for body, truth_body, shape in database.execute(
                    'SELECT input,truth,pattern FROM candidates WHERE split=? AND label=? ORDER BY sid', (split, source_label)):
                data, truth = Session.model_validate_json(body), Label.model_validate_json(truth_body)
                if shape in patterns or split == 'evaluation' and (subjects.intersection(truth.subjects) or clients.intersection(truth.clients)):
                    continue
                patterns.add(shape)
                group.append((data, truth))
                benign, attack, anomaly = database.execute('SELECT benign,attack,anomaly FROM patterns '
                    'WHERE projection=? AND digest=?', ('module_method_status_level_sequence', shape)).fetchone()
                source_context.append({'session_id': data.session_id, 'split': split,
                    'source_label': source_label, 'pattern_sha256': shape,
                    'full_source_same_pattern': {'benign': benign, 'attack': attack, 'anomaly': anomaly},
                    'binary_label_conflict': benign > 0 and attack > 0})
                if len(group) == limit:
                    break
            if len(group) != limit:
                raise ValueError('m7_insufficient_disjoint_sessions')
            selected.extend(group)
            if split == 'development':
                subjects.update(subject for _data, truth in group for subject in truth.subjects)
                clients.update(client for _data, truth in group for client in truth.clients)
        selected.sort(key=lambda item: item[0].session_id)
        inputs[split+'.jsonl'] = jsonl(data for data, _truth in selected)
        labels.extend(truth for _data, truth in selected)
    inputs['labels.jsonl'] = jsonl(labels)
    manifest = describe(inputs, contract)
    inputs['manifest.json'] = (json.dumps(manifest, ensure_ascii=False, indent=2)+'\n').encode()
    return inputs, manifest, {'rows': source_context,
        'selected_sessions_with_binary_source_pattern_conflict': sum(r['binary_label_conflict'] for r in source_context),
        'scope': 'Declared sequence projection excludes duration, IDs, payload and event_type; not a full-feature impossibility claim.'}


def audit(source, destination, contract, *, reference=None):
    source, destination = Path(source), Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('m7_audit_fresh_directory_required')
    source_paths = [Path(__file__), ROOT/'scripts/prepare_m7.py', ROOT/'scripts/audit_f1_features.py',
                    ROOT/'scripts/f1_lab/provenance.py']
    captured = {p.relative_to(ROOT).as_posix(): sha(p.read_bytes().replace(b'\r\n', b'\n')) for p in source_paths}
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix='.m7-audit-') as temporary:
        stage, spool = Path(temporary)/'result', Path(temporary)/'spool.db'
        stage.mkdir()
        with closing(sqlite3.connect(spool)) as database:
            # Disposable spool only; accepted evidence is the atomic final output,
            # not this temporary database. Never reuse an application database.
            database.execute('PRAGMA journal_mode=OFF')
            database.execute('PRAGMA synchronous=OFF')
            database.execute('PRAGMA cache_size=-2048')
            population = ingest(source, database, contract)
            analysis = analyze_sessions(database, contract)
            files, manifest, pilot_source_context = select(database, contract)
            spool_bytes = database.execute('PRAGMA page_count').fetchone()[0]*database.execute('PRAGMA page_size').fetchone()[0]
        if spool_bytes > MAX_SPOOL or stream_hash(source) != (contract['bytes'], contract['sha256']):
            raise ValueError('m7_audit_spool_or_source_changed')
        matched = None
        if reference is not None:
            verify(Path(reference), contract)
            matched = all((Path(reference)/name).read_bytes() == data for name, data in files.items())
            if not matched:
                raise ValueError('m7_audit_reference_bytes_differ')
        if captured != {p.relative_to(ROOT).as_posix(): sha(p.read_bytes().replace(b'\r\n', b'\n')) for p in source_paths}:
            raise ValueError('m7_audit_source_code_changed')
        pilot = stage/'pilot'
        pilot.mkdir()
        for name, data in files.items():
            (pilot/name).write_bytes(data)
        result = {'schema': 'm7-streamed-readiness-1', **git_context(ROOT, captured),
            'source_files_lf_sha256': captured, 'source_contract_sha256': sha(canonical(contract)),
            'source_kind': contract['source_kind'], 'source_url': contract['source_url'],
            'license': contract['license'], 'license_url': contract['license_url'],
            'population': population, 'analysis': analysis, 'pilot': manifest,
            'pilot_source_pattern_context': pilot_source_context,
            'reference_pilot_byte_identical': matched,
            'peak_spool_logical_bytes': spool_bytes, 'spool_limit_bytes': MAX_SPOOL,
            'memory_strategy': '2MiB SQLite cache; bounded one-session model materialization; no raw corpus in memory',
            'memory_peak_measured': False, 'detector_inference_runs': 0,
            'compatible_with_full_signed_security_events': False,
            'missing_full_zero_trust_contracts': ['trusted event signatures and issuer scopes',
                'IdP role/active/MFA assertions', 'EDR device management/posture',
                'resource-owner permissions/classification', 'download byte-delta and approved job evidence'],
            'independent_review': 'pending', 'new_independent_evaluation': False, 'goal_qualified': False,
            'effects': {'network_calls': 0, 'paid_api_calls': 0, 'cloud_calls': 0, 'baseline_writes': 0}}
        (stage/'audit.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
        (stage/'NOTICE.md').write_text('Derived counts and pilot from KREONET / KAFE Research, '
            'IAM Anomaly Detection Dataset 2026. Copyright (c) 2026 KAFE Research. '
            'CC BY 4.0: '+contract['license_url']+'\nSource: '+contract['source_url']+'\n'
            'Changes: disk-backed audit, filtered feature projections and reproduced pilot. No publisher endorsement.\n', encoding='utf8')
        stage.rename(destination)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--reference-pilot', type=Path, default=SOURCE.parent/'pilot')
    args = parser.parse_args()
    result = audit(args.source, args.directory, json.loads(SOURCE.read_bytes()), reference=args.reference_pilot)
    print(json.dumps({key: result[key] for key in ('population', 'reference_pilot_byte_identical',
        'peak_spool_logical_bytes', 'goal_qualified')}))


if __name__ == '__main__':
    main()
