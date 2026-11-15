"""Offline full-corpus split feasibility audit; no fitting, inference or selection."""

import argparse
import json
import sqlite3
import tempfile
from collections import Counter
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from scripts.audit_m7_source import MAX_SPOOL, ingest, microseconds, stream_hash
from scripts.f1_lab.provenance import git_context
from scripts.prepare_m7 import SOURCE, Event, canonical, pattern, sha, timestamp

ROOT = Path(__file__).resolve().parents[1]
PROFILES = {'semantic_family': ('family',), 'known_subject': ('subjects',), 'known_client': ('clients',),
    'family_subject': ('family', 'subjects'),
    'family_subject_client': ('family', 'subjects', 'clients'),
    'family_subject_client_sequence': ('family', 'subjects', 'clients', 'sequence')}
NULL_CLIENT = sha(canonical(['client', None]))
MAX_SESSIONS = 30000


@dataclass(frozen=True)
class Summary:
    ident: str
    label: str
    family: str
    subjects: tuple[str, ...]
    clients: tuple[str, ...]
    sequence: str
    first: int
    last: int
    events: int
    missing_subject_events: int
    missing_client_events: int


def summaries(database):
    result = []
    for sid, encoded_family in database.execute('SELECT id,family FROM sessions ORDER BY id'):
        if len(result) >= MAX_SESSIONS:
            raise ValueError('m7_split_session_bound')
        label, category, subcategory = json.loads(encoded_family)
        rows = database.execute('SELECT instant,input,subjects,client FROM events WHERE sid=? ORDER BY instant,line', (sid,)).fetchall()
        subjects = [json.loads(row[2]) for row in rows]
        result.append(Summary(sid, label, sha(canonical([category, subcategory])),
            tuple(sorted({value for values in subjects for value in values})),
            tuple(sorted({row[3] for row in rows if row[3] != NULL_CLIENT})),
            sha(canonical(pattern([Event.model_validate_json(row[1]) for row in rows]))),
            rows[0][0], rows[-1][0], len(rows), sum(not values for values in subjects),
            sum(row[3] == NULL_CLIENT for row in rows)))
    return result


def tokens(row, fields):
    for field in fields:
        value = getattr(row, field)
        for item in value if isinstance(value, tuple) else (value,):
            yield field, item


def components(rows, fields, *, folds=3):
    parent, sizes = list(range(len(rows))), [1]*len(rows)
    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index
    def union(left, right):
        left, right = find(left), find(right)
        if left == right:
            return
        if sizes[left] < sizes[right]:
            left, right = right, left
        parent[right], sizes[left] = left, sizes[left]+sizes[right]
    seen = {}
    for index, row in enumerate(rows):
        for key in tokens(row, fields):
            if key in seen:
                union(index, seen[key])
            else:
                seen[key] = index
    groups = {}
    for index, row in enumerate(rows):
        groups.setdefault(find(index), Counter())[row.label] += 1
    labels = sorted({row.label for row in rows})
    label_components = {label: sum(counts[label] > 0 for counts in groups.values()) for label in labels}
    ranked = sorted(groups.values(), key=lambda c: (-sum(c.values()), tuple(c[label] for label in labels)))
    return {'components': len(groups), 'largest_component_sessions': max((sum(c.values()) for c in ranked), default=0),
        'largest_component_fraction': max((sum(c.values()) for c in ranked), default=0)/len(rows) if rows else None,
        'components_containing_each_label': label_components,
        'largest_five_component_label_counts': [dict(sorted(c.items())) for c in ranked[:5]],
        'requested_folds': folds, 'necessary_nonempty_label_support_conditions_met': bool(rows) and len(groups) >= folds
            and all(count >= folds for count in label_components.values()),
        'balanced_split_constructed': False, 'feasibility_proven': False,
        'interpretation': 'Necessary conditions for keeping every declared group intact in three nonempty folds with every present label; not sufficient balance, independence or a claim about selected subsets.'}


def time_overlap(rows, cutoff):
    before = [row for row in rows if row.last < cutoff]
    after = [row for row in rows if row.first >= cutoff]
    spanning = [row for row in rows if row.first < cutoff <= row.last]
    result = {'before_sessions': len(before), 'after_sessions': len(after), 'spanning_sessions': len(spanning),
        'spanning_sessions_kept_separate': True, 'populations_modified': False, 'overlap': {}}
    for field in ('family', 'subjects', 'clients', 'sequence'):
        left = {key for row in before for key in tokens(row, (field,))}
        right = {key for row in after for key in tokens(row, (field,))}
        overlap = left & right
        result['overlap'][field] = {'shared_keys': len(overlap),
            'before_sessions_touching_shared_keys': sum(any(key in overlap for key in tokens(row, (field,))) for row in before),
            'after_sessions_touching_shared_keys': sum(any(key in overlap for key in tokens(row, (field,))) for row in after)}
    return result


def analyze(rows, cutoff):
    if len(rows) > MAX_SESSIONS or not rows or len({row.ident for row in rows}) != len(rows):
        raise ValueError('m7_split_population')
    if any(row.label not in {'benign', 'attack', 'anomaly'} or row.first > row.last for row in rows):
        raise ValueError('m7_split_summary_contract')
    populations = {'all_publisher_classes': rows, 'binary_benign_attack': [r for r in rows if r.label != 'anomaly']}
    result = {}
    for name, selected in populations.items():
        result[name] = {'sessions': len(selected), 'source_label_counts': dict(sorted(Counter(r.label for r in selected).items())),
            'excluded_anomaly_sessions': len(rows)-len(selected),
            'known_identity_coverage': {'sessions_without_known_subject': sum(not r.subjects for r in selected),
                'sessions_without_known_client': sum(not r.clients for r in selected),
                'events_without_known_subject': sum(r.missing_subject_events for r in selected),
                'events_without_known_client': sum(r.missing_client_events for r in selected)},
            'profiles': {key: components(selected, fields) for key, fields in PROFILES.items()},
            'fixed_time_cutoff': time_overlap(selected, cutoff)}
    return result


def audit(source, destination, contract):
    source, destination = Path(source), Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('m7_split_fresh_directory_required')
    paths = [Path(__file__), ROOT/'scripts/audit_m7_source.py', ROOT/'scripts/prepare_m7.py', ROOT/'scripts/f1_lab/provenance.py']
    captured = {p.relative_to(ROOT).as_posix(): sha(p.read_bytes().replace(b'\r\n', b'\n')) for p in paths}
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix='.m7-splits-') as temporary:
        stage = Path(temporary)/'result'
        stage.mkdir()
        with closing(sqlite3.connect(Path(temporary)/'spool.db')) as database:
            database.execute('PRAGMA journal_mode=OFF')
            database.execute('PRAGMA synchronous=OFF')
            database.execute('PRAGMA cache_size=-2048')
            population = ingest(source, database, contract)
            analysis = analyze(summaries(database), microseconds(timestamp(contract['pilot']['evaluation_start'])))
            spool_bytes = database.execute('PRAGMA page_count').fetchone()[0]*database.execute('PRAGMA page_size').fetchone()[0]
        if spool_bytes > MAX_SPOOL or stream_hash(source) != (contract['bytes'], contract['sha256']):
            raise ValueError('m7_split_spool_or_source_changed')
        if captured != {p.relative_to(ROOT).as_posix(): sha(p.read_bytes().replace(b'\r\n', b'\n')) for p in paths}:
            raise ValueError('m7_split_code_changed')
        report = {'schema': 'm7-source-split-readiness-1', **git_context(ROOT, captured),
            'source_files_lf_sha256': captured, 'source_sha256': contract['sha256'],
            'source_contract_sha256': sha(canonical(contract)), 'source_kind': contract['source_kind'],
            'source_url': contract['source_url'], 'population': population,
            'family_definition': 'publisher category plus subcategory; source label excluded from family key',
            'sequence_projection': 'ordered module/http_method/http_status/level; no duration, identity, timestamp, message or event_type',
            'identity_definition': 'known user_id/action_by values share a subject namespace; known client_ip is a client, not verified device',
            'unknown_identity_policy': 'null subjects and null clients do not become a shared identity; absence is reported, not proof of distinctness',
            'cutoff': contract['pilot']['evaluation_start'], 'analysis': analysis,
            'spool_logical_bytes': spool_bytes, 'memory_peak_measured': False,
            'detector_inference_runs': 0, 'new_split_selected': False, 'pilot_modified': False,
            'independent_review': 'pending', 'new_independent_evaluation': False, 'goal_qualified': False,
            'effects': {'network_calls': 0, 'paid_api_calls': 0, 'cloud_calls': 0, 'baseline_writes': 0}}
        (stage/'audit.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
        (stage/'NOTICE.md').write_text('Derived aggregate split audit of KREONET / KAFE Research, IAM Anomaly Detection Dataset 2026. '
            'Copyright (c) 2026 KAFE Research. CC BY 4.0: '+contract['license_url']+'\nSource: '+contract['source_url']+
            '\nChanges: grouped aggregate counts only. No publisher endorsement.\n', encoding='utf8')
        stage.rename(destination)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.source, args.directory, json.loads(SOURCE.read_bytes()))
    print(json.dumps({key: result[key] for key in ('population', 'spool_logical_bytes', 'new_split_selected', 'goal_qualified')}))


if __name__ == '__main__':
    main()
