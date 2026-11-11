"""Freeze the unchanged detector and explain baseline errors offline, without approving labels."""

import argparse
import hashlib
import json
import platform
import tempfile
from collections import defaultdict
from importlib.metadata import version
from pathlib import Path, PurePosixPath

import yaml

from app.services.detection_benchmark import DetectionBenchmark
from app.services.ocsf import OCSFNormalizer
from app.services.sigma import (
    SigmaEngine,
    _evaluate_condition,
    _lookup,
    _match_field,
    _match_selector,
)
from scripts.f1_lab.provenance import git_context

ROOT = Path(__file__).resolve().parents[1]
FIXED_SOURCES = (
    'app/models.py', 'app/services/detection_benchmark.py', 'app/services/ocsf.py',
    'app/services/sigma.py', 'scripts/build_detection_benchmark.py',
    'scripts/prepare_f1_review.py', 'app/data/benchmark/manifest.json',
    'app/data/benchmark/families.json', 'app/data/benchmark/cases.jsonl',
    'scripts/f1_lab/provenance.py',
)
CAUSES = {'input_mapping', 'missing_observation', 'temporal_context', 'scope_exception',
          'rule_condition', 'label_dispute', 'other'}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def read(path, *, limit=32 * 1024**2):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit,
            'f1_regular_bounded_file_required')
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'f1_file_size')
    return raw


def sources():
    names = (*FIXED_SOURCES, *(p.relative_to(ROOT).as_posix() for p in
              sorted((ROOT / 'app/data/sigma').iterdir()) if p.suffix in {'.yml', '.yaml'}))
    return {name: read(ROOT / name).replace(b'\r\n', b'\n') for name in names}


def trace_rule(rule, event):
    selectors, details = {}, {}
    for name, selector in rule.detection.items():
        if name == 'condition':
            continue
        selectors[name] = _match_selector(selector, event)
        branches = selector if isinstance(selector, list) else [selector]
        details[name] = {'matched': selectors[name], 'branches': []}
        for branch in branches:
            fields = []
            for expression, expected in branch.items():
                field = str(expression).split('|')[0]
                present, actual = _lookup(event, field)
                fields.append({'expression': expression, 'present': present, 'actual': actual,
                               'expected': expected, 'matched': _match_field(str(expression), expected, event)})
            details[name]['branches'].append({'fields': fields})
    return {'rule_id': rule.summary.rule_id, 'rule_sha256': rule.summary.digest_sha256,
            'condition': rule.detection['condition'],
            'matched': _evaluate_condition(rule.condition, selectors), 'selectors': details}


def diagnostics(benchmark, reports):
    outcomes = {row['case_id']: row for report in reports.values() for row in report['cases']}
    evidence, groups = [], defaultdict(list)
    for case in benchmark.cases:
        row = outcomes[case.case_id]
        require(row['error'] is None, 'f1_baseline_evaluation_error')
        missing = sorted(set(row['expected_rule_ids']) - set(row['predicted_rule_ids']))
        extra = sorted(set(row['predicted_rule_ids']) - set(row['expected_rule_ids']))
        if row['outcome'] not in {'FN', 'FP'} and not missing and not extra:
            continue
        normalized = benchmark.normalizer.normalize(case.event).event.model_dump(mode='json', exclude_none=True)
        relevant = set(row['expected_rule_ids']) | set(row['predicted_rule_ids'])
        traces = [trace_rule(rule, normalized) for rule in benchmark.engine.approved_rules
                  if rule.summary.rule_id in relevant]
        require({trace['rule_id'] for trace in traces if trace['matched']} == set(row['predicted_rule_ids']),
                'f1_trace_detector_mismatch')
        detail = {**row, 'split': case.split, 'missed_expected_rule_ids': missing,
                  'unexpected_rule_ids': extra, 'observed_input': case.event.analysis_payload(),
                  'normalized_input': normalized, 'rule_traces': traces,
                  'diagnosis_status': 'mechanical_trace_only_pending_human_review'}
        evidence.append(detail)
        groups[case.family_id].append(detail)
    worksheet = []
    for family, rows in sorted(groups.items()):
        worksheet.append({'family_id': family, 'split': rows[0]['split'],
            'case_ids': [r['case_id'] for r in rows], 'reviewer_subject': None,
            'cause': None, 'label_assessment': None, 'evidence_case_ids': [],
            'rationale': '', 'proposed_change': '', 'counterexample': ''})
    return evidence, worksheet


def verify(directory, expected):
    require(directory.is_dir() and not directory.is_symlink(), 'f1_directory_required')
    raw = read(directory / 'freeze.json', limit=128 * 1024)
    require(digest(raw) == expected, 'f1_external_anchor_mismatch')
    manifest = json.loads(raw)
    require(manifest['schema'] == 'f1-baseline-review-1' and
            manifest['independent_review'] == 'pending' and manifest['detector_changed'] is False,
            'f1_manifest_contract')
    expected_files = set(manifest['files']) | {'freeze.json', 'reviews.jsonl'}
    actual_files = set()
    for path in directory.rglob('*'):
        require(not path.is_symlink() and path.resolve().is_relative_to(directory.resolve()), 'f1_path_scope')
        if path.is_file():
            actual_files.add(path.relative_to(directory).as_posix())
    require(actual_files == expected_files, 'f1_file_inventory')
    for name, expected_hash in manifest['files'].items():
        parts = PurePosixPath(name)
        require(not parts.is_absolute() and '..' not in parts.parts and '\\' not in name,
                'f1_manifest_path')
        require(digest(read(directory / name)) == expected_hash, 'f1_frozen_file_changed')
    return manifest


def create(destination, *, author):
    require(isinstance(author, str) and bool(author.strip()), 'f1_author_required')
    require(not destination.exists() and not destination.is_symlink(), 'f1_fresh_directory_required')
    captured = sources()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix='.f1-') as temp:
        stage = Path(temp) / 'candidate'
        stage.mkdir()
        for name, raw in captured.items():
            path = stage / 'source' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        documents = [(name, yaml.safe_load(raw)) for name, raw in captured.items()
                     if name.startswith('app/data/sigma/')]
        engine = SigmaEngine.from_documents(documents)
        benchmark = DetectionBenchmark(root=stage / 'source/app/data/benchmark',
                                       normalizer=OCSFNormalizer(), engine=engine)
        require(digest(captured['scripts/build_detection_benchmark.py']) == benchmark.manifest['generator_sha256'],
                'f1_generator_identity_mismatch')
        reports = {split: benchmark.evaluate(split) for split in ('development', 'holdout')}
        evidence, worksheet = diagnostics(benchmark, reports)
        for split, report in reports.items():
            (stage / f'{split}.json').write_bytes(encoded(report))
        (stage / 'evidence.jsonl').write_bytes(b''.join(
            json.dumps(row, ensure_ascii=False, separators=(',', ':')).encode() + b'\n' for row in evidence))
        (stage / 'review-index.json').write_bytes(encoded([
            {key: row[key] for key in ('family_id', 'split', 'case_ids')} for row in worksheet]))
        (stage / 'reviews.jsonl').write_bytes(b''.join(
            json.dumps(row, ensure_ascii=False).encode() + b'\n' for row in worksheet))
        manifest = {'schema': 'f1-baseline-review-1', 'independent_review': 'pending',
            'implementation_author': author, 'detector_changed': False,
            **git_context(ROOT, captured),
            'environment': {'python': platform.python_version(),
                            'pydantic': version('pydantic'), 'pyyaml': version('pyyaml')},
            'metric_unit': 'authored_synthetic_event', 'new_blind_evaluation': False,
            'ruleset_sha256': engine.ruleset_digest_sha256,
            'mapping_sha256': benchmark.normalizer.mapping_digest_sha256,
            'evidence_cases': len(evidence), 'review_families': len(worksheet),
            'files': {p.relative_to(stage).as_posix(): digest(read(p)) for p in sorted(stage.rglob('*'))
                      if p.is_file() and p.name != 'reviews.jsonl'}}
        raw = encoded(manifest)
        (stage / 'freeze.json').write_bytes(raw)
        anchor = digest(raw)
        verify(stage, anchor)
        require(sources() == captured, 'f1_source_changed_during_run')
        stage.rename(destination)
    return {'freeze_sha256': anchor, 'evidence_cases': len(evidence), 'review_families': len(worksheet),
            'independent_review': 'pending', 'quality_targets_met': reports['holdout']['gate_passed'],
            'confusion': {split: r['confusion'] for split, r in reports.items()}}


def assess(directory, expected):
    manifest = verify(directory, expected)
    index = {r['family_id']: r for r in json.loads(read(directory / 'review-index.json'))}
    rows = [json.loads(line) for line in read(directory / 'reviews.jsonl', limit=4 * 1024**2).splitlines()]
    require(len(rows) == len(index), 'f1_review_count')
    seen, pending = set(), 0
    for row in rows:
        require(set(row) == {'family_id', 'split', 'case_ids', 'reviewer_subject', 'cause',
            'label_assessment', 'evidence_case_ids', 'rationale', 'proposed_change', 'counterexample'},
            'f1_review_fields')
        family = row['family_id']
        require(family in index and family not in seen and all(
            row[k] == index[family][k] for k in ('split', 'case_ids')), 'f1_review_scope')
        seen.add(family)
        if row['cause'] is None:
            pending += 1
            continue
        require(row['cause'] in CAUSES and row['label_assessment'] in {'supported', 'disputed', 'insufficient'},
                'f1_review_cause')
        subject = row['reviewer_subject']
        require(isinstance(subject, str) and bool(subject.strip()) and subject.strip().casefold() !=
                manifest['implementation_author'].strip().casefold(), 'f1_different_reviewer_required')
        require(all(isinstance(row[k], str) and 10 <= len(row[k].strip()) <= 2000 for k in
                    ('rationale', 'proposed_change', 'counterexample')), 'f1_review_reason_required')
        evidence = row['evidence_case_ids']
        require(isinstance(evidence, list) and evidence and all(isinstance(v, str) for v in evidence)
                and len(set(evidence)) == len(evidence) and set(evidence) <= set(row['case_ids']),
                'f1_review_evidence_scope')
    return {'review_families': len(index), 'reviewed': len(index) - pending, 'pending': pending,
            'ready_for_team_adjudication': pending == 0, 'independent_review_verified': False,
            'label_approval': 'pending', 'identity_assurance': 'self_reported_only',
            'worksheet_sha256': digest(read(directory / 'reviews.jsonl'))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('create', 'verify', 'assess'))
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--expected-sha256')
    parser.add_argument('--author')
    args = parser.parse_args()
    if args.mode == 'create':
        result = create(args.directory, author=args.author)
    else:
        require(args.expected_sha256, 'f1_external_anchor_required')
        if args.mode == 'assess':
            result = assess(args.directory, args.expected_sha256)
            print(json.dumps(result))
            return 0 if result['ready_for_team_adjudication'] else 2
        manifest = verify(args.directory, args.expected_sha256)
        result = {'verified': True, 'independent_review': manifest['independent_review']}
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
