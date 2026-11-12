"""Freeze existing local evaluation evidence without relabeling it as a new evaluation.

No model calls, source pin overrides, rule changes or original artifact writes.
The manifest binds historical reports and the current source separately.
"""

import argparse
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from scripts.runtime_release import capture

ROOT = Path(__file__).resolve().parents[1]
SUFFIXES = {'.json', '.jsonl', '.md'}


def sha(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('evaluation_freeze_regular_file_required')
    result = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024 * 1024):
            result.update(block)
    return result.hexdigest()


def artifact_paths(root, directories):
    paths = set()
    for directory in directories:
        directory = Path(directory)
        directory = directory if directory.is_absolute() else root / directory
        if directory.is_symlink():
            raise ValueError('evaluation_freeze_symlink')
        directory = directory.resolve()
        if (not directory.is_dir() or not any(directory.is_relative_to(root / 'runtime' / name)
                                              for name in ('m6', 'm7'))):
            raise ValueError('evaluation_freeze_artifact_scope')
        for path in directory.rglob('*'):
            if path.is_symlink():
                raise ValueError('evaluation_freeze_symlink')
            if path.is_file() and path.suffix in SUFFIXES:
                paths.add(path.relative_to(root).as_posix())
    if not paths:
        raise ValueError('evaluation_freeze_empty')
    return sorted(paths)


def historical_summary(document):
    """Keep aggregate values only; conditional and full-denominator metrics stay distinct."""
    if document.get('schema') == 'm7-context-comparison-report-1':
        return {'kind': 'historical_context', 'arms': document['arms'],
                'project_goals_met': document['project_goals_met']}
    if document.get('schema') == 'm7-execution-comparison-report-1':
        return {'kind': 'historical_execution', 'cohorts': {
            name: {'arms': value['arms']} for name, value in document['cohorts'].items()},
                'project_goals_met': document['project_goals_met']}
    if document.get('mode') == 'live' and isinstance(document.get('models'), dict):
        return {'kind': 'historical_model_calls', 'models': {
            name: value['summary'] for name, value in document['models'].items()},
                'budget': document.get('budget'), 'wire_verification': document.get('wire_verification'),
                'explanation_semantics_independently_verified': False}
    return None


def freeze(directory, directories, *, root=ROOT):
    root = Path(root).resolve()
    directory = Path(directory).resolve()
    if not directory.is_relative_to(root / 'runtime') or directory.exists():
        raise ValueError('evaluation_freeze_fresh_output_required')
    paths = artifact_paths(root, directories)
    hashes = {name: sha(root / name) for name in paths}
    reports = {}
    for name in paths:
        if Path(name).name == 'report.json':
            summary = historical_summary(json.loads((root / name).read_text()))
            if summary is not None:
                reports[name] = summary
    source = capture(root, {})
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    manifest = {'schema': 'evaluation-evidence-freeze-1', 'created_at': datetime.now(UTC).isoformat(),
                'source_commit': commit, 'source_release': source,
                'artifacts': hashes, 'historical_reports': reports,
                'new_model_calls': 0, 'new_independent_evaluation': False,
                'new_independent_human_review': False, 'current_source_equivalence_claimed': False,
                'limits': ['Historical source pins remain authoritative for historical results.',
                           'A freeze verifies artifact bytes; it does not validate labels or demonstrate generalization.']}
    if {name: sha(root / name) for name in paths} != hashes or capture(root, {}) != source:
        raise ValueError('evaluation_freeze_inputs_changed')
    directory.mkdir(parents=True, mode=0o700)
    descriptor = os.open(directory / 'manifest.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(manifest, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    return {'manifest_sha256': sha(directory / 'manifest.json'), 'artifacts': len(hashes),
            'historical_reports': len(reports), 'new_model_calls': 0}


def verify(directory, *, root=ROOT, expected_manifest=None):
    root = Path(root).resolve()
    path = Path(directory).resolve() / 'manifest.json'
    if not path.is_relative_to(root / 'runtime'):
        raise ValueError('evaluation_freeze_output_scope')
    if expected_manifest is not None and sha(path) != expected_manifest:
        raise ValueError('evaluation_freeze_manifest_changed')
    document = json.loads(path.read_text())
    if document.get('schema') != 'evaluation-evidence-freeze-1':
        raise ValueError('evaluation_freeze_schema')
    for name, expected in document['artifacts'].items():
        path = root / name
        if (not any(path.resolve().is_relative_to(root / 'runtime' / prefix) for prefix in ('m6', 'm7'))
                or path.suffix not in SUFFIXES or sha(path) != expected):
            raise ValueError('evaluation_freeze_artifact_changed')
    if capture(root, {}) != document['source_release']:
        raise ValueError('evaluation_freeze_source_changed')
    return {'verified': True, 'artifacts': len(document['artifacts']), 'new_independent_evaluation': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('freeze', 'verify'))
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--artifact', action='append', default=[])
    parser.add_argument('--manifest-sha256', help='Previously recorded external manifest pin for verification')
    args = parser.parse_args(argv)
    result = (freeze(args.directory, args.artifact) if args.command == 'freeze'
              else verify(args.directory, expected_manifest=args.manifest_sha256))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
