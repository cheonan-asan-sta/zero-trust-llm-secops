"""Recheck the real240 archive and replay all10 saved approval consumptions.

This is an explicit local artifact acceptance run, separate from portable unit
fixtures. It does not invent a historical normal verdict or relabel old data.
"""

import argparse
import json
import tempfile
from pathlib import Path

from scripts import evaluate_m7_execution_context as evaluation
from scripts.evaluate_m7_context import exclusive_write, implementation_hashes, source_revision


def verify(directory):
    directory = Path(directory)
    sources = implementation_hashes()
    before = evaluation.prior_artifacts(directory)
    inputs = evaluation.read_rows((directory / 'inputs.jsonl').read_bytes())
    predictions = evaluation.read_rows((directory / 'predictions.jsonl').read_bytes())
    scoring = evaluation.read_rows((directory / 'private/scoring.jsonl').read_bytes())
    groups = [inputs, predictions, scoring]
    identifiers = [{row['case_id'] for row in rows} for rows in groups]
    if any(len(rows) != 240 for rows in groups) or any(len(ids) != 240 for ids in identifiers):
        raise ValueError('historical_archive_session_count')
    if identifiers[0] != identifiers[1] or identifiers[0] != identifiers[2]:
        raise ValueError('historical_archive_session_binding')
    indexed = {row['case_id']: row for row in predictions}
    selected = [item for item in inputs if item['prior_use'] is not None]
    if len(selected) != 10:
        raise ValueError('historical_archive_quota_count')
    with tempfile.TemporaryDirectory(prefix='m7-historical-quota-') as temporary:
        for index, spec in enumerate(selected):
            fingerprint = evaluation.digest(evaluation.canonical(spec))
            archived = [entry for entry in indexed[spec['case_id']]['provenance']['context_records']
                        if entry['kind'] == 'evaluation']
            if len(archived) != 1:
                raise ValueError('historical_archive_evaluation_count')
            row = evaluation.run_case(spec, Path(temporary) / str(index), historical_prior=archived[0])
            used = [entry for entry in row['provenance']['context_records'] if entry['kind'] == 'evaluation']
            if (row['historical_quota_replayed'] is not True or used != archived
                    or row['with_context']['verdict'] != 'unknown'
                    or row['execution_trace']['state'] != 'not_supplied'
                    or evaluation.digest(evaluation.canonical(spec)) != fingerprint):
                raise ValueError('historical_archive_replay_changed')
    evaluation.prior_artifacts(directory, pinned=before)
    if implementation_hashes() != sources:
        raise ValueError('historical_archive_verifier_source_changed')
    commit, dirty = source_revision()
    return {'schema': 'm7-historical-quota-acceptance-1', 'sessions': 240,
            'historical_quota_records_replayed': len(selected), 'artifacts_unchanged': True,
            'saved_evaluations_preserved': True, 'new_normal_verdicts_invented': 0,
            'source_commit': commit, 'source_dirty': dirty, 'source_sha256': sources,
            'previous_artifact_sha256': before, 'private_case_workspaces_removed': True,
            'external_model_requests': 0, 'scope': 'Original controlled archive regression, not an independent accuracy evaluation.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('historical_acceptance_output_exists')
    result = verify(args.directory)
    exclusive_write(args.output, json.dumps(result, ensure_ascii=False, indent=2).encode() + b'\n')
    print(json.dumps({'sessions': result['sessions'], 'historical_quota_records_replayed': result['historical_quota_records_replayed'],
                      'artifacts_unchanged': result['artifacts_unchanged']}))


if __name__ == '__main__':
    main()
