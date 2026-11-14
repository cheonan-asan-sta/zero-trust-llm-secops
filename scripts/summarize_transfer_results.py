"""Recompute a sealed transfer score before producing a descriptive kind summary."""

import argparse
from pathlib import Path

from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import score, sha
from scripts.f1_lab.transfer_summary import markdown, summarize


def run(directory, expected_score_sha256, expected_manifest_sha256, output):
    directory, output = Path(directory), Path(output)
    scored_path = directory/'scoring/score.json'
    manifest_path = directory/'prediction-packet/prediction-manifest.json'
    require(sha(scored_path) == expected_score_sha256 and sha(manifest_path) == expected_manifest_sha256,
            'transfer_summary_input_hash')
    scored, manifest = decode(scored_path.read_bytes()), decode(manifest_path.read_bytes())
    require(scored.get('completed') is True and manifest.get('phase') == 'predictions_sealed'
            and scored.get('prediction_manifest_sha256') == expected_manifest_sha256
            and scored.get('candidate_freeze_sha256') == manifest.get('candidate_freeze_sha256')
            and sha(directory/'freeze.json') == manifest['candidate_freeze_sha256'], 'transfer_summary_seal_binding')
    audit_path = directory/'raw/audit.json'
    require(sha(audit_path) == manifest['raw_manifest_sha256'], 'transfer_summary_raw_hash')
    raw = decode(audit_path.read_bytes())
    frozen = decode((directory/'freeze.json').read_bytes())
    require(raw['candidate_freeze_sha256'] == manifest['candidate_freeze_sha256']
            and raw['archive_sha256'] == frozen['archive_sha256'], 'transfer_summary_raw_binding')
    actual = score(directory/'prediction-packet/predictions.jsonl', directory/'scoring/truth.jsonl',
                   manifest['predictions_sha256'], scored['truth_manifest']['truth_sha256'])
    require(all(actual[key] == scored[key] for key in ('population', 'metrics', 'per_source', 'changes')),
            'transfer_summary_recomputed_score_disagrees')
    result = summarize(actual, raw)
    result.update(score_sha256=expected_score_sha256, prediction_manifest_sha256=expected_manifest_sha256,
        candidate_freeze_sha256=manifest['candidate_freeze_sha256'], predictions_rescored=True,
        source_id=scored['source_id'], paid_api_calls=0, aws_calls=0)
    require(sha(scored_path) == expected_score_sha256 and sha(manifest_path) == expected_manifest_sha256
            and sha(audit_path) == manifest['raw_manifest_sha256'], 'transfer_summary_inputs_changed')
    require(not output.exists() and not output.is_symlink(), 'transfer_summary_fresh_output')
    output.mkdir(parents=True)
    (output/'summary.json').write_bytes(canonical(result)+b'\n')
    (output/'summary.md').write_text(markdown(result), encoding='utf8')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--expected-score-sha256', required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.directory, args.expected_score_sha256, args.expected_manifest_sha256, args.output)
    print(canonical({'completed': result['completed'], 'goal_qualified': result['goal_qualified'],
                     'output': str(args.output)}).decode())


if __name__ == '__main__':
    main()
