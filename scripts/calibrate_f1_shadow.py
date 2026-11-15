"""Run a bounded, development-only threshold diagnostic without changing app settings."""

import argparse
import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from app.services.detection_benchmark import DetectionBenchmark
from scripts.evaluate_f1_shadow import score
from scripts.f1_lab.calibration import calibrate, infer, validate_contract
from scripts.f1_lab.detector import RULE_IDS
from scripts.f1_lab.provenance import git_context

ROOT = Path(__file__).resolve().parents[1]


def run(contract_path, anchor, destination):
    if destination.exists() or destination.is_symlink():
        raise ValueError('calibration_fresh_directory_required')
    raw = contract_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != anchor:
        raise ValueError('calibration_external_contract_anchor')
    contract = validate_contract(raw)
    benchmark = DetectionBenchmark()
    source_paths = [Path(__file__), ROOT/'scripts/evaluate_f1_shadow.py',
        ROOT/'scripts/audit_f1_features.py', *sorted((ROOT/'scripts/f1_lab').glob('*.py')),
        ROOT/'app/models.py', ROOT/'app/services/detection_benchmark.py',
        *sorted((ROOT/'app/data/benchmark').glob('*.*'))]
    before = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
              for p in source_paths}
    started = datetime.now(UTC).isoformat()
    development = [case for case in benchmark.cases if case.split == 'development']
    result = calibrate(development, contract)
    outer_rows = result.pop('out_of_fold_rows')
    result['out_of_fold_score'] = score(outer_rows, RULE_IDS.values())
    # Candidate selection is finished before even constructing diagnostic rows.
    diagnostic = infer([case for case in benchmark.cases if case.split == 'holdout'],
                       result['selected_from_all_development'])
    result['previously_observed_holdout_diagnostic'] = score(diagnostic, RULE_IDS.values())
    after = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
             for p in source_paths}
    if before != after or contract_path.read_bytes() != raw:
        raise ValueError('calibration_source_or_contract_changed')
    result.update({'schema': 'f1-calibration-result-1', **git_context(ROOT, before),
        'source_files_lf_sha256': before, 'contract_sha256': anchor,
        'contract': contract, 'started_at_utc': started, 'finished_at_utc': datetime.now(UTC).isoformat(),
        'manifest_sha256': benchmark.manifest_digest,
        'effects': {'cloud_calls': 0, 'paid_api_calls': 0, 'app_configuration_writes': 0},
        'limits': ['Previously observed authored development and holdout, never a new blind dataset.',
                   'Outer folds group identical declared observations as well as family and identity.',
                   'Grouped threshold selection does not acquire missing observations or verify approval authority.']})
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix='.calibration-') as temporary:
        stage = Path(temporary)/'result'
        stage.mkdir()
        for name, body in [('summary.json', result), ('out-of-fold.json', outer_rows), ('diagnostic.json', diagnostic)]:
            (stage/name).write_text(json.dumps(body, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
        stage.rename(destination)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract', type=Path, default=ROOT/'infra/f1-lab/calibration.json')
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.contract, args.expected_sha256, args.directory)
    print(json.dumps({key: result[key] for key in ('selected_from_all_development', 'group_audit',
        'out_of_fold_score', 'previously_observed_holdout_diagnostic', 'goal_qualified')}))


if __name__ == '__main__':
    main()
