"""Compare draft advice with the preserved baseline on already-observed synthetic data."""

import argparse
import hashlib
import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from app.services.detection_benchmark import (
    DetectionBenchmark,
    confusion,
    family_intervals,
    metrics,
)
from scripts.f1_lab.detector import DraftThresholds, ShadowDetector
from scripts.f1_lab.provenance import git_context

ROOT = Path(__file__).resolve().parents[1]


def targets_met(values):
    return all(values[key] is not None and values[key] >= .95 for key in ('precision', 'recall', 'f1')) and (
        values['false_positive_rate'] is not None and values['false_positive_rate'] <= .05)


def score(rows, rule_ids):
    counts = confusion([r['threat'] for r in rows], [r['detected'] for r in rows])
    values = metrics(counts)
    rules = []
    for ident in sorted(rule_ids):
        rule_counts = confusion([ident in r['expected_rule_ids'] for r in rows],
                                [ident in r['predicted_rule_ids'] for r in rows])
        rule_values = metrics(rule_counts)
        support = len({r['family_id'] for r in rows if ident in r['expected_rule_ids']})
        rules.append({'rule_id': ident, 'confusion': rule_counts, 'metrics': rule_values,
                      'positive_families': support, 'point_targets_met': targets_met(rule_values)})
    negatives = len({r['family_id'] for r in rows if not r['threat']})
    errors = sum(r['error'] is not None for r in rows)
    inconclusive = sum(r.get('assessment_status') == 'inconclusive' for r in rows)
    gate = targets_met(values) and errors == 0 and inconclusive == 0 and negatives >= 12 and all(
        r['point_targets_met'] and r['positive_families'] >= 2 for r in rules)
    confidence = family_intervals(rows)
    statistical = gate and all((interval['upper'] is not None and interval['upper'] <= .05)
        if name == 'false_positive_rate' else (interval['lower'] is not None and interval['lower'] >= .95)
        for name, interval in confidence['intervals'].items())
    return {'confusion': counts, 'metrics': values, 'case_count': len(rows),
            'inconclusive_cases': inconclusive,
            'inconclusive_kept_in_denominator': True,
            'point_targets_met': targets_met(values), 'gate_passed': gate,
            'statistical_target_supported': statistical, 'family_confidence': confidence,
            'evaluation_errors': errors, 'rules': rules}


def evaluate(benchmark, detector):
    results = {}
    for split in ('development', 'holdout'):
        rows = []
        for case in benchmark.cases:
            if case.split != split:
                continue
            error, prediction = None, None
            try:
                # Only event observations and an operator-chosen tenant enter the detector.
                # Labels/family/expected rules remain exclusively in scoring below.
                prediction = detector.evaluate(case.event, 'synthetic-lab')
                predicted = prediction['predicted_rule_ids']
            except (ValueError, TypeError, RuntimeError):
                error, predicted = 'shadow_evaluation_failed', []
            detected = bool(predicted)
            rows.append({'case_id': case.case_id, 'session_id': case.session_id,
                'family_id': case.family_id, 'domain': case.domain, 'threat': case.threat,
                'detected': detected, 'expected_rule_ids': case.expected_rule_ids,
                'predicted_rule_ids': predicted, 'error': error, 'prediction': prediction,
                'assessment_status': prediction.get('assessment_status') if prediction else 'failed',
                'outcome': 'TP' if case.threat and detected else 'FN' if case.threat else 'FP' if detected else 'TN'})
        results[split] = {**score(rows, (r.rule_id for r in benchmark.engine.summaries())), 'cases': rows}
    return results


def run(destination, thresholds):
    if destination.exists() or destination.is_symlink():
        raise ValueError('fresh_shadow_output_required')
    benchmark = DetectionBenchmark()
    detector = ShadowDetector(thresholds=thresholds)
    started = datetime.now(UTC).isoformat()
    source_paths = [*sorted((ROOT / 'scripts/f1_lab').glob('*.py')),
                    ROOT / 'scripts/evaluate_f1_shadow.py', ROOT / 'app/models.py',
                    ROOT / 'app/services/ocsf.py', ROOT / 'app/services/sigma.py',
                    ROOT / 'app/services/detection_benchmark.py',
                    *sorted((ROOT / 'app/data/benchmark').glob('*.*')),
                    *sorted((ROOT / 'app/data/sigma').glob('*.yml'))]
    captured = {p.relative_to(ROOT).as_posix(): hashlib.sha256(
        p.read_bytes().replace(b'\r\n', b'\n')).hexdigest() for p in source_paths}
    reports = evaluate(benchmark, detector)
    summary = {'schema': 'f1-shadow-comparison-1', 'started_at_utc': started,
        'finished_at_utc': datetime.now(UTC).isoformat(),
        **git_context(ROOT, captured),
        'source_files_lf_sha256': captured,
        'thresholds': thresholds.model_dump(), 'config_sha256': detector.config_sha256,
        'manifest_sha256': benchmark.manifest_digest,
        'baseline_ruleset_sha256': benchmark.engine.ruleset_digest_sha256,
        'data_role': 'previously_observed_synthetic_development_and_diagnostic_holdout',
        'new_independent_evaluation': False, 'independent_review': 'pending',
        'production_integrated': False, 'baseline_rules_changed': False,
        'unsigned_approval_claims_used_by_candidate': False, 'signed_approvals_supplied': 0,
        'paid_api_calls': 0, 'cloud_calls': 0, 'access_grants': 0, 'session_changes': 0,
        'goal_qualified': False,
        'comparisons': {split: {'baseline': {k: v for k, v in benchmark.evaluate(split).items()
            if k in {'confusion', 'metrics', 'gate_passed', 'statistical_target_supported'}},
            'shadow': {k: v for k, v in report.items() if k != 'cases'}} for split, report in reports.items()},
        'limits': ['Candidate is draft advice only and has no access or session API.',
                   'Legacy baseline reads an unsigned approval field; the candidate deliberately does not trust it.',
                   'Observed holdout is diagnostic and cannot establish new independent performance.',
                   'No approvals are fabricated from labels, family names or unsigned claims.']}
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix='.shadow-') as temp:
        stage = Path(temp) / 'candidate'
        stage.mkdir()
        for split, report in reports.items():
            (stage / (split+'.json')).write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
        (stage / 'comparison.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2)+'\n', encoding='utf8')
        if captured != {p.relative_to(ROOT).as_posix(): hashlib.sha256(
                p.read_bytes().replace(b'\r\n', b'\n')).hexdigest() for p in source_paths}:
            raise ValueError('shadow_source_changed_during_run')
        stage.rename(destination)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--credential-failures', type=int, default=3)
    parser.add_argument('--fanout', type=int, default=8)
    parser.add_argument('--download-mb', type=float, default=500)
    args = parser.parse_args()
    thresholds = DraftThresholds(credential_failures=args.credential_failures,
                                resource_fanout=args.fanout, bulk_download_mb=args.download_mb)
    result = run(args.directory, thresholds)
    print(json.dumps({'comparisons': result['comparisons'], 'goal_qualified': False}))


if __name__ == '__main__':
    main()
