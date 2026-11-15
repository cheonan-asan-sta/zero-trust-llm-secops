"""Fit on first-development data and compare a pinned HTTP-only candidate locally."""

import argparse
import hashlib
import json
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.native_heads import gate, load_frozen_heads
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.raw_semantics import PROFILE
from scripts.f1_lab.web_refinement import (
    WebRefinement,
    canonical,
    fit_http_tree,
    load_web_refinement,
)
from scripts.fit_native_raw import receipt, rows

ROOT = Path(__file__).resolve().parents[1]
THRESHOLDS = (.5, .95)


def pinned(path, sha):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 2*1024**2, 'web_plan_file')
    body = path.read_bytes()
    require(hashlib.sha256(body).hexdigest() == sha, 'web_plan_hash')
    return decode(body)


def fingerprint(path):
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def compare(directory, preparation, baseline, candidate, reference):
    totals = {str(t): {'baseline': counts(), 'refined': counts()} for t in THRESHOLDS}
    groups = [{str(t): {'baseline': counts(), 'refined': counts()} for t in THRESHOLDS}
              for _ in preparation['pairs']]
    changes = [Counter() for _ in preparation['pairs']]
    index = within = count = non_http = 0
    cache, reasons, sha_old, sha_new = {}, Counter(), hashlib.sha256(), hashlib.sha256()
    model_before = canonical(candidate.export())
    for features, truth in rows(directory, preparation):
        key = canonical(features)
        if key not in cache:
            require(len(cache) < 100000, 'web_comparison_vector_bound')
            old = new = None
            is_http, reason = False, 'baseline_inference_error'
            try:
                old = baseline.probability(features)
            except ValueError:
                pass
            else:
                result = candidate.score(features)
                new, reason = result.score, result.reason
                require(result.baseline == old and new <= old, 'web_monotone_score')
                is_http = gate(features, profile=PROFILE) == 'http'
                if not is_http:
                    require(new == old, 'web_non_http_changed')
            cache[key] = old, new, is_http, reason
        old, new, is_http, reason = cache[key]
        reasons[reason] += 1
        non_http += reason != 'baseline_inference_error' and not is_http
        count += 1
        for sha, score in ((sha_old, old), (sha_new, new)):
            sha.update(canonical({'ordinal': count, 'probability': score})+b'\n')
        for threshold in THRESHOLDS:
            label = str(threshold)
            for kind, score in (('baseline', old), ('refined', new)):
                prediction = None if score is None else score >= threshold
                record(totals[label][kind], truth, prediction)
                record(groups[index][label][kind], truth, prediction)
        if old is not None and new is not None:
            if old >= .95 and new < .95:
                changes[index]['lost_tp' if truth else 'removed_fp'] += 1
            if old < .95 and new >= .95:
                changes[index]['recovered_tp' if truth else 'introduced_fp'] += 1
        within += 1
        if within == preparation['pairs'][index]['rows']:
            index += 1
            within = 0
    require(canonical(candidate.export()) == model_before, 'web_candidate_changed_during_evaluation')
    require(sha_old.hexdigest() == reference['probability_sequence_sha256'], 'web_baseline_score_drift')
    result = {label: {kind: metrics(c) for kind, c in group.items()} for label, group in totals.items()}
    require(all(result[label]['baseline'] == reference['metrics'][label] for label in result), 'web_baseline_metric_drift')
    pairs = [{'raw_member': pair['raw_member'], 'metrics': {label: {kind: metrics(c) for kind,c in group.items()}
             for label, group in groups[index].items()}, 'changes_at_0_95': dict(changes[index])}
             for index, pair in enumerate(preparation['pairs'])]
    return {'metrics': result, 'per_pair': pairs, 'population': count, 'unique_vectors': len(cache),
            'baseline_probability_sha256': sha_old.hexdigest(), 'refined_probability_sha256': sha_new.hexdigest(),
            'non_http_scores_unchanged': True, 'non_http_rows_verified': non_http, 'reason_counts': dict(reasons)}


def run(plan_path, expected_plan_sha256, output):
    plan_path, output = Path(plan_path), Path(output)
    plan = pinned(plan_path, expected_plan_sha256)
    require(plan['schema'] == 'f1-web-refinement-protocol-1' and plan['feature_profile'] == PROFILE
            and plan['scope'] == 'observed development/calibration only' and len(plan['scenarios']) == 3,
            'web_experiment_scope')
    require(not output.exists() and not output.is_symlink(), 'fresh_web_experiment_output')
    output.mkdir(parents=True, mode=0o700)
    source_paths = ('scripts/f1_lab/web_refinement.py', 'scripts/run_web_refinement.py')
    sources = {path: fingerprint(ROOT/path) for path in source_paths}
    report = {'schema': 'extra-native-web-refinement-1', 'completed': False,
              'started_at': datetime.now(UTC).isoformat(), 'plan': fingerprint(plan_path), 'sources': sources,
              'scope': plan['scope'], 'thresholds': THRESHOLDS, 'scenarios': {}, 'goal_qualified': False,
              'original_app_changed': False, 'labels_changed': False, 'baseline_refitted': False,
              'production_adopted': False, 'independent_final_metrics': None,
              'paid_api_calls': 0, 'aws_sdk_calls': 0, 'github_pushes': 0}
    def save():
        (output/'run.json.part').write_bytes(canonical(report)+b'\n')
        (output/'run.json.part').replace(output/'run.json')
    save()
    started = time.perf_counter()
    try:
        baseline_spec = plan['baseline']
        baseline = load_frozen_heads(ROOT/baseline_spec['path'], baseline_spec['sha256'])
        training_spec = plan['scenarios'][0]
        require(training_spec['name'] == 'russellmitchell' and training_spec['role'] == 'training_development', 'web_training_split')
        training_dir = ROOT/training_spec['directory']
        training = receipt(training_dir, training_spec['preparation_sha256'])
        tree, fit_report = fit_http_tree(rows(training_dir, training))
        report['training'] = fit_report
        candidate = WebRefinement(baseline, baseline_spec['sha256'], tree, training_spec['preparation_sha256'])
        (output/'model.json').write_bytes(canonical(candidate.export())+b'\n')
        report['candidate'] = fingerprint(output/'model.json')
        report['candidate_frozen_at'] = datetime.now(UTC).isoformat()
        candidate = load_web_refinement(output/'model.json', report['candidate']['sha256'],
                                        ROOT/baseline_spec['path'], baseline_spec['sha256'])
        save()
        for scenario in plan['scenarios']:
            name = scenario['name']
            require(name in {'russellmitchell', 'santos', 'fox'} and name not in report['scenarios'], 'web_evaluation_split')
            directory = ROOT/scenario['directory']
            preparation = receipt(directory, scenario['preparation_sha256'])
            reference = pinned(ROOT/scenario['baseline_diagnostic'], scenario['baseline_diagnostic_sha256'])
            require(reference['completed'] and reference['preparation_sha256'] == scenario['preparation_sha256']
                    and reference['model_sha256'] == baseline_spec['sha256'], 'web_reference_binding')
            part_started = time.perf_counter()
            result = compare(directory, preparation, baseline, candidate, reference)
            require(result['population'] == scenario['rows'], 'web_comparison_population')
            result['seconds'] = round(time.perf_counter()-part_started, 3)
            result['role'] = scenario['role']
            report['scenarios'][name] = result
            save()
            web = next(p for p in result['per_pair'] if '-access.' in p['raw_member'])
            print(json.dumps({'scenario': name, 'web': web, 'global': result['metrics']['0.95']}), flush=True)
        web_results = [next(p for p in value['per_pair'] if '-access.' in p['raw_member'])
                       for value in report['scenarios'].values()]
        report['local_web_comparison_passed'] = all(
            row['metrics']['0.95']['refined']['false_positive_rate'] <= .05
            and row['metrics']['0.95']['refined']['recall'] >= .95
            and row['changes_at_0_95'].get('lost_tp', 0) == 0
            and row['changes_at_0_95'].get('introduced_fp', 0) == 0 for row in web_results)
        require(all(fingerprint(ROOT/path) == value for path,value in sources.items()), 'web_source_changed')
        require(hashlib.sha256((ROOT/baseline_spec['path']).read_bytes()).hexdigest() == baseline_spec['sha256'], 'web_baseline_changed')
        report['completed'] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        report['elapsed_seconds'] = round(time.perf_counter()-started, 3)
        report['ended_at'] = datetime.now(UTC).isoformat()
        save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, type=Path)
    parser.add_argument('--expected-plan-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = run(args.plan, args.expected_plan_sha256, args.output)
    print(json.dumps({'completed': result['completed'], 'local_web_comparison_passed': result['local_web_comparison_passed'],
                      'goal_qualified': result['goal_qualified']}))


if __name__ == '__main__':
    main()
