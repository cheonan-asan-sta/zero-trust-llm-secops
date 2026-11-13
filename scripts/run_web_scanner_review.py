"""Reproduce the fixed scanner-read hypothesis on already observed development data."""

import argparse
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.transfer_evaluation import observations, score, sha, source_pins
from scripts.f1_lab.web_scanner_review import REASON, refine

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ['russellmitchell', 'santos', 'fox', 'harrison_observed']


def predict(prepared, preparation, baseline, expected_baseline_sha256, output):
    """Read observations and sealed baseline only, never original labels."""
    require(sha(baseline) == expected_baseline_sha256, 'scanner_baseline_hash')
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'scanner_fresh_prediction')
    partial = output.with_suffix(output.suffix+'.part')
    cache, total, errors = {}, 0, 0
    with Path(baseline).open('rb') as old, partial.open('xb') as target:
        for index, row in observations(prepared, preparation):
            body = old.readline(MAX_ROW+1)
            require(0 < len(body) <= MAX_ROW, 'scanner_baseline_row')
            prior = decode(body)
            require(prior['case_id'] == row['case_id'] and prior['source_index'] == index,
                    'scanner_row_binding')
            before = prior['after'] if prior['error'] is None else None
            after, probability, reason, error = before, prior['after_score'], prior['reason'], prior['error']
            if error is None:
                try:
                    require(row['observation_error'] is None and row['features'] is not None, 'scanner_observation_error')
                    key = canonical([row['features'], prior['before_score'], probability, before, reason])
                    if key not in cache:
                        require(len(cache) < 100000, 'scanner_prediction_cache_bound')
                        cache[key] = refine(OperationDecision(prior['before_score'], probability,
                            before, before, reason), row['features'])
                    decision = cache[key]
                    require(decision.score >= probability and (not before or decision.alert)
                            and not decision.automatic_enforcement_allowed, 'scanner_additive_direction')
                    after, probability, reason = decision.alert, decision.score, decision.reason
                except (ValueError, TypeError, KeyError, RecursionError):
                    after, probability, reason, error = None, None, 'scanner_inference_error', 'scanner_inference_error'
            errors += error is not None
            target.write(canonical({'case_id': row['case_id'], 'source_index': index,
                'before': before, 'after': after, 'before_score': prior['after_score'], 'after_score': probability,
                'reason': reason, 'error': error})+b'\n')
            total += 1
        require(not old.read(1), 'scanner_extra_baseline')
    require(sha(baseline) == expected_baseline_sha256, 'scanner_baseline_changed')
    partial.rename(output)
    return {'population': total, 'inference_errors': errors, 'predictions_sha256': sha(output),
            'labels_opened_by_predictor': False}


def run(plan_path, expected_plan_sha256, prior_path, expected_prior_sha256, output):
    require(sha(plan_path) == expected_plan_sha256 and sha(prior_path) == expected_prior_sha256,
            'scanner_external_hash')
    plan, prior = decode(Path(plan_path).read_bytes()), decode(Path(prior_path).read_bytes())
    require(plan['scope'] == prior['scope'] == 'observed_development_only'
            and plan['goal_qualified'] is False and prior['goal_qualified'] is False
            and prior['completed'] is True and plan['candidate'] == REASON
            and plan['candidate_sha256'] == sha(ROOT/'scripts/f1_lab/web_scanner_review.py')
            and [s['name'] for s in plan['scenarios']] == SCENARIOS
            and set(prior['scenarios']) == set(SCENARIOS), 'scanner_development_contract')
    for spec in plan['scenarios']:
        require(spec['baseline_sha256'] == prior['scenarios'][spec['name']]['prediction']['predictions_sha256'],
                'scanner_prior_binding')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    pins = source_pins(ROOT)
    report = {'schema': 'f1-scanner-read-development-1', 'completed': False,
        'scope': plan['scope'], 'goal_qualified': False, 'scenarios': {},
        'plan_sha256': expected_plan_sha256, 'prior_sha256': expected_prior_sha256, 'source_pins': pins,
        'paid_api_calls': 0, 'aws_calls': 0, 'models_refitted': False, 'labels_changed': False,
        'automatic_enforcement_allowed': False, 'production_adopted': False}
    (output/'plan.json').write_bytes(canonical(plan)+b'\n')
    try:
        preparations = {}
        for spec in plan['scenarios']:
            name, prepared = spec['name'], Path(spec['prepared'])
            require(sha(prepared/'preparation.json') == spec['preparation_sha256'], 'scanner_preparation_hash')
            preparation = decode((prepared/'preparation.json').read_bytes())
            preparations[name] = preparation
            prediction = predict(prepared, preparation, spec['baseline'], spec['baseline_sha256'],
                                 output/(name+'-predictions.jsonl'))
            require(prediction['population'] == prior['scenarios'][name]['population'], 'scanner_previous_population')
            report['scenarios'][name] = {'prediction': prediction}
            print(canonical({'predicted': name, 'population': prediction['population']}).decode(), flush=True)
        require(source_pins(ROOT) == pins, 'scanner_predictor_changed')
        (output/'prediction-seal.json').write_bytes(canonical(report)+b'\n')
        for spec in plan['scenarios']:
            name = spec['name']
            prediction = report['scenarios'][name]['prediction']
            result = score(output/(name+'-predictions.jsonl'), Path(spec['prepared'])/'truth.jsonl',
                           prediction['predictions_sha256'], preparations[name]['files']['truth.jsonl']['sha256'])
            require(result['metrics']['before'] == prior['scenarios'][name]['metrics']['after'], 'scanner_previous_score_drift')
            report['scenarios'][name] = {**result, 'prediction': prediction}
            print(canonical({'scored': name, 'changes': result['changes']}).decode(), flush=True)
        require(source_pins(ROOT) == pins and sha(plan_path) == expected_plan_sha256
                and sha(prior_path) == expected_prior_sha256, 'scanner_inputs_changed')
        report['candidate_development_gate_passed'] = all(
            value['changes']['introduced_fp'] == value['changes']['lost_tp'] == value['prediction']['inference_errors'] == 0
            for value in report['scenarios'].values()) and sum(v['changes']['new_tp'] for v in report['scenarios'].values()) > 0
        report['completed'] = True
    finally:
        (output/'run.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--expected-plan-sha256', required=True)
    parser.add_argument('--prior', type=Path, required=True)
    parser.add_argument('--expected-prior-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.plan, args.expected_plan_sha256, args.prior, args.expected_prior_sha256, args.output)


if __name__ == '__main__':
    main()
