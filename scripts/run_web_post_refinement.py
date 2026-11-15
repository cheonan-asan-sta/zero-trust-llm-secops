"""Paired, observed-development replay for the frozen successful POST candidate."""

import argparse
import json
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.transfer_evaluation import load_detector, observations, score, sha, source_pins
from scripts.f1_lab.web_post_refinement import SuccessfulPostRefinement

ROOT = Path(__file__).resolve().parents[1]


def predict(prepared, preparation, baseline, expected_baseline_sha256, model, output):
    """Only observations and frozen prior decisions; no truth file input."""
    require(sha(baseline) == expected_baseline_sha256, 'post_replay_baseline_hash')
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'post_replay_fresh_output')
    partial = output.with_suffix(output.suffix+'.part')
    cache, total, failures = {}, 0, 0
    frozen = canonical(model.web_model.export())
    with Path(baseline).open('rb') as old, partial.open('xb') as target:
        for index, row in observations(prepared, preparation):
            body = old.readline(MAX_ROW+1)
            require(0 < len(body) <= MAX_ROW, 'post_replay_baseline_row')
            prior = decode(body)
            require(prior['case_id'] == row['case_id'] and prior['source_index'] == index,
                    'post_replay_alignment')
            before, after, probability = prior['after'], prior['after'], prior['after_score']
            reason, error = prior['reason'], prior['error']
            if error is None:
                try:
                    require(type(before) is bool and row['features'] is not None, 'post_replay_prior')
                    key = canonical([row['features'], prior['before_score'], probability, before, reason])
                    if key not in cache:
                        require(len(cache) < 100000, 'post_replay_cache_bound')
                        cache[key] = model.refine(OperationDecision(prior['before_score'], probability,
                            before, before, reason), row['features'])
                    decision = cache[key]
                    require(decision.score <= probability and (before or not decision.alert)
                            and not decision.automatic_enforcement_allowed, 'post_replay_direction')
                    after, probability, reason = decision.alert, decision.score, decision.reason
                except (ValueError, KeyError, TypeError, RecursionError):
                    after, probability, reason, error = None, None, 'post_inference_error', 'post_inference_error'
            failures += error is not None
            target.write(canonical({'case_id': row['case_id'], 'source_index': index, 'before': before,
                'after': after, 'before_score': prior['after_score'], 'after_score': probability,
                'reason': reason, 'error': error})+b'\n')
            total += 1
        require(not old.read(1), 'post_replay_extra_baseline')
    require(sha(baseline) == expected_baseline_sha256 and canonical(model.web_model.export()) == frozen,
            'post_replay_baseline_or_model_changed')
    partial.rename(output)
    return {'population': total, 'inference_errors': failures, 'predictions_sha256': sha(output),
            'labels_opened_by_predictor': False}


def run(plan_path, expected_plan_sha256, output):
    require(sha(plan_path) == expected_plan_sha256, 'post_replay_plan_hash')
    plan = decode(Path(plan_path).read_bytes())
    require(plan['scope'] == 'observed_development_only' and plan['goal_qualified'] is False, 'post_replay_scope')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    pins = source_pins(ROOT)
    model = SuccessfulPostRefinement(load_detector(ROOT, plan['models'], plan['operation_policy']).web_model)
    report = {'completed': False, 'scope': plan['scope'], 'goal_qualified': False,
        'scenarios': {}, 'source_pins': pins, 'models': plan['models'], 'operation_policy': plan['operation_policy'],
        'plan_sha256': expected_plan_sha256, 'paid_api_calls': 0, 'aws_sdk_calls': 0, 'labels_changed': False,
        'models_refitted': False, 'automatic_enforcement_allowed': False, 'production_adopted': False}
    (output/'plan.json').write_bytes(canonical(plan)+b'\n')
    try:
        for spec in plan['scenarios']:
            name = spec['name']
            require(name in {'russellmitchell', 'santos', 'fox', 'harrison_observed'}
                    and name not in report['scenarios'], 'post_replay_scenario')
            prepared = Path(spec['prepared'])
            require(sha(prepared/'preparation.json') == spec['preparation_sha256'], 'post_replay_preparation')
            preparation = decode((prepared/'preparation.json').read_bytes())
            path = output/(name+'-predictions.jsonl')
            prediction = predict(prepared, preparation, spec['baseline'], spec['baseline_sha256'], model, path)
            result = score(path, prepared/'truth.jsonl', prediction['predictions_sha256'],
                           preparation['files']['truth.jsonl']['sha256'])
            result['prediction'] = prediction
            report['scenarios'][name] = result
            (output/'run.json').write_bytes(canonical(report)+b'\n')
            print(json.dumps({'scenario': name, 'changes': result['changes'], 'after': result['metrics']['after']}), flush=True)
        require(source_pins(ROOT) == pins, 'post_replay_sources_changed')
        for spec in [*plan['models'].values(), plan['operation_policy']]:
            require(sha(ROOT/spec['path']) == spec['sha256'], 'post_replay_model_changed')
        report['completed'] = True
    finally:
        (output/'run.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, type=Path)
    parser.add_argument('--expected-plan-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    run(args.plan, args.expected_plan_sha256, args.output)


if __name__ == '__main__':
    main()
