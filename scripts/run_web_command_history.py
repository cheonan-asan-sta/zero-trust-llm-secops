"""Replay additive command history on frozen observed-development predictions."""

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.raw_observations import raw_time
from scripts.f1_lab.transfer_evaluation import observations, score, sha, source_pins
from scripts.f1_lab.web_command_history import build_evidence, refine

ROOT = Path(__file__).resolve().parents[1]


def source_evidence(raw_directory, preparation):
    raw_directory = Path(raw_directory)
    require(sha(raw_directory/'audit.json') == preparation['source_manifest_sha256'], 'history_raw_manifest')
    audit = decode((raw_directory/'audit.json').read_bytes())
    require(len(audit['pairs']) == len(preparation['pairs']), 'history_source_count')
    result = {}
    for index, pair in enumerate(preparation['pairs']):
        if '-access.' not in pair['raw_member']:
            continue
        provenance = audit['pairs'][index]['provenance']
        require(provenance['raw_sha256'] == pair['raw_sha256']
                and provenance['raw_member'] == pair['raw_member'], 'history_source_alignment')
        path = raw_directory/f'pair-{index}-raw.source'
        require(sha(path) == pair['raw_sha256'], 'history_raw_hash')

        def records(path=path, provenance=provenance, pair=pair):
            count, digest = 0, hashlib.sha256()
            with path.open('rb') as stream:
                while body := stream.readline(MAX_ROW+1):
                    require(len(body) <= MAX_ROW, 'history_raw_line')
                    digest.update(body)
                    count += 1
                    line = body.decode('utf-8', errors='replace')
                    try:
                        moment = raw_time(line, provenance['simulation_start'], provenance['simulation_end'],
                                          source_timezone='UTC')
                    except (ValueError, RecursionError):
                        moment = None
                    yield count, moment, line
            require(count == pair['rows'] and digest.hexdigest() == pair['raw_sha256'], 'history_raw_population')

        values = build_evidence(records(), pair['raw_sha256'])
        require(not result.keys() & values.keys(), 'history_case_collision')
        result.update(values)
    return result


def predict(prepared, preparation, baseline, expected_baseline_sha256, evidence, output):
    """No labels are accepted. Freeze every result before scoring opens truth."""
    require(sha(baseline) == expected_baseline_sha256, 'history_baseline_hash')
    used, failures, total = set(), 0, 0
    with Path(baseline).open('rb') as old, Path(output).open('xb') as target:
        for index, row in observations(prepared, preparation):
            body = old.readline(MAX_ROW+1)
            require(0 < len(body) <= MAX_ROW, 'history_baseline_row')
            prior = decode(body)
            require(prior['case_id'] == row['case_id'] and prior['source_index'] == index, 'history_baseline_alignment')
            before, after, after_score = prior['after'], prior['after'], prior['after_score']
            reason, error = prior['reason'], prior['error']
            if row['case_id'] in evidence:
                used.add(row['case_id'])
                try:
                    require(error is None and type(before) is bool and row['features'] is not None,
                            'history_prior_inference')
                    decision = refine(OperationDecision(prior['before_score'], after_score, before, before, reason),
                                      row['features'], row['case_id'], evidence[row['case_id']])
                    require(decision.score >= after_score and (not before or decision.alert)
                            and not decision.automatic_enforcement_allowed, 'history_monotonicity')
                    after, after_score, reason = decision.alert, decision.score, decision.reason
                except (ValueError, KeyError, TypeError, RecursionError):
                    after, after_score, reason, error = None, None, 'history_inference_error', 'history_inference_error'
            failures += error is not None
            target.write(canonical({'case_id': row['case_id'], 'source_index': index, 'before': before,
                'after': after, 'before_score': prior['after_score'], 'after_score': after_score,
                'reason': reason, 'error': error})+b'\n')
            total += 1
        require(not old.read(1) and used == evidence.keys(), 'history_extra_baseline_or_evidence')
    require(sha(baseline) == expected_baseline_sha256, 'history_baseline_changed')
    return {'predictions_sha256': sha(output), 'population': total, 'inference_errors': failures,
            'labels_opened_by_predictor': False}


def run(plan_path, expected_plan_sha256, output):
    require(sha(plan_path) == expected_plan_sha256, 'history_plan_hash')
    plan = decode(Path(plan_path).read_bytes())
    require(plan['scope'] == 'observed_development_only' and plan['goal_qualified'] is False, 'history_plan_scope')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    pins = source_pins(ROOT)
    report = {'completed': False, 'scope': plan['scope'], 'goal_qualified': False, 'scenarios': {},
              'paid_api_calls': 0, 'aws_sdk_calls': 0, 'automatic_enforcement_allowed': False,
              'production_adopted': False, 'labels_changed': False, 'source_pins': pins,
              'plan_sha256': expected_plan_sha256}
    (output/'plan.json').write_bytes(canonical(plan)+b'\n')
    try:
        for scenario in plan['scenarios']:
            name = scenario['name']
            require(name in {'russellmitchell', 'santos', 'fox', 'harrison_observed'}
                    and name not in report['scenarios'], 'history_scenario')
            prepared = Path(scenario['prepared'])
            require(sha(prepared/'preparation.json') == scenario['preparation_sha256'], 'history_preparation')
            preparation = decode((prepared/'preparation.json').read_bytes())
            evidence = source_evidence(scenario['raw'], preparation)
            evidence_path = output/(name+'-evidence.json')
            evidence_path.write_bytes(canonical({k: asdict(v) for k, v in evidence.items()})+b'\n')
            prediction_path = output/(name+'-predictions.jsonl')
            prediction = predict(prepared, preparation, scenario['baseline'], scenario['baseline_sha256'],
                                 evidence, prediction_path)
            # Hash-sealed predictions exist before truth is opened by score().
            result = score(prediction_path, prepared/'truth.jsonl', prediction['predictions_sha256'],
                           preparation['files']['truth.jsonl']['sha256'])
            result.update(prediction=prediction, evidence_count=len(evidence), evidence_sha256=sha(evidence_path))
            report['scenarios'][name] = result
            (output/'run.json').write_bytes(canonical(report)+b'\n')
            print(json.dumps({'scenario': name, 'metrics': result['metrics'], 'changes': result['changes']}), flush=True)
        require(source_pins(ROOT) == pins, 'history_sources_changed')
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
