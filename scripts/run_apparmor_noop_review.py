"""Frozen advisory replay of completed audit no-op context; prediction only."""

import argparse
import hashlib
from pathlib import Path

from scripts.f1_lab.apparmor_noop import MAX_SOURCE_BYTES, MAX_SOURCE_ROWS, contexts, refine
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.transfer_evaluation import sha, source_pins

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ['russellmitchell', 'santos', 'fox', 'harrison_observed']


def observations(preparation, raw_directory):
    raw_directory = Path(raw_directory)
    manifest_path = raw_directory/'audit.json'
    require(sha(manifest_path) == preparation['source_manifest_sha256'], 'apparmor_raw_manifest')
    manifest = decode(manifest_path.read_bytes())
    require(manifest['completed'] is True, 'apparmor_raw_incomplete')
    selected, records, pins = {}, {}, {}
    for index, pair in enumerate(preparation['pairs']):
        if not pair['raw_member'].endswith('/logs/audit/audit.log'):
            continue
        provenance = manifest['pairs'][index]['provenance']
        require(provenance['raw_member'] == pair['raw_member']
                and provenance['raw_sha256'] == pair['raw_sha256'], 'apparmor_raw_binding')
        path = raw_directory/f'pair-{index}-raw.source'
        require(sha(path, MAX_SOURCE_BYTES) == pair['raw_sha256'], 'apparmor_raw_hash')
        rows = []
        with path.open('rb') as stream:
            while raw := stream.readline(MAX_ROW+1):
                require(len(rows) < MAX_SOURCE_ROWS and len(raw) <= MAX_ROW, 'apparmor_raw_bound')
                rows.append(raw)
        require(len(rows) == pair['rows'], 'apparmor_raw_population')
        selected[index] = contexts(rows, pair['raw_sha256'])
        records[index] = rows
        pins[path] = pair['raw_sha256']
    require(all(sha(p) == pin for p, pin in pins.items()), 'apparmor_raw_changed')
    return selected, records, pins


def predict(preparation, raw_directory, baseline, baseline_sha256, output):
    require(sha(baseline) == baseline_sha256, 'apparmor_baseline_hash')
    selected, records, pins = observations(preparation, raw_directory)
    output = Path(output)
    temporary = output.with_suffix('.part')
    require(not output.exists() and not temporary.exists(), 'apparmor_fresh_prediction')
    count = source = ordinal = errors = changed = 0
    with Path(baseline).open('rb') as old, temporary.open('xb') as target:
        while raw := old.readline(MAX_ROW+1):
            require(len(raw) <= MAX_ROW and source < len(preparation['pairs']), 'apparmor_previous_bound')
            ordinal += 1
            pair, row = preparation['pairs'][source], decode(raw)
            case = hashlib.sha256((pair['raw_sha256']+':'+str(ordinal)).encode()).hexdigest()
            require(row['source_index'] == source and row['case_id'] == case, 'apparmor_previous_order')
            before, error = row['after'], row['error']
            after, probability, reason = before, row['after_score'], row['reason']
            review = row.get('review', before)
            context = selected.get(source, {}).get(ordinal)
            if error is None and context is not None:
                decision = refine(OperationDecision(row['before_score'], probability, before,
                                                     bool(review), reason), context,
                                  source_sha256=pair['raw_sha256'], ordinal=ordinal,
                                  raw=records[source][ordinal-1])
                after, probability, reason, review = decision.alert, decision.score, decision.reason, decision.review
                require(not decision.automatic_enforcement_allowed, 'apparmor_no_enforcement')
            errors += error is not None
            changed += before != after
            target.write(canonical({'case_id': case, 'source_index': source,
                                    'before': before, 'after': after,
                                    'before_score': row['after_score'], 'after_score': probability,
                                    'reason': reason, 'review': review, 'error': error})+b'\n')
            count += 1
            if ordinal == pair['rows']:
                source, ordinal = source+1, 0
    require(source == len(preparation['pairs']) and ordinal == 0
            and sha(baseline) == baseline_sha256 and all(sha(p) == pin for p, pin in pins.items()),
            'apparmor_previous_population_or_drift')
    temporary.rename(output)
    return {'population': count, 'inference_errors': errors, 'changed_decisions': changed,
            'selected_noop_rows': sum(len(s) for s in selected.values()),
            'predictions_sha256': sha(output), 'labels_opened_by_predictor': False,
            'event_completion_uses_exact_same_event_only': True,
            'strictly_past_row_online_prediction': False}


def run(plan_path, expected_plan_sha256, output):
    require(sha(plan_path) == expected_plan_sha256, 'apparmor_plan_hash')
    plan = decode(Path(plan_path).read_bytes())
    require(plan['schema'] == 'apparmor-noop-observed-replay-1'
            and plan['scope'] == 'already observed development only'
            and plan['goal_qualified'] is False
            and [s['name'] for s in plan['scenarios']] == SCENARIOS
            and plan['source_pins'] == source_pins(ROOT), 'apparmor_plan_contract')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'apparmor-noop-prediction-seal-1', 'completed': False,
              'scope': plan['scope'], 'goal_qualified': False,
              'production_adopted': False, 'automatic_enforcement_allowed': False,
              'paid_api_calls': 0, 'aws_calls': 0, 'models_refitted': False,
              'labels_opened_by_predictor': False, 'plan_sha256': expected_plan_sha256,
              'source_pins': plan['source_pins'], 'scenarios': {}}
    (output/'plan.json').write_bytes(canonical(plan)+b'\n')
    try:
        for spec in plan['scenarios']:
            require(sha(spec['preparation']) == spec['preparation_sha256'], 'apparmor_preparation_hash')
            preparation = decode(Path(spec['preparation']).read_bytes())
            result = predict(preparation, spec['raw'], spec['baseline'], spec['baseline_sha256'],
                             output/(spec['name']+'-predictions.jsonl'))
            require(result['population'] == spec['population'], 'apparmor_planned_population')
            report['scenarios'][spec['name']] = result
            print(canonical({'predicted': spec['name'], **result}).decode(), flush=True)
        require(source_pins(ROOT) == plan['source_pins'] and sha(plan_path) == expected_plan_sha256,
                'apparmor_code_or_plan_changed')
        report['completed'] = True
    finally:
        (output/'prediction-seal.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.plan, args.plan_sha256, args.output)


if __name__ == '__main__':
    main()
