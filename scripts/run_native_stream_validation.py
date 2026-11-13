"""Pinned all-row stream equivalence and frozen-model calibration, locally only."""

import argparse
import hashlib
import json
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path

from scripts.evaluate_native_tree import evaluate
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.raw_semantics import PROFILE
from scripts.prepare_native_stream import canonical, prepare

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('scripts/f1_lab/streaming_context.py', 'scripts/prepare_native_stream.py',
           'scripts/run_native_stream_validation.py', 'scripts/f1_lab/raw_observations.py',
           'scripts/f1_lab/raw_context.py', 'scripts/f1_lab/raw_semantics.py', 'scripts/evaluate_native_tree.py')


def pinned(path, expected):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024**2, 'stream_validation_pin_file')
    body = path.read_bytes()
    require(hashlib.sha256(body).hexdigest() == expected, 'stream_validation_pin_hash')
    return decode(body)


def fingerprint(path):
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def run(plan_path, expected_plan_sha256, output):
    plan_path, output = Path(plan_path), Path(output)
    plan = pinned(plan_path, expected_plan_sha256)
    require(plan['schema'] == 'bounded-native-calibration-plan-1' and plan['feature_profile'] == PROFILE
            and plan['final_six_domain_acceptance'] is False and plan['reserved_final_scenarios_read'] is False
            and plan['model_selection_or_threshold_changes'] is False, 'stream_validation_scope')
    require(not output.exists() and not output.is_symlink(), 'fresh_stream_validation_output')
    output.mkdir(parents=True, mode=0o700)
    sources = {name: fingerprint(ROOT/name) for name in SOURCES}
    for model in plan['models'].values():
        pinned(ROOT/model['path'], model['sha256'])
    report = {'schema': 'extra-bounded-native-calibration-1', 'completed': False,
              'started_at': datetime.now(UTC).isoformat(), 'plan': fingerprint(plan_path), 'sources': sources,
              'free_before': shutil.disk_usage(output).free, 'scenarios': {}, 'models_refitted': False,
              'threshold_changed': False, 'labels_changed': False, 'goal_qualified': False,
              'original_six_domain_goal_replaced': False, 'independent_final_metrics': None,
              'paid_api_calls': 0, 'aws_sdk_calls': 0, 'github_pushes': 0}
    started = time.perf_counter()

    def save():
        (output/'run.json.part').write_bytes(canonical(report)+b'\n')
        (output/'run.json.part').replace(output/'run.json')

    save()
    try:
        for scenario in plan['scenarios']:
            name = scenario['name']
            require(name in {'russellmitchell', 'santos', 'fox'} and name not in report['scenarios'],
                    'stream_validation_scenario')
            reference = pinned(ROOT/scenario['reference_preparation'], scenario['reference_preparation_sha256'])
            require(reference['completed'] and reference.get('feature_profile', 'base') == scenario['reference_profile']
                    and reference['source_manifest_sha256'] == scenario['manifest_sha256'], 'stream_validation_reference')
            stage = report['scenarios'][name] = {'role': scenario['role'], 'completed': False, 'evaluations': {}}
            save()
            directory = output/name
            stage_started = time.perf_counter()
            preparation = prepare(ROOT/scenario['pairs_directory'], scenario['manifest_sha256'], directory, profile=PROFILE)
            stage['preparation_seconds'] = round(time.perf_counter()-stage_started, 3)
            require(sum(pair['rows'] for pair in preparation['pairs']) == scenario['rows'], 'stream_validation_rows')
            sidecars = all(preparation['files'][n] == reference['files'][n] for n in ('truth.jsonl', 'references.jsonl'))
            if scenario['reference_profile'] == 'base':
                inputs_match = preparation['streaming']['base_inputs'] == reference['files']['inputs.jsonl']
            else:
                inputs_match = preparation['files']['inputs.jsonl'] == reference['files']['inputs.jsonl']
            require(sidecars and inputs_match, 'stream_validation_equivalence')
            stage.update(preparation=fingerprint(directory/'preparation.json'), rows=scenario['rows'],
                         truth_and_references_identical=sidecars, reference_inputs_identical=inputs_match,
                         streaming=preparation['streaming'])
            save()
            for kind, model in plan['models'].items():
                evaluation_started = time.perf_counter()
                result = evaluate(directory, stage['preparation']['sha256'], ROOT/model['path'], model['sha256'],
                                  output/(name+'-'+kind), model_kind=kind)
                stage['evaluations'][kind] = {'receipt': fingerprint(output/(name+'-'+kind)/'evaluation.json'),
                                             'metrics': result['metrics'], 'per_pair': result['per_pair'],
                                             'seconds': round(time.perf_counter()-evaluation_started, 3),
                                             'model_unchanged': result['model_unchanged']}
                save()
                print(json.dumps({'stage': 'evaluated_frozen_model', 'scenario': name, 'kind': kind, 'metrics': result['metrics']}), flush=True)
            stage['completed'] = True
            save()
        require(all(fingerprint(ROOT/name) == entry for name, entry in sources.items()), 'stream_validation_source_changed')
        for model in plan['models'].values():
            pinned(ROOT/model['path'], model['sha256'])
        report['completed'] = True
    except (OSError, ValueError, KeyError, TypeError) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        report['elapsed_seconds'] = round(time.perf_counter()-started, 3)
        report['ended_at'] = datetime.now(UTC).isoformat()
        report['free_after'] = shutil.disk_usage(output).free
        save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, type=Path)
    parser.add_argument('--expected-plan-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = run(args.plan, args.expected_plan_sha256, args.output)
    print(json.dumps({'completed': result['completed'], 'elapsed_seconds': result['elapsed_seconds'], 'goal_qualified': False}))


if __name__ == '__main__':
    main()
