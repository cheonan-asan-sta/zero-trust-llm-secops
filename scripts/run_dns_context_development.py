"""Observed DNS development experiment with a Russell-only fixed tree and paired replay."""

import argparse
import hashlib
from pathlib import Path

from app.config import get_settings
from scripts.f1_lab.dns_context import PROFILE, DNSWindow
from scripts.f1_lab.native_binary_tree import NativeBinaryTree
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.raw_observations import raw_time
from scripts.f1_lab.transfer_evaluation import observations, score, sha, source_pins

ROOT = Path(__file__).resolve().parents[1]
CONFIG = {'profile': PROFILE, 'max_depth': 8, 'min_leaf': 5, 'class_balanced': False}
THRESHOLD = .95


def rows(path):
    with Path(path).open('rb') as stream:
        while body := stream.readline(MAX_ROW+1):
            require(len(body) <= MAX_ROW, 'dns_replay_row_bound')
            yield decode(body)


def extract(spec, output):
    """Read original observations/raw/previous predictions, never truth here."""
    prepared, raw_directory = Path(spec['prepared']), Path(spec['raw_directory'])
    require(sha(prepared/'preparation.json') == spec['preparation_sha256'], 'dns_preparation_hash')
    preparation = decode((prepared/'preparation.json').read_bytes())
    require(sha(raw_directory/'audit.json') == preparation['source_manifest_sha256'], 'dns_raw_manifest_hash')
    audit = decode((raw_directory/'audit.json').read_bytes())
    require(audit['completed'] is True and audit['timestamp_basis'] ==
        'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check', 'dns_timezone_contract')
    indices = [i for i, p in enumerate(preparation['pairs']) if p['raw_member'].endswith('/dnsmasq.log')]
    require(len(indices) == 1, 'dns_one_physical_source')
    index = indices[0]
    pair, provenance = preparation['pairs'][index], audit['pairs'][index]['provenance']
    require(pair['raw_member'] == provenance['raw_member'] and pair['raw_sha256'] == provenance['raw_sha256']
            and 0 < pair['rows'] <= 1000000, 'dns_source_alignment')
    raw_path, baseline = raw_directory/f'pair-{index}-raw.source', Path(spec['baseline'])
    require(sha(raw_path, 256*1024**2) == pair['raw_sha256']
            and sha(baseline) == spec['baseline_sha256'], 'dns_raw_or_baseline_hash')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    destination = output/'inputs.jsonl'
    window, ordinal, errors, syntax, timed = DNSWindow(), 0, 0, 0, 0
    with raw_path.open('rb') as raw, baseline.open('rb') as previous, destination.open('xb') as target:
        for source_index, row in observations(prepared, preparation):
            body = previous.readline(MAX_ROW+1)
            require(0 < len(body) <= MAX_ROW, 'dns_previous_row')
            prior = decode(body)
            require(prior['case_id'] == row['case_id'] and prior['source_index'] == source_index, 'dns_previous_alignment')
            if source_index != index:
                continue
            ordinal += 1
            line_bytes = raw.readline(MAX_ROW+1)
            require(0 < len(line_bytes) <= MAX_ROW and row['case_id'] ==
                    hashlib.sha256((pair['raw_sha256']+':'+str(ordinal)).encode()).hexdigest(), 'dns_raw_row_binding')
            line = line_bytes.decode('utf8', errors='replace')
            try:
                moment = raw_time(line, provenance['simulation_start'], provenance['simulation_end'], source_timezone='UTC')
            except (ValueError, RecursionError):
                moment = None
            facts = window.observe(line, moment)
            syntax += facts['dns_semantic_available']
            timed += facts['dns_query_window_available']
            error = row['observation_error'] or prior['error']
            features = {**row['features'], **facts} if row['features'] is not None and error is None else None
            errors += error is not None or features is None
            target.write(canonical({'case_id': row['case_id'], 'source_index': index, 'features': features,
                'before': prior['after'], 'before_score': prior['after_score'], 'error': error})+b'\n')
        require(not previous.read(1) and not raw.read(1) and ordinal == pair['rows'], 'dns_extract_population')
    require(sha(raw_path) == pair['raw_sha256'] and sha(baseline) == spec['baseline_sha256'], 'dns_extract_inputs_changed')
    result = {'population': ordinal, 'inputs_sha256': sha(destination), 'observation_errors': errors,
        'syntax_available': syntax, 'query_window_available': timed, 'source_index': index,
        'first_global_row': 1+sum(p['rows'] for p in preparation['pairs'][:index]),
        'raw_sha256': pair['raw_sha256'], 'labels_opened_by_extractor': False}
    (output/'extraction.json').write_bytes(canonical(result)+b'\n')
    require(syntax > 0 and timed > 0, 'dns_source_format_no_usable_observations')
    return result


def truth_subset(spec, extracted, directory):
    prepared, directory = Path(spec['prepared']), Path(directory)
    preparation = decode((prepared/'preparation.json').read_bytes())
    original = prepared/'truth.jsonl'
    require(sha(original) == preparation['files']['truth.jsonl']['sha256'], 'dns_truth_hash')
    require(sha(directory/'inputs.jsonl') == extracted['inputs_sha256'], 'dns_truth_inputs_hash')
    result = directory/'truth.jsonl'
    count = 0
    with result.open('xb') as target:
        selected = iter(rows(directory/'inputs.jsonl'))
        for ordinal, gold in enumerate(rows(original), 1):
            if not extracted['first_global_row'] <= ordinal < extracted['first_global_row']+extracted['population']:
                continue
            row = next(selected)
            require(gold['case_id'] == row['case_id'] and type(gold['malicious']) is bool, 'dns_truth_alignment')
            target.write(canonical({'case_id': gold['case_id'], 'malicious': gold['malicious']})+b'\n')
            count += 1
        require(next(selected, None) is None and count == extracted['population'], 'dns_truth_population')
    require(sha(original) == preparation['files']['truth.jsonl']['sha256'], 'dns_truth_changed')
    return sha(result)


def fit(directory, inputs_sha256, truth_sha256):
    directory = Path(directory)
    require(sha(directory/'inputs.jsonl') == inputs_sha256 and sha(directory/'truth.jsonl') == truth_sha256,
            'dns_training_hash')
    tree = NativeBinaryTree(**CONFIG)
    for row, gold in zip(rows(directory/'inputs.jsonl'), rows(directory/'truth.jsonl'), strict=True):
        require(row['case_id'] == gold['case_id'] and row['features'] is not None and row['error'] is None,
                'dns_training_binding_or_error')
        tree.observe_training(row['features'], gold['malicious'])
    tree.fit()
    require(sha(directory/'inputs.jsonl') == inputs_sha256 and sha(directory/'truth.jsonl') == truth_sha256,
            'dns_training_changed')
    return tree


def predict(inputs, expected_sha256, tree, destination):
    require(sha(inputs) == expected_sha256, 'dns_predict_input_hash')
    frozen = canonical(tree.export())
    destination = Path(destination)
    total = errors = 0
    cache = {}
    with destination.open('xb') as target:
        for row in rows(inputs):
            before, probability, error = row['before'], row['before_score'], row['error']
            after, reason = before, 'dns_baseline_retained'
            try:
                require(type(before) is bool and row['features'] is not None and error is None, 'dns_prior_unavailable')
                if row['features']['dns_semantic_available']:
                    key = canonical(row['features'])
                    if key not in cache:
                        require(len(cache) < 100000, 'dns_prediction_vector_bound')
                        cache[key] = tree.probability(row['features'])
                    if cache[key] >= THRESHOLD:
                        after, probability, reason = True, max(probability, cache[key]), 'dns_context_additive_risk'
                require(not before or after, 'dns_existing_alert_lost')
            except (ValueError, TypeError, KeyError, RecursionError):
                after, probability, error, reason = None, None, 'dns_inference_error', 'dns_inference_error'
            errors += error is not None
            total += 1
            target.write(canonical({'case_id': row['case_id'], 'source_index': row['source_index'],
                'before': before, 'after': after, 'before_score': row['before_score'], 'after_score': probability,
                'reason': reason, 'error': error})+b'\n')
    require(sha(inputs) == expected_sha256 and canonical(tree.export()) == frozen, 'dns_prediction_changed')
    return {'population': total, 'inference_errors': errors, 'predictions_sha256': sha(destination),
            'labels_opened_by_predictor': False, 'automatic_enforcement_allowed': False}


def run(plan_path, expected_sha256, output):
    require(get_settings().app_environment in {'local', 'test'}, 'dns_development_local_only')
    require(sha(plan_path) == expected_sha256, 'dns_plan_hash')
    plan = decode(Path(plan_path).read_bytes())
    require(plan['scope'] == 'observed_development_only' and plan['goal_qualified'] is False
            and plan['training_source'] == 'russellmitchell' and plan['configuration'] == CONFIG
            and plan['threshold'] == THRESHOLD
            and [spec['name'] for spec in plan['scenarios']] == ['russellmitchell', 'santos', 'fox'], 'dns_fixed_plan')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    pins = source_pins(ROOT)
    report = {'completed': False, 'goal_qualified': False, 'scope': plan['scope'], 'training_source': plan['training_source'],
        'source_pins': pins, 'plan_sha256': expected_sha256, 'configuration': CONFIG, 'threshold': THRESHOLD,
        'scenarios': {}, 'paid_api_calls': 0, 'aws_calls': 0, 'production_adopted': False, 'labels_changed': False}
    (output/'plan.json').write_bytes(canonical(plan)+b'\n')
    tree = None
    try:
        for spec in plan['scenarios']:
            name, directory = spec['name'], output/spec['name']
            extracted = extract(spec, directory)
            truth_hash = None
            if tree is None:
                truth_hash = truth_subset(spec, extracted, directory)
                tree = fit(directory, extracted['inputs_sha256'], truth_hash)
                (output/'model.json').write_bytes(canonical(tree.export())+b'\n')
                tree = NativeBinaryTree.restore(decode((output/'model.json').read_bytes()))
                report['model_sha256'] = sha(output/'model.json')
            prediction = predict(directory/'inputs.jsonl', extracted['inputs_sha256'], tree, directory/'predictions.jsonl')
            (directory/'prediction-manifest.json').write_bytes(canonical(prediction)+b'\n')
            if truth_hash is None:
                truth_hash = truth_subset(spec, extracted, directory)
            result = score(directory/'predictions.jsonl', directory/'truth.jsonl', prediction['predictions_sha256'], truth_hash)
            require(result['metrics']['before'] == spec['baseline_dns_metrics'], 'dns_previous_score_drift')
            report['scenarios'][name] = {**result, 'extraction': extracted, 'prediction': prediction,
                'role': 'training_replay' if name == plan['training_source'] else 'observed_development_comparison'}
            (output/'run.json').write_bytes(canonical(report)+b'\n')
            print(canonical({'scenario': name, 'changes': result['changes'], 'after': result['metrics']['after']}).decode(), flush=True)
        require(source_pins(ROOT) == pins and sha(output/'model.json') == report['model_sha256'], 'dns_sources_or_model_changed')
        report['candidate_development_gate_passed'] = all(
            value['changes']['introduced_fp'] == value['changes']['lost_tp'] == value['prediction']['inference_errors'] == 0
            for value in report['scenarios'].values()) and sum(value['changes']['new_tp'] for value in report['scenarios'].values()) > 0
        report['completed'] = True
    finally:
        (output/'run.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--expected-plan-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.plan, args.expected_plan_sha256, args.output)


if __name__ == '__main__':
    main()
