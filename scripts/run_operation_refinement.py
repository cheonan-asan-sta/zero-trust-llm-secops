"""Source-bound Apache warning and VPN-history comparison against frozen v39."""

import argparse
import hashlib
import json
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import MAX_BYTES, MAX_EVENTS, bound_contexts, canonical
from scripts.f1_lab.operation_refinement import POLICY, load_operation_refinement
from scripts.f1_lab.raw_observations import raw_time
from scripts.fit_native_raw import receipt

ROOT = Path(__file__).resolve().parents[1]


def pinned(path, sha):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 2*1024**2, 'operation_manifest_file')
    body = path.read_bytes()
    require(hashlib.sha256(body).hexdigest() == sha, 'operation_manifest_hash')
    return decode(body)


def fingerprint(path):
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def prepare_contexts(directory, preparation):
    manifest = pinned(directory/'audit.json', preparation['source_manifest_sha256'])
    require(manifest['completed'] and len(manifest['pairs']) == len(preparation['pairs'])
            and manifest['timestamp_basis'] == 'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
            'operation_source_contract')
    contexts, sources = {}, []
    for index, pair in enumerate(manifest['pairs']):
        provenance = pair['provenance']
        prior = preparation['pairs'][index]
        require(prior['raw_sha256'] == provenance['raw_sha256'] and prior['raw_member'] == provenance['raw_member'],
                'operation_source_alignment')
        member = provenance['raw_member']
        kind = 'vpn' if member.endswith('/openvpn.log') else 'apache_error' if '-error.' in member else None
        if kind is None:
            continue
        path = directory/f'pair-{index}-raw.source'
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_BYTES, 'operation_raw_file')
        sha, records, size, time_errors = hashlib.sha256(), [], 0, 0
        with path.open('rb') as stream:
            while body := stream.readline(MAX_ROW+1):
                size += len(body)
                require(len(body) <= MAX_ROW and size <= MAX_BYTES and len(records) < MAX_EVENTS, 'operation_raw_bound')
                sha.update(body)
                line = body.decode('utf-8', errors='replace')
                try:
                    moment = raw_time(line, provenance['simulation_start'], provenance['simulation_end'], source_timezone='UTC')
                except (ValueError, RecursionError):
                    moment = None
                    time_errors += 1
                records.append((len(records)+1, moment, line))
        require(sha.hexdigest() == provenance['raw_sha256'] and len(records) == pair['raw_rows'] == prior['rows'],
                'operation_raw_hash_or_rows')
        values = bound_contexts(records, kind, sha.hexdigest())
        require(not contexts.keys() & values.keys(), 'operation_context_case_collision')
        contexts.update(values)
        features = hashlib.sha256()
        if kind == 'vpn':
            for case in values.values():
                features.update(canonical(case.vpn_features)+b'\n')
        sources.append({'raw_member': member, 'kind': kind, 'rows': len(records), 'raw_sha256': sha.hexdigest(),
                        'time_errors': time_errors, 'vpn_feature_sequence_sha256': features.hexdigest() if kind == 'vpn' else None})
    return contexts, sources


def bound_rows(directory, preparation):
    files = [directory/name for name in ('inputs.jsonl', 'truth.jsonl')]
    for path in files:
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == preparation['files'][path.name]['bytes'],
                'operation_prepared_file')
    hashes = [hashlib.sha256(), hashlib.sha256()]
    index, within, total = 0, 0, 0
    with files[0].open('rb') as inputs, files[1].open('rb') as truth:
        while body := inputs.readline(MAX_ROW+1):
            gold = truth.readline(MAX_ROW+1)
            require(0 < len(body) <= MAX_ROW and 0 < len(gold) <= MAX_ROW, 'operation_join_row_bound')
            hashes[0].update(body)
            hashes[1].update(gold)
            row, target = decode(body), decode(gold)
            require(set(row) == {'case_id', 'features', 'observation_error'}
                    and set(target) == {'case_id', 'malicious', 'attack_labels'}
                    and type(target['malicious']) is bool and index < len(preparation['pairs']), 'operation_join_schema')
            pair = preparation['pairs'][index]
            expected = hashlib.sha256((pair['raw_sha256']+':'+str(within+1)).encode()).hexdigest()
            require(row['case_id'] == target['case_id'] == expected, 'operation_raw_case_binding')
            total += 1
            yield index, row['case_id'], row['features'], target['malicious']
            within += 1
            if within == pair['rows']:
                index += 1
                within = 0
        require(not truth.read(1) and index == len(preparation['pairs']) and within == 0, 'operation_join_population')
    require(all(sha.hexdigest() == preparation['files'][path.name]['sha256'] for sha, path in zip(hashes, files, strict=True))
            and total == sum(pair['rows'] for pair in preparation['pairs']), 'operation_prepared_hash_or_rows')


def compare(directory, preparation, contexts, model, previous):
    totals = {key: counts() for key in ('baseline', 'alert', 'review')}
    groups = [{key: counts() for key in totals} for _ in preparation['pairs']]
    changes = [Counter() for _ in groups]
    cache, reasons, old_sha = {}, Counter(), hashlib.sha256()
    count = unchanged = 0
    before = canonical(model.web_model.export())
    before_vpn = canonical(model.vpn_model.export())
    for index, case_id, features, truth in bound_rows(directory, preparation):
        key = canonical(features)
        if key not in cache:
            require(len(cache) < 100000, 'operation_vector_bound')
            try:
                cache[key] = model.web_model.probability(features)
            except ValueError:
                cache[key] = None
        baseline = cache[key]
        context = contexts.get(case_id)
        if baseline is None:
            alerts = {'baseline': None, 'alert': None, 'review': None}
            reason = 'baseline_inference_error'
        elif context is None:
            alerts = dict.fromkeys(totals, baseline >= .95)
            reason = 'untargeted_unchanged'
            unchanged += 1
        else:
            value = model.decide(features, case_id, context)
            require(value.baseline_score == baseline and not value.automatic_enforcement_allowed, 'operation_baseline_or_scope_drift')
            alerts = {'baseline': baseline >= .95, 'alert': value.alert, 'review': value.review}
            reason = value.reason
        reasons[reason] += 1
        count += 1
        old_sha.update(canonical({'ordinal': count, 'probability': baseline})+b'\n')
        for kind, prediction in alerts.items():
            record(totals[kind], truth, prediction)
            record(groups[index][kind], truth, prediction)
        for kind in ('alert', 'review'):
            a, b = alerts['baseline'], alerts[kind]
            if a is True and b is False:
                changes[index][kind+('_lost_tp' if truth else '_removed_fp')] += 1
            if a is False and b is True:
                changes[index][kind+('_new_tp' if truth else '_introduced_fp')] += 1
    require(old_sha.hexdigest() == previous['refined_probability_sha256'], 'operation_v39_score_drift')
    require(metrics(totals['baseline']) == previous['metrics']['0.95']['refined'], 'operation_v39_metric_drift')
    require(canonical(model.web_model.export()) == before and canonical(model.vpn_model.export()) == before_vpn,
            'operation_models_changed')
    return {'population': count, 'metrics': {key: metrics(value) for key, value in totals.items()},
            'per_pair': [{'raw_member': pair['raw_member'], 'metrics': {key: metrics(value) for key, value in group.items()},
                          'changes': dict(change)} for pair, group, change in zip(preparation['pairs'], groups, changes, strict=True)],
            'baseline_probability_sha256': old_sha.hexdigest(), 'reason_counts': dict(reasons),
            'untargeted_rows_verified_unchanged': unchanged, 'context_rows': len(contexts)}


def run(plan_path, expected_plan_sha256, output):
    plan_path, output = Path(plan_path), Path(output)
    plan = pinned(plan_path, expected_plan_sha256)
    require(plan['schema'] == 'f1-error-vpn-experiment-1' and plan['scope'] == 'observed development/calibration only', 'operation_plan_scope')
    require(not output.exists() and not output.is_symlink(), 'fresh_operation_output')
    output.mkdir(parents=True, mode=0o700)
    paths = ('scripts/f1_lab/operation_context.py', 'scripts/f1_lab/operation_refinement.py', 'scripts/run_operation_refinement.py')
    sources = {path: fingerprint(ROOT/path) for path in paths}
    report = {'schema': 'extra-error-vpn-comparison-1', 'completed': False, 'started_at': datetime.now(UTC).isoformat(),
              'plan': fingerprint(plan_path), 'sources': sources, 'scenarios': {}, 'goal_qualified': False,
              'production_adopted': False, 'automatic_enforcement_allowed': False, 'labels_changed': False,
              'models_refitted': False, 'paid_api_calls': 0, 'aws_sdk_calls': 0, 'github_pushes': 0}
    def save():
        (output/'run.json.part').write_bytes(canonical(report)+b'\n')
        (output/'run.json.part').replace(output/'run.json')
    started = time.perf_counter()
    save()
    try:
        specs = plan['models']
        policy = {**POLICY, **{name+'_model_sha256': specs[name]['sha256'] for name in ('web', 'heads', 'vpn')}}
        (output/'policy.json').write_bytes(canonical(policy)+b'\n')
        report['policy'] = fingerprint(output/'policy.json')
        model = load_operation_refinement(output/'policy.json', report['policy']['sha256'],
            ROOT/specs['web']['path'], specs['web']['sha256'], ROOT/specs['heads']['path'], specs['heads']['sha256'],
            ROOT/specs['vpn']['path'], specs['vpn']['sha256'])
        prior = pinned(ROOT/plan['v39_run']['path'], plan['v39_run']['sha256'])
        require(prior['completed'], 'operation_v39_incomplete')
        for scenario in plan['scenarios']:
            name = scenario['name']
            require(name in {'russellmitchell', 'santos', 'fox'} and name not in report['scenarios'], 'operation_scenario')
            directory = ROOT/scenario['directory']
            preparation = receipt(directory, scenario['preparation_sha256'])
            contexts, source_report = prepare_contexts(ROOT/scenario['pairs_directory'], preparation)
            result = compare(directory, preparation, contexts, model, prior['scenarios'][name])
            result.update(sources=source_report, role=scenario['role'])
            report['scenarios'][name] = result
            save()
            print(json.dumps({'scenario': name, 'targets': [p for p in result['per_pair'] if '-error.' in p['raw_member'] or p['raw_member'].endswith('/openvpn.log')]}), flush=True)
        require(all(fingerprint(ROOT/path) == value for path, value in sources.items()), 'operation_source_changed')
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
    print(json.dumps({'completed': result['completed'], 'goal_qualified': False}))


if __name__ == '__main__':
    main()
