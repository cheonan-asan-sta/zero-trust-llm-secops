"""Reproduce VPN precision hypotheses and reject any loss of existing TP."""

import argparse
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from scripts.f1_lab.line_truth import annotations
from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.operation_context import MAX_BYTES, MAX_EVENTS, canonical, core_features
from scripts.f1_lab.operation_refinement import load_operation_refinement
from scripts.f1_lab.raw_observations import raw_time
from scripts.f1_lab.raw_semantics import semantic_observations
from scripts.f1_lab.vpn_precision_audit import (
    THRESHOLDS,
    collision_bound,
    informational_declaration,
    metadata_candidate,
    paired_review,
    signature,
)
from scripts.f1_lab.vpn_risk_retention import RiskRetention, retained_contexts
from scripts.fit_native_raw import receipt
from scripts.run_operation_refinement import ROOT, fingerprint, pinned


def raw_records(directory, index, pair, prepared_pair):
    provenance = pair['provenance']
    require(provenance['raw_member'] == prepared_pair['raw_member']
            and provenance['raw_sha256'] == prepared_pair['raw_sha256'], 'precision_source_alignment')
    path = directory/f'pair-{index}-raw.source'
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_BYTES, 'precision_raw_file')
    records, sha, size, errors = [], hashlib.sha256(), 0, 0
    with path.open('rb') as stream:
        while body := stream.readline(MAX_ROW+1):
            size += len(body)
            require(len(body) <= MAX_ROW and size <= MAX_BYTES and len(records) < MAX_EVENTS, 'precision_raw_bound')
            sha.update(body)
            line = body.decode('utf-8', errors='replace')
            try:
                moment = raw_time(line, provenance['simulation_start'], provenance['simulation_end'], source_timezone='UTC')
            except (ValueError, RecursionError):
                moment = None
                errors += 1
            records.append((len(records)+1, moment, line))
    require(sha.hexdigest() == provenance['raw_sha256'] and len(records) == pair['raw_rows'] == prepared_pair['rows'],
            'precision_raw_binding')
    return records, errors


def compare_source(records, source_sha, model, label_path, label_sha, previous):
    # All inference finishes before the evaluator opens label payloads.
    contexts = retained_contexts(records, source_sha, model.vpn_model)
    by_ordinal = {c.base.ordinal: c for c in contexts.values()}
    observations, baselines = {}, {}
    for ordinal, _, line in records:
        context = by_ordinal[ordinal]
        features = {**core_features(line), **semantic_observations(line)}
        decision = model.decide(features, context.base.case_id, context)
        require(not decision.automatic_enforcement_allowed, 'precision_no_enforcement')
        observations[ordinal] = (context, decision.score,
            signature({**context.base.vpn_features, **semantic_observations(line)}, context,
                      informational_declaration(line)))
        baselines[context.base.case_id] = decision.baseline_score
    metadata = metadata_candidate(records, source_sha, model.vpn_model, baselines)
    gold, label_meta = annotations(label_path, label_sha)
    require(all(1 <= n <= len(records) for n in gold), 'precision_label_population')
    policies = ['metadata_only']+['threshold_'+str(t) for t in THRESHOLDS]
    rows = {name: [] for name in policies}
    score_sha = hashlib.sha256()
    for ordinal, _, _ in records:
        context, score, key = observations[ordinal]
        case_id = context.base.case_id
        score_sha.update(canonical({'case_id': case_id, 'score': score, 'metadata_score': metadata[case_id]})+b'\n')
        common = {'case_id': case_id, 'malicious': ordinal in gold, 'before': score >= .95, 'signature': key}
        rows['metadata_only'].append({**common, 'after': metadata[case_id] >= .95})
        for threshold in THRESHOLDS:
            rows['threshold_'+str(threshold)].append({**common, 'after': score >= threshold})
    results = {name: paired_review(value) for name, value in rows.items()}
    require(results['metadata_only']['before'] == previous, 'precision_v40b_metric_drift')
    return {'population': len(records), 'score_comparison_sequence_sha256': score_sha.hexdigest(),
            'label_metadata': label_meta, 'policies': results,
            'collision': collision_bound(rows['metadata_only']),
            'metadata_lost_tp_cases': [r['case_id'] for r in rows['metadata_only']
                                      if r['malicious'] and r['before'] and not r['after']],
            'selected': 'keep_v40b_no_recall_loss', 'selected_metrics': previous}


def run(plan_path, plan_sha, prior_path, prior_sha, output):
    plan_path, prior_path, output = Path(plan_path), Path(prior_path), Path(output)
    plan, prior = pinned(plan_path, plan_sha), pinned(prior_path, prior_sha)
    require(plan['schema'] == 'f1-error-vpn-experiment-1' and plan['scope'] == 'observed development/calibration only'
            and prior['completed'] and prior['plan']['sha256'] == plan_sha, 'precision_plan_contract')
    require(not output.exists() and not output.is_symlink(), 'fresh_precision_output')
    for name, expected in prior['sources'].items():
        require(fingerprint(ROOT/name) == expected, 'precision_baseline_source_drift')
    output.mkdir(parents=True, mode=0o700)
    own_paths = ('scripts/f1_lab/vpn_precision_audit.py', 'scripts/audit_vpn_precision.py')
    sources = {name: fingerprint(ROOT/name) for name in own_paths}
    report = {'schema': 'extra-vpn-precision-audit-1', 'completed': False,
        'started_at': datetime.now(UTC).isoformat(), 'scope': 'previously observed R/S/Fox VPN rows only',
        'plan': fingerprint(plan_path), 'prior': fingerprint(prior_path), 'sources': sources,
        'scenarios': {}, 'fp_reduction_achieved': False, 'selected_policy': 'keep_v40b',
        'production_adopted': False, 'goal_qualified': False, 'labels_changed': False,
        'models_refitted': False, 'automatic_enforcement_allowed': False,
        'paid_api_calls': 0, 'aws_sdk_calls': 0, 'github_pushes': 0}
    started = time.perf_counter()
    def save():
        (output/'run.json.part').write_bytes(canonical(report)+b'\n')
        (output/'run.json.part').replace(output/'run.json')
    save()
    try:
        stateless = pinned(ROOT/prior['stateless_run']['path'], prior['stateless_run']['sha256'])
        specs = plan['models']
        base = load_operation_refinement(ROOT/stateless['policy']['path'], stateless['policy']['sha256'],
            ROOT/specs['web']['path'], specs['web']['sha256'], ROOT/specs['heads']['path'], specs['heads']['sha256'],
            ROOT/specs['vpn']['path'], specs['vpn']['sha256'])
        model = RiskRetention(base)
        frozen = [fingerprint(ROOT/s['path']) for s in specs.values()]
        for scenario in plan['scenarios']:
            name = scenario['name']
            require(name in {'russellmitchell', 'santos', 'fox'} and name not in report['scenarios'], 'precision_scenario')
            preparation = receipt(ROOT/scenario['directory'], scenario['preparation_sha256'])
            directory = ROOT/scenario['pairs_directory']
            manifest = pinned(directory/'audit.json', preparation['source_manifest_sha256'])
            require(manifest['completed'] and len(manifest['pairs']) == len(preparation['pairs'])
                    and manifest['timestamp_basis'] == 'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
                    'precision_source_contract')
            indices = [i for i, p in enumerate(manifest['pairs']) if p['provenance']['raw_member'].endswith('/openvpn.log')]
            require(len(indices) == 1, 'precision_one_vpn_source')
            index = indices[0]
            pair = manifest['pairs'][index]
            provenance = pair['provenance']
            records, time_errors = raw_records(directory, index, pair, preparation['pairs'][index])
            previous = next(p['metrics']['alert'] for p in prior['scenarios'][name]['per_pair']
                            if p['raw_member'] == provenance['raw_member'])
            result = compare_source(records, provenance['raw_sha256'], model, directory/f'pair-{index}-labels.source',
                                    provenance['label_sha256'], previous)
            result.update(raw_member=provenance['raw_member'], raw_sha256=provenance['raw_sha256'],
                          label_sha256=provenance['label_sha256'], time_errors=time_errors)
            report['scenarios'][name] = result
            save()
            print(json.dumps({'scenario': name, 'metadata_changes': result['policies']['metadata_only']['changes'],
                              'mandatory_fp': result['collision']['mandatory_fp_if_all_baseline_tp_retained']}), flush=True)
        policy_names = next(iter(report['scenarios'].values()))['policies']
        eligible = []
        for policy in policy_names:
            values = [s['policies'][policy] for s in report['scenarios'].values()]
            if (all(not v['changes'].get('lost_true_positives') and v['after']['inference_errors'] == 0
                    and v['after']['fp'] <= v['before']['fp'] and v['after']['fn'] <= v['before']['fn'] for v in values)
                    and sum(v['after']['fp'] for v in values) < sum(v['before']['fp'] for v in values)):
                eligible.append(policy)
        report['eligible_policies_requiring_further_review'] = eligible
        require(all(fingerprint(ROOT/name) == expected for name, expected in sources.items()), 'precision_source_changed')
        require(frozen == [fingerprint(ROOT/s['path']) for s in specs.values()], 'precision_model_changed')
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
    parser.add_argument('--prior', required=True, type=Path)
    parser.add_argument('--expected-prior-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = run(args.plan, args.expected_plan_sha256, args.prior, args.expected_prior_sha256, args.output)
    print(json.dumps({'completed': result['completed'], 'fp_reduction_achieved': result['fp_reduction_achieved']}))


if __name__ == '__main__':
    main()
