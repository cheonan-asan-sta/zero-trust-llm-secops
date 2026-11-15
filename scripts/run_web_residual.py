"""Compare additive web evidence with frozen v40b on all observed physical rows."""

import argparse
import hashlib
import json
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision, load_operation_refinement
from scripts.f1_lab.raw_observations import raw_time
from scripts.f1_lab.vpn_risk_retention import RiskRetention
from scripts.f1_lab.web_residual import (
    MAX_BYTES,
    MAX_RECORDS,
    POLICY,
    WebResidualRefinement,
    build_evidence,
)
from scripts.fit_native_raw import receipt
from scripts.run_operation_refinement import ROOT, bound_rows, fingerprint, pinned, prepare_contexts
from scripts.run_vpn_risk_retention import prepare_retention


def prepare_web(directory, preparation):
    audit = pinned(directory/'audit.json', preparation['source_manifest_sha256'])
    require(audit['completed'] and len(audit['pairs']) == len(preparation['pairs'])
            and audit['timestamp_basis'] == 'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
            'web_residual_provenance')
    evidence, sources = {}, []
    for index, pair in enumerate(preparation['pairs']):
        member = pair['raw_member']
        kind = 'error' if '-error.' in member else 'access' if '-access.' in member else None
        if kind is None:
            continue
        provenance = audit['pairs'][index]['provenance']
        require(provenance['raw_member'] == member and provenance['raw_sha256'] == pair['raw_sha256'],
                'web_residual_raw_alignment')
        path = directory/f'pair-{index}-raw.source'
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_BYTES, 'web_residual_raw_file')
        sha, size, records, time_errors = hashlib.sha256(), 0, [], 0
        with path.open('rb') as stream:
            while body := stream.readline(MAX_ROW+1):
                size += len(body)
                require(len(body) <= MAX_ROW and size <= MAX_BYTES and len(records) < MAX_RECORDS,
                        'web_residual_read_bound')
                sha.update(body)
                line, moment = body.decode('utf-8', errors='replace'), None
                if kind == 'error':
                    try:
                        moment = raw_time(line, provenance['simulation_start'], provenance['simulation_end'], source_timezone='UTC')
                    except (ValueError, RecursionError):
                        time_errors += 1
                records.append((len(records)+1, moment, line))
        require(sha.hexdigest() == pair['raw_sha256'] and len(records) == pair['rows'], 'web_residual_raw_hash_or_rows')
        values = build_evidence(records, kind, sha.hexdigest())
        require(not evidence.keys() & values.keys(), 'web_residual_duplicate_evidence')
        evidence.update(values)
        sources.append({'raw_member': member, 'kind': kind, 'rows': len(records), 'raw_sha256': sha.hexdigest(),
                        'evidence_cases': len(values), 'time_errors': time_errors})
    return evidence, sources


def compare(directory, preparation, contexts, evidence, base, prior, error_stream):
    candidate = WebResidualRefinement(base.operation_model)
    totals = {key: counts() for key in ('before', 'after')}
    per_pair = [{key: counts() for key in totals} for _ in preparation['pairs']]
    cache, changes, reasons, review_changes = {}, Counter(), Counter(), Counter()
    reviews = {key: counts() for key in ('before', 'after')}
    nonweb = {key: hashlib.sha256() for key in totals}
    count = web_rows = 0
    for index, case_id, features, truth in bound_rows(directory, preparation):
        pair = preparation['pairs'][index]
        is_web = '-access.' in pair['raw_member'] or '-error.' in pair['raw_member']
        key = canonical(features)
        if key not in cache:
            require(len(cache) < 100000, 'web_residual_vector_bound')
            try:
                cache[key] = base.web_model.probability(features)
            except ValueError:
                cache[key] = None
        score = cache[key]
        if score is None:
            old = new = None
            value = updated = None
        else:
            value = (base.decide(features, case_id, contexts[case_id]) if case_id in contexts
                     else OperationDecision(score, score, score >= .95, score >= .95, 'untargeted_unchanged'))
            updated = candidate.refine(value, features, case_id, evidence.get(case_id))
            require(updated.score >= value.score and (not value.alert or updated.alert)
                    and (not value.review or updated.review) and not updated.automatic_enforcement_allowed,
                    'web_residual_monotonicity')
            old, new = value.alert, updated.alert
            if not is_web:
                require(value == updated, 'web_residual_nonweb_changed')
        count += 1
        web_rows += is_web
        for name, prediction in (('before', old), ('after', new)):
            record(totals[name], truth, prediction)
            record(per_pair[index][name], truth, prediction)
            if not is_web:
                decision = value if name == 'before' else updated
                nonweb[name].update(canonical({'case_id': case_id, 'score': decision.score if decision else None,
                    'alert': prediction, 'review': decision.review if decision else None})+b'\n')
        for name, decision in (('before', value), ('after', updated)):
            record(reviews[name], truth, decision.review if decision else None)
        review_added = value is not None and not value.review and updated.review
        if review_added:
            review_changes['publisher_threat_review_added' if truth else 'publisher_normal_review_added'] += 1
        if old != new:
            changes['new_tp' if truth and new else 'introduced_fp' if new else 'lost_tp' if truth else 'removed_fp'] += 1
            reasons[updated.reason] += 1
        if is_web and (old != truth or new != truth or old != new or review_added):
            error_stream.write(canonical({'case_id': case_id, 'raw_member': pair['raw_member'],
                'source_sha256': pair['raw_sha256'], 'features_sha256': hashlib.sha256(key).hexdigest(),
                'publisher_malicious': truth, 'before_alert': old, 'after_alert': new,
                'before_score': value.score if value else None, 'after_score': updated.score if updated else None,
                'before_review': value.review if value else None, 'after_review': updated.review if updated else None,
                'reason': updated.reason if updated else 'inference_error',
                'label_status': 'publisher label retained; independent adjudication pending'})+b'\n')
    require(metrics(totals['before']) == prior['metrics']['alert'], 'web_residual_prior_total_drift')
    for group, expected in zip(per_pair, prior['per_pair'], strict=True):
        require(metrics(group['before']) == expected['metrics']['alert'], 'web_residual_prior_pair_drift')
    require(nonweb['before'].hexdigest() == nonweb['after'].hexdigest(), 'web_residual_nonweb_hash_drift')
    return {'population': count, 'web_rows': web_rows, 'metrics': {k: metrics(v) for k, v in totals.items()},
        'per_pair': [{'raw_member': p['raw_member'], 'metrics': {k: metrics(v) for k, v in g.items()}}
                     for p, g in zip(preparation['pairs'], per_pair, strict=True)],
        'changes': dict(changes), 'change_reasons': dict(reasons), 'review_changes': dict(review_changes),
        'review_metrics_separate_from_alert': {k: metrics(v) for k, v in reviews.items()},
        'nonweb_decision_sha256': {k: v.hexdigest() for k, v in nonweb.items()}}


def run(plan_path, expected_sha256, output):
    plan_path, output = Path(plan_path), Path(output)
    plan = pinned(plan_path, expected_sha256)
    require(plan['schema'] == 'f1-web-residual-experiment-1' and plan['policy'] == POLICY
            and plan['scope'] == 'previously observed development only', 'web_residual_plan')
    require(not output.exists() and not output.is_symlink(), 'web_residual_fresh_output')
    operation = pinned(ROOT/plan['operation_plan']['path'], plan['operation_plan']['sha256'])
    prior = pinned(ROOT/plan['prior_run']['path'], plan['prior_run']['sha256'])
    stateless = pinned(ROOT/plan['stateless_run']['path'], plan['stateless_run']['sha256'])
    require(prior['completed'] and stateless['completed'] and operation['scope'] == 'observed development/calibration only',
            'web_residual_prior_complete')
    specs = operation['models']
    base = load_operation_refinement(ROOT/stateless['policy']['path'], stateless['policy']['sha256'],
        ROOT/specs['web']['path'], specs['web']['sha256'], ROOT/specs['heads']['path'], specs['heads']['sha256'],
        ROOT/specs['vpn']['path'], specs['vpn']['sha256'])
    model = RiskRetention(base)
    paths = ('scripts/f1_lab/web_residual.py', 'scripts/run_web_residual.py',
             'scripts/f1_lab/web_refinement.py', 'scripts/f1_lab/operation_context.py',
             'scripts/f1_lab/operation_refinement.py', 'scripts/f1_lab/vpn_risk_retention.py',
             'scripts/run_operation_refinement.py', 'scripts/run_vpn_risk_retention.py')
    sources = {name: fingerprint(ROOT/name) for name in paths}
    output.mkdir(parents=True)
    report = {'schema': 'extra-web-residual-comparison-1', 'completed': False, 'started_at': datetime.now(UTC).isoformat(),
        'plan': fingerprint(plan_path), 'sources': sources, 'scenarios': {}, 'policy': POLICY,
        'goal_qualified': False, 'independent_evaluation': False, 'production_adopted': False,
        'models_refitted': False, 'labels_changed': False, 'automatic_enforcement_allowed': False,
        'paid_api_calls': 0, 'aws_sdk_calls': 0, 'github_pushes': 0}
    def save():
        (output/'run.json.part').write_bytes(canonical(report)+b'\n')
        (output/'run.json.part').replace(output/'run.json')
    started = time.perf_counter()
    save()
    try:
        for scenario in operation['scenarios']:
            name = scenario['name']
            require(name in {'russellmitchell', 'santos', 'fox'} and name not in report['scenarios'], 'web_residual_scenario')
            directory, raw_directory = ROOT/scenario['directory'], ROOT/scenario['pairs_directory']
            preparation = receipt(directory, scenario['preparation_sha256'])
            contexts, _ = prepare_contexts(raw_directory, preparation)
            contexts = prepare_retention(raw_directory, preparation, contexts, model.vpn_model)
            evidence, raw_sources = prepare_web(raw_directory, preparation)
            errors_path = output/(name+'-web-errors.jsonl')
            with errors_path.open('wb') as errors:
                result = compare(directory, preparation, contexts, evidence, model, prior['scenarios'][name], errors)
            result.update(sources=raw_sources, error_inventory=fingerprint(errors_path), role='observed_development')
            report['scenarios'][name] = result
            save()
            print(json.dumps({'scenario': name, 'population': result['population'], 'changes': result['changes']}), flush=True)
        require(all(fingerprint(ROOT/name) == pin for name, pin in sources.items()), 'web_residual_sources_changed')
        require(pinned(plan_path, expected_sha256) == plan, 'web_residual_plan_changed')
        require(all(hashlib.sha256((ROOT/s['path']).read_bytes()).hexdigest() == s['sha256'] for s in specs.values()),
                'web_residual_models_changed')
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
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--expected-plan-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.plan, args.expected_plan_sha256, args.output)


if __name__ == '__main__':
    main()
