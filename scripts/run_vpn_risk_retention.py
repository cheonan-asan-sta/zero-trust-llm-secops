"""Frozen v40 Apache/VPN candidate plus strictly-past VPN risk retention."""

import argparse
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.operation_context import MAX_BYTES, MAX_EVENTS, canonical
from scripts.f1_lab.operation_refinement import load_operation_refinement
from scripts.f1_lab.raw_observations import raw_time
from scripts.f1_lab.vpn_risk_retention import LOOKBACK_SECONDS, RiskRetention, retained_contexts
from scripts.fit_native_raw import receipt
from scripts.run_operation_refinement import ROOT, compare, fingerprint, pinned, prepare_contexts


def prepare_retention(directory, preparation, contexts, vpn_model):
    manifest = pinned(directory/'audit.json', preparation['source_manifest_sha256'])
    result = dict(contexts)
    for index, pair in enumerate(manifest['pairs']):
        provenance = pair['provenance']
        if not provenance['raw_member'].endswith('/openvpn.log'):
            continue
        path = directory/f'pair-{index}-raw.source'
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_BYTES, 'retention_raw_file')
        sha, records, size = hashlib.sha256(), [], 0
        with path.open('rb') as stream:
            while body := stream.readline(MAX_ROW+1):
                size += len(body)
                require(len(body) <= MAX_ROW and size <= MAX_BYTES and len(records) < MAX_EVENTS, 'retention_raw_bound')
                sha.update(body)
                line = body.decode('utf-8', errors='replace')
                try:
                    moment = raw_time(line, provenance['simulation_start'], provenance['simulation_end'], source_timezone='UTC')
                except (ValueError, RecursionError):
                    moment = None
                records.append((len(records)+1, moment, line))
        require(sha.hexdigest() == provenance['raw_sha256'] and len(records) == preparation['pairs'][index]['rows'],
                'retention_raw_binding')
        extra = retained_contexts(records, sha.hexdigest(), vpn_model)
        require(all(contexts.get(key) == value.base for key, value in extra.items()), 'retention_base_alignment')
        result.update(extra)
    return result


def run(plan_path, expected_sha256, prior_path, prior_sha256, output):
    plan_path, output = Path(plan_path), Path(output)
    plan = pinned(plan_path, expected_sha256)
    prior = pinned(Path(prior_path), prior_sha256)
    require(plan['schema'] == 'f1-error-vpn-experiment-1' and plan['scope'] == 'observed development/calibration only'
            and prior['completed'], 'retention_plan_or_prior')
    require(not output.exists() and not output.is_symlink(), 'fresh_retention_output')
    output.mkdir(parents=True, mode=0o700)
    paths = ('scripts/f1_lab/operation_context.py', 'scripts/f1_lab/operation_refinement.py',
             'scripts/run_operation_refinement.py', 'scripts/f1_lab/vpn_risk_retention.py',
             'scripts/run_vpn_risk_retention.py', 'scripts/f1_lab/vpn_context.py')
    sources = {path: fingerprint(ROOT/path) for path in paths}
    report = {'schema': 'extra-causal-vpn-retention-comparison-1', 'completed': False,
              'started_at': datetime.now(UTC).isoformat(), 'sources': sources,
              'plan': fingerprint(plan_path), 'stateless_run': fingerprint(Path(prior_path)),
              'policy': {'lookback_seconds': LOOKBACK_SECONDS, 'alert_threshold': .95, 'review_threshold': .9,
                         'strict_past': True, 'equal_time_batch_withheld': True,
                         'scope': 'physical source plus exact logged IP:port; no verified identity',
                         'held_risk_refreshes_expiry': False},
              'scenarios': {}, 'goal_qualified': False, 'production_adopted': False,
              'automatic_enforcement_allowed': False, 'models_refitted': False, 'labels_changed': False,
              'paid_api_calls': 0, 'aws_sdk_calls': 0, 'github_pushes': 0}
    def save():
        (output/'run.json.part').write_bytes(canonical(report)+b'\n')
        (output/'run.json.part').replace(output/'run.json')
    started = time.perf_counter()
    save()
    try:
        specs = plan['models']
        policy_path = ROOT/prior['policy']['path']
        base = load_operation_refinement(policy_path, prior['policy']['sha256'],
            ROOT/specs['web']['path'], specs['web']['sha256'], ROOT/specs['heads']['path'], specs['heads']['sha256'],
            ROOT/specs['vpn']['path'], specs['vpn']['sha256'])
        model = RiskRetention(base)
        v39 = pinned(ROOT/plan['v39_run']['path'], plan['v39_run']['sha256'])
        for scenario in plan['scenarios']:
            name = scenario['name']
            require(name in {'russellmitchell', 'santos', 'fox'} and name not in report['scenarios'], 'retention_scenario')
            directory = ROOT/scenario['directory']
            preparation = receipt(directory, scenario['preparation_sha256'])
            contexts, source_report = prepare_contexts(ROOT/scenario['pairs_directory'], preparation)
            extended = prepare_retention(ROOT/scenario['pairs_directory'], preparation, contexts, model.vpn_model)
            result = compare(directory, preparation, extended, model, v39['scenarios'][name])
            result.update(sources=source_report, role=scenario['role'])
            result['stateless_metrics'] = prior['scenarios'][name]['metrics']
            report['scenarios'][name] = result
            save()
            print(json.dumps({'scenario': name, 'metrics': result['metrics']}), flush=True)
        require(all(fingerprint(ROOT/path) == value for path, value in sources.items()), 'retention_source_changed')
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
    print(json.dumps({'completed': result['completed'], 'goal_qualified': False}))


if __name__ == '__main__':
    main()
