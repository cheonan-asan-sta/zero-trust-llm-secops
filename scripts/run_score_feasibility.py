"""Audit all thresholds of sealed, already observed scores without changing them."""

import argparse
import hashlib
import os
import re
from datetime import UTC, datetime
from itertools import zip_longest
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.score_feasibility import MAX_ROWS, ScoreAudit
from scripts.f1_lab.transfer_evaluation import sha, source_pins

ROOT = Path(__file__).resolve().parents[1]
ROLES = {'russellmitchell': 'observed_training_development', 'santos': 'observed_development',
         'fox': 'predeclared_calibration', 'harrison_observed': 'previously_evaluated_now_observed'}


def kind(member):
    require(type(member) is str and 1 <= len(member) <= 4096, 'score_audit_member')
    if '/internal_share/logs/audit/' in member:
        return 'audit-share'
    if '/intranet_server/logs/audit/' in member:
        return 'audit-web'
    for suffix, name in [('auth.log', 'auth'), ('dnsmasq.log', 'dns'), ('openvpn.log', 'vpn')]:
        if re.search(r'/'+re.escape(suffix)+r'(?:\.\d+)?(?:\.gz)?$', member):
            return name
    for text, name in [('-access.log', 'web-access'), ('-error.log', 'web-error'), ('-system.cpu.log', 'cpu')]:
        if text in member:
            return name
    raise ValueError('native_source_score_audit_unknown_member')


def rows(path):
    with Path(path).open('rb') as stream:
        while raw := stream.readline(MAX_ROW+1):
            require(len(raw) <= MAX_ROW, 'score_audit_line_bound')
            yield decode(raw)


def same_counts(observed, expected):
    require(all(observed[key] == expected[key] for key in ('tp', 'fp', 'fn', 'tn', 'inference_errors', 'population')),
            'score_audit_original_matrix')


def run(plan_path, expected_plan_sha256, output):
    require(sha(plan_path, 256*1024) == expected_plan_sha256, 'score_audit_plan_pin')
    plan = decode(Path(plan_path).read_bytes())
    require(plan['schema'] == 'frozen-score-diagnostic-plan-1' and plan['scope'] == 'observed_development_only'
            and plan['goal_qualified'] is False and plan['threshold_changes_allowed'] is False
            and [s['name'] for s in plan['scenarios']] == list(ROLES), 'score_audit_plan_contract')
    require(all(type(s['population']) is int and s['population'] > 0 for s in plan['scenarios'])
            and sum(s['population'] for s in plan['scenarios']) <= MAX_ROWS, 'score_audit_global_population')
    prior_path = Path(plan['prior'])
    require(sha(prior_path, 4*1024**2) == plan['prior_sha256'], 'score_audit_prior_pin')
    prior = decode(prior_path.read_bytes())
    require(prior['completed'] is True and prior['goal_qualified'] is False
            and prior['schema'] == 'apparmor-noop-development-result-1'
            and prior['scope'] == 'observed_development_only', 'score_audit_prior_contract')
    pins = source_pins(ROOT)
    inputs, preparations = {Path(plan_path): expected_plan_sha256, prior_path: plan['prior_sha256']}, {}
    for spec in plan['scenarios']:
        name = spec['name']
        require(spec['role'] == ROLES[name] and type(spec['population']) is int
                and 0 < spec['population'] <= MAX_ROWS, 'score_audit_role_or_population')
        preparation_path = Path(spec['preparation'])
        require(sha(preparation_path, 4*1024**2) == spec['preparation_sha256'], 'score_audit_preparation_pin')
        prepared = decode(preparation_path.read_bytes())
        require(prepared['completed'] is True and prepared['goal_qualified'] is False,
                'score_audit_preparation_contract')
        require(0 < len(prepared['pairs']) <= 1000 and all(type(p['rows']) is int and 0 < p['rows'] <= MAX_ROWS
                and re.fullmatch('[a-f0-9]{64}', p['raw_sha256']) for p in prepared['pairs'])
                and sum(p['rows'] for p in prepared['pairs']) == spec['population'], 'score_audit_source_population')
        for pair in prepared['pairs']:
            kind(pair['raw_member'])
        require(Path(spec['truth']) == preparation_path.parent/'truth.jsonl'
                and spec['truth_sha256'] == prepared['files']['truth.jsonl']['sha256']
                and spec['prediction_sha256'] == prior['scenarios'][name]['prediction']['predictions_sha256']
                and spec['population'] == prior['scenarios'][name]['population'], 'score_audit_input_binding')
        inputs.update({preparation_path: spec['preparation_sha256'], Path(spec['truth']): spec['truth_sha256'],
                       Path(spec['prediction']): spec['prediction_sha256']})
        preparations[name] = prepared
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    (output/'plan.json').write_bytes(canonical(plan)+b'\n')
    report = {'schema': 'frozen-score-feasibility-diagnostic-1', 'completed': False,
              'scope': 'observed_development_only', 'goal_qualified': False,
              'new_independent_evaluation': False, 'independent_human_review': False,
              'labels_reopened_for_diagnostic': False, 'labels_decoded_for_diagnostic': False, 'labels_changed': False,
              'predictions_changed': False, 'threshold_adopted': False, 'models_refitted': False,
              'automatic_enforcement_allowed': False, 'aws_calls': 0, 'paid_api_calls': 0,
              'plan_sha256': expected_plan_sha256, 'prior_sha256': plan['prior_sha256'],
              'source_pins': pins, 'per_scenario': {}}
    combined = {}

    def access(spec, phase):
        with (output/'diagnostic-access.jsonl').open('ab') as ledger:
            ledger.write(canonical({'scenario': spec['name'], 'role': spec['role'],
                'label_sha256': spec['truth_sha256'], 'purpose': 'score_only_diagnostic',
                'phase': phase, 'opened_at': datetime.now(UTC).isoformat()})+b'\n')
            ledger.flush()
            os.fsync(ledger.fileno())

    try:
        # Even hashing a label file reads its body. Record that first access,
        # not just the later JSON decoding, before the first integrity scan.
        for spec in plan['scenarios']:
            access(spec, 'integrity_verification')
        report['labels_reopened_for_diagnostic'] = True
        require(all(sha(path, 2*1024**3) == pin for path, pin in inputs.items()), 'score_audit_input_pin')
        for spec in plan['scenarios']:
            name = spec['name']
            access(spec, 'semantic_diagnostic')
            report['labels_decoded_for_diagnostic'] = True
            preparations_here = preparations[name]
            groups, total = {}, ScoreAudit()
            source, ordinal, population = 0, 0, 0
            for prediction, truth in zip_longest(rows(spec['prediction']), rows(spec['truth'])):
                require(prediction is not None and truth is not None and source < len(preparations_here['pairs']),
                        'score_audit_row_alignment')
                ordinal += 1
                pair = preparations_here['pairs'][source]
                case = hashlib.sha256((pair['raw_sha256']+':'+str(ordinal)).encode()).hexdigest()
                require(prediction['case_id'] == truth['case_id'] == case
                        and type(prediction['source_index']) is int and prediction['source_index'] == source,
                        'score_audit_case_binding')
                category = kind(pair['raw_member'])
                score, expected, previous = prediction['after_score'], truth['malicious'], prediction['after']
                failed = prediction['error'] is not None
                current = groups.setdefault(category, ScoreAudit())
                targets = [current, total]
                if name != 'harrison_observed':
                    targets.append(combined.setdefault(category, ScoreAudit()))
                for target in targets:
                    target.add(score, expected, previous, failed=failed)
                population += 1
                require(population <= spec['population'], 'score_audit_row_bound')
                if ordinal == pair['rows']:
                    source, ordinal = source+1, 0
            require(population == spec['population'] and source == len(preparations_here['pairs']) and ordinal == 0,
                    'score_audit_full_population')
            result = total.report()
            same_counts(result['current'], prior['scenarios'][name]['metrics']['after'])
            report['per_scenario'][name] = {'role': spec['role'], 'all_rows': result,
                'kinds': {k: value.report() for k, value in sorted(groups.items())}}
            print(canonical({'diagnosed': name, 'population': population}).decode(), flush=True)
        report['kinds_RSF'] = {k: value.report() for k, value in sorted(combined.items())}
        require(set(report['kinds_RSF']) == set(prior['kinds_RSF']), 'score_audit_kind_population')
        for category, result in report['kinds_RSF'].items():
            same_counts(result['current'], prior['kinds_RSF'][category]['after'])
        report['population'] = sum(s['all_rows']['population'] for s in report['per_scenario'].values())
        require(report['population'] == prior['population']
                and source_pins(ROOT) == pins
                and all(sha(path, 2*1024**3) == pin for path, pin in inputs.items()), 'score_audit_final_pins')
        report['completed'] = True
    finally:
        (output/'run.json').write_bytes(canonical(report)+b'\n')
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
