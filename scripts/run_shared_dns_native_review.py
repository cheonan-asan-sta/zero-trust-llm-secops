"""Add review from frozen native capture context, preserving all baseline rows."""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.shared_dns_native_review import REASON, SharedDnsNativeReview
from scripts.f1_lab.transfer_evaluation import sha


def predict(prep, raw, baseline, pin, output, members):
    require(sha(baseline) == pin, 'native_dns_baseline_pin')
    selected, proof, seen = {}, [], set()
    for member in members:
        index = member['source_index']
        require(type(index) is int and 0 <= index < len(prep['pairs']) and index not in seen,
                'native_dns_source_index')
        seen.add(index)
        pair = prep['pairs'][index]
        require(pair['raw_member'] == 'gather/internal_share/logs/audit/audit.log'
                and member['raw_source_sha256'] == pair['raw_sha256'], 'native_dns_audit_source_binding')
        path = Path(raw) / f'pair-{index}-raw.source'
        require(sha(path, 64 * 1024**2) == pair['raw_sha256'], 'native_dns_raw_pin')
        with path.open('r', encoding='utf8', newline='') as stream:
            lines = stream.readlines()
        require(len(lines) == pair['rows'], 'native_dns_raw_population')
        reader = SharedDnsNativeReview(pair['raw_sha256'], lines, member['path'], member['sha256'])
        for ordinal, line in enumerate(lines, 1):
            evidence = reader.observe(ordinal, line, source_sha256=pair['raw_sha256'])
            if evidence:
                selected[index, ordinal] = evidence
        reader.verify()
        require(sha(path) == pair['raw_sha256'], 'native_dns_raw_drift')
    output = Path(output)
    partial = output.with_suffix('.part')
    require(not output.exists() and not partial.exists(), 'native_dns_fresh_prediction')
    source = ordinal = total = errors = changed = 0
    with Path(baseline).open('rb') as old, partial.open('xb') as target:
        for body in iter(lambda: old.readline(MAX_ROW + 1), b''):
            require(len(body) <= MAX_ROW and source < len(prep['pairs']), 'native_dns_baseline_bound')
            ordinal += 1
            pair, prior = prep['pairs'][source], decode(body)
            case = hashlib.sha256((pair['raw_sha256'] + ':' + str(ordinal)).encode()).hexdigest()
            require(prior['case_id'] == case and prior['source_index'] == source, 'native_dns_case_order')
            before = prior['after'] if prior['error'] is None else None
            after, score, reason = before, prior['after_score'], prior['reason']
            evidence = selected.get((source, ordinal))
            if before is False and prior['error'] is None and reason == 'unchanged' and evidence:
                after, score, reason = True, max(score, .95), REASON
                proof.append({'case_id': case, **evidence})
            changed += before != after
            errors += prior['error'] is not None
            total += 1
            target.write(canonical({'case_id': case, 'source_index': source, 'before': before, 'after': after,
                'before_score': prior['after_score'], 'after_score': score, 'reason': reason, 'error': prior['error']}) + b'\n')
            if ordinal == pair['rows']:
                source, ordinal = source + 1, 0
    require(source == len(prep['pairs']) and ordinal == 0 and sha(baseline) == pin,
            'native_dns_complete_population_or_drift')
    partial.rename(output)
    evidence_path = output.with_suffix('.evidence.jsonl')
    evidence_path.write_bytes(b''.join(canonical(row) + b'\n' for row in proof))
    return {'population': total, 'inference_errors': errors, 'changed_alerts': changed,
            'predictions_sha256': sha(output), 'evidence_sha256': sha(evidence_path), 'validation_labels_opened': False}


def run(plan_path, pin, native_path, native_pin, output):
    require(sha(plan_path) == pin and sha(native_path) == native_pin, 'native_dns_plan_pins')
    plan, native = decode(Path(plan_path).read_bytes()), decode(Path(native_path).read_bytes())
    require(plan['schema'] == 'ordered-audit-replay-1' and plan['scope'] == 'observed_development_only'
            and plan['goal_qualified'] is False and sha(plan['baseline']) == plan['baseline_sha256'], 'native_dns_plan_scope')
    require(native['schema'] == 'shared-dns-native-sidecars-1' and native['goal_qualified'] is False
            and type(native['members']) is list and len(native['members']) <= 16, 'native_dns_catalog_scope')
    baseline = decode(Path(plan['baseline']).read_bytes())
    require(baseline['completed'] is True and baseline['goal_qualified'] is False
            and len(baseline['scenarios']) == len(plan['scenarios']), 'native_dns_baseline_scope')
    names = {s['name'] for s in plan['scenarios']}
    require(all(m['scenario'] in names for m in native['members']), 'native_dns_scenario_binding')
    out = Path(output)
    out.mkdir(parents=True, exist_ok=False)
    (out / 'prediction').mkdir()
    report = {'schema': 'shared-dns-native-prediction-1', 'completed': False, 'goal_qualified': False,
              'new_independent_evaluation': False, 'validation_labels_opened': False, 'native_catalog_sha256': native_pin,
              'models_refitted': False, 'historical_application_receipt_proven': False,
              'actor_or_authority_proven': False, 'automatic_enforcement_allowed': False,
              'scenarios': {}, 'aws_calls': 0, 'paid_api_calls': 0}
    for spec in plan['scenarios']:
        name = spec['name']
        require(name not in report['scenarios'] and sha(spec['preparation']) == spec['preparation_sha256'],
                'native_dns_preparation_pin')
        prep = decode(Path(spec['preparation']).read_bytes())
        require(prep['completed'] is True and prep['inputs_contain_truth'] is False, 'native_dns_preparation_scope')
        members = [m for m in native['members'] if m['scenario'] == name]
        prior = baseline['scenarios'][name]
        row = predict(prep, spec['raw'], spec['prediction'], prior['prediction']['predictions_sha256'],
                      out / 'prediction' / (name + '-predictions.jsonl'), members)
        require(row['population'] == prior['population'], 'native_dns_scenario_population')
        report['scenarios'][name] = row
        (out / 'prediction-seal.json').write_bytes(canonical(report) + b'\n')
    require(sha(plan_path) == pin and sha(native_path) == native_pin, 'native_dns_plan_drift')
    report['completed'] = True
    (out / 'prediction-seal.json').write_bytes(canonical(report) + b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'sha256', 'native-catalog', 'native-catalog-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    result = run(args.plan, args.sha256, args.native_catalog, args.native_catalog_sha256, args.output)
    print(json.dumps({'completed': result['completed'], 'goal_qualified': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
