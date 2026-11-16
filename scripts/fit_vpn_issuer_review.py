"""Fit one explicit training-only issuer advisory head after sealing observations."""

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from app.config import get_settings
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.vpn_control_review import ControlHead
from scripts.f1_lab.vpn_issuer_review import (
    PROFILE,
    IssuerHead,
    IssuerObservation,
    IssuerRelationReview,
)
from scripts.f1_lab.vpn_protocol_head import ProtocolHead
from scripts.f1_lab.vpn_protocol_io import legacy, records
from scripts.f1_lab.vpn_protocol_review import ProtocolReview


def fit(plan_path, pin, protocol_path, protocol_pin, control_path, control_pin, output):
    require(get_settings().app_environment in {'local', 'test'}, 'issuer_fit_local_test_only')
    require(sha(plan_path, 65536) == pin, 'issuer_fit_plan_pin')
    plan = decode(Path(plan_path).read_bytes())
    require(plan['schema'] == 'vpn-protocol-training-plan-1' and plan['goal_qualified'] is False
            and plan['scope'] == 'observed_development' and plan['minimum_support'] == 5
            and len(plan['sources']) == 4 and {s['name'] for s in plan['sources']} ==
                {'russellmitchell', 'santos', 'shaw', 'wheeler'}
            and all(s['role'] == 'training' for s in plan['sources'])
            and {'fox', 'harrison', 'wilson', 'wardbeck'} <= set(plan['not_fitted_observed']),
            'issuer_fit_declared_training_only')
    _model, identity = legacy(plan['legacy_models'], plan['legacy_models_sha256'])
    ProtocolHead.load(protocol_path, protocol_pin, identity)
    ControlHead.load(control_path, control_pin, identity, protocol_pin)
    dependencies = {'legacy_identity_sha256': identity, 'protocol_model_sha256': protocol_pin,
                    'control_model_sha256': control_pin}
    head = IssuerHead(dependencies)
    out = Path(output)
    out.mkdir(parents=True, exist_ok=False)
    frozen, provenance, source_pins = {}, [], set()
    input_pins = {Path(plan_path): pin, Path(protocol_path): protocol_pin, Path(control_path): control_pin,
                  Path(plan['legacy_models']): plan['legacy_models_sha256']}
    for spec in plan['sources']:
        name = spec['name']
        require(sha(spec['preparation'], 2 * 1024**2) == spec['preparation_sha256'], 'issuer_fit_preparation_pin')
        prep = decode(Path(spec['preparation']).read_bytes())
        require(prep['completed'] is True and prep['inputs_contain_truth'] is False, 'issuer_fit_preparation_scope')
        sources = records(spec['raw'], prep)
        require(len(sources) == 1, 'issuer_fit_one_original_vpn_source')
        index, (source, rows, errors) = next(iter(sources.items()))
        require(errors == 0 and source not in source_pins, 'issuer_fit_no_time_errors_or_repeated_source')
        source_pins.add(source)
        input_pins[Path(spec['preparation'])] = spec['preparation_sha256']
        input_pins[Path(spec['raw']) / 'audit.json'] = prep['source_manifest_sha256']
        input_pins[Path(spec['raw']) / f'pair-{index}-raw.source'] = source
        input_pins[Path(spec['truth'])] = spec['truth_sha256']
        protocol, issuer = ProtocolReview(source), IssuerRelationReview(source)
        selected = []
        for ordinal, moment, line in rows:
            base = protocol.observe(ordinal, line, moment, source_sha256=source)
            observation = issuer.observe(ordinal, line, moment, base, source_sha256=source)
            selected.append({'case_id': hashlib.sha256((source + ':' + str(ordinal)).encode()).hexdigest(),
                             'observation': asdict(observation) if observation is not None else None})
        path = out / (name + '-observations.json')
        path.write_bytes(canonical(selected) + b'\n')
        frozen[name] = selected, sha(path)
        provenance.append({'name': name, 'role': 'training', 'source_sha256': source, 'source_index': index,
            'original_vpn_rows': len(rows), 'original_total_rows': sum(p['rows'] for p in prep['pairs']),
            'preparation_sha256': spec['preparation_sha256'], 'observations_sha256': sha(path),
            'truth_sha256': spec['truth_sha256']})
    # No truth is opened until every original source projection has been sealed.
    for spec in plan['sources']:
        require(sha(spec['truth']) == spec['truth_sha256'], 'issuer_fit_truth_pin')
        selected, observation_pin = frozen[spec['name']]
        require(sha(out / (spec['name'] + '-observations.json')) == observation_pin, 'issuer_fit_observation_drift')
        wanted = {row['case_id']: row['observation'] for row in selected}
        seen, total = set(), 0
        with Path(spec['truth']).open('rb') as source:
            for body in iter(lambda: source.readline(MAX_ROW + 1), b''):
                total += 1
                require(len(body) <= MAX_ROW and total <= 2000000, 'issuer_fit_truth_bound')
                row = decode(body)
                if row['case_id'] not in wanted:
                    continue
                require(row['case_id'] not in seen and type(row['malicious']) is bool, 'issuer_fit_case_labels')
                seen.add(row['case_id'])
                value = wanted[row['case_id']]
                head.add(IssuerObservation(**value) if value is not None else None, row['malicious'])
        expected = next(p for p in provenance if p['name'] == spec['name'])
        require(seen == set(wanted) and total == expected['original_total_rows']
                and sha(spec['truth']) == spec['truth_sha256'], 'issuer_fit_complete_original_population')
    require(sha(plan_path, 65536) == pin and sha(protocol_path) == protocol_pin and sha(control_path) == control_pin
            and all(sha(path) == expected for path, expected in input_pins.items()), 'issuer_fit_input_drift')
    model_pin = head.save(out / 'head.json')
    report = {'schema': 'vpn-issuer-training-provenance-1', 'completed': True, 'feature_profile': PROFILE,
        'head_sha256': model_pin, 'dependencies': dependencies, 'training': provenance,
        'training_plan_sha256': pin, 'observations_sealed_before_labels': True,
        'minimum_normal_support': 5, 'any_attack_veto': True, 'reported_subjects_are_not_identity_or_authority': True,
        'support_separate_by_phase': True,
        'models_fit_only_original_declared_training': True, 'validation_labels_opened': False,
        'parameters_frozen_before_validation': True, 'goal_qualified': False, 'new_independent_evaluation': False,
        'aws_calls': 0, 'paid_api_calls': 0}
    (out / 'training-provenance.json').write_bytes(canonical(report) + b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('plan', 'sha256', 'protocol-model', 'protocol-model-sha256', 'control-model', 'control-model-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    result = fit(args.plan, args.sha256, args.protocol_model, args.protocol_model_sha256,
                 args.control_model, args.control_model_sha256, args.output)
    print(json.dumps({'completed': result['completed'], 'head_sha256': result['head_sha256'], 'goal_qualified': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
