"""Add the explicitly frozen issuer advisory head to a label-free VPN replay."""

import argparse
import json
import shutil
from pathlib import Path

from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.vpn_issuer_review import PROFILE, IssuerHead
from scripts.f1_lab.vpn_protocol_io import legacy
from scripts.stage_vpn_protocol_replay import ROOT
from scripts.stage_vpn_protocol_replay import stage as base_stage


def stage(catalog_path, pin, output):
    report = base_stage(catalog_path, pin, output, profile='vpn-control')
    out, inputs = Path(output), Path(output) / 'inputs'
    report['completed'] = False
    (out / 'stage.json').write_bytes(canonical(report) + b'\n')
    bundle_path = ROOT / 'infra/f1-lab/frozen-vpn-issuer-v125'
    bundle = decode((bundle_path / 'bundle.json').read_bytes())
    require(bundle['schema'] == 'frozen-vpn-issuer-advisory-bundle-1' and bundle['feature_profile'] == PROFILE
            and bundle['goal_qualified'] is False and bundle['new_independent_evaluation'] is False
            and bundle['models_fit_only_original_declared_training'] is True
            and bundle['head']['path'] == 'head.json', 'issuer_bundle_scope')
    head_path = bundle_path / 'head.json'
    expected = bundle['head']['sha256']
    require(sha(head_path, 65536) == expected, 'issuer_bundle_head_pin')
    _model, identity = legacy(inputs / 'models/legacy.json', report['legacy_models_sha256'])
    dependencies = {'legacy_identity_sha256': identity, 'protocol_model_sha256': report['model_sha256'],
                    'control_model_sha256': report['control_model_sha256']}
    IssuerHead.load(head_path, expected, dependencies)
    provenance_path = bundle_path / 'training-provenance.json'
    require(sha(provenance_path, 65536) == bundle['training_provenance_sha256'], 'issuer_bundle_provenance_pin')
    provenance = decode(provenance_path.read_bytes())
    require(provenance['schema'] == 'vpn-issuer-training-provenance-1' and provenance['completed'] is True
            and provenance['feature_profile'] == PROFILE and provenance['head_sha256'] == expected
            and provenance['dependencies'] == dependencies and provenance['minimum_normal_support'] == 5
            and provenance['any_attack_veto'] is True and provenance['validation_labels_opened'] is False
            and provenance['parameters_frozen_before_validation'] is True and provenance['goal_qualified'] is False
            and provenance['models_fit_only_original_declared_training'] is True
            and len(provenance['training']) == 4 and {s['name'] for s in provenance['training']} ==
                {'russellmitchell', 'santos', 'shaw', 'wheeler'}
            and all(s['role'] == 'training' for s in provenance['training'])
            and len({s['source_sha256'] for s in provenance['training']}) == 4, 'issuer_bundle_provenance_scope')
    target = inputs / 'models/issuer.json'
    shutil.copyfile(head_path, target)
    require(sha(target, 65536) == expected, 'issuer_bundle_copy_pin')
    report['source_pins'].extend({'path': str(path), 'sha256': sha(path)}
                                 for path in (bundle_path / 'bundle.json', head_path, provenance_path))
    report.update(completed=True, profile='vpn-issuer', issuer_model_sha256=expected,
                  input_pins={path.relative_to(inputs).as_posix(): sha(path)
                              for path in inputs.rglob('*') if path.is_file()})
    (out / 'stage.json').write_bytes(canonical(report) + b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('catalog', 'sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    result = stage(args.catalog, args.sha256, args.output)
    print(json.dumps({'completed': result['completed'], 'goal_qualified': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
