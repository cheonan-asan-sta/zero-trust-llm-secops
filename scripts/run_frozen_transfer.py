"""Separate frozen-candidate, raw-only preparation, prediction sealing and truth scoring commands."""

import argparse
from pathlib import Path

from app.config import get_settings
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import (
    ROOT,
    check_freeze,
    freeze,
    load_detector,
    predict,
    score,
    sha,
)
from scripts.prepare_native_stream import prepare as observations_only
from scripts.prepare_transfer_source import prepare as raw_sources
from scripts.prepare_transfer_source import truth_after_seal


def prediction_packet(root, freeze_path, freeze_hash, raw_directory, prepared_directory, output):
    value = check_freeze(root, freeze_path, freeze_hash)
    preparation_path = Path(prepared_directory)/'preparation.json'
    preparation = decode(preparation_path.read_bytes())
    require(preparation['schema'] == 'f1-native-raw-observations-1' and preparation['completed']
            and preparation['labels_loaded'] is False and preparation['truth_sidecar_written'] is False,
            'transfer_observations_only_required')
    require(set(preparation['files']) == {'inputs.jsonl', 'references.jsonl'}, 'transfer_unexpected_input_artifact')
    audit_path = Path(raw_directory)/'audit.json'
    require(sha(audit_path) == preparation['source_manifest_sha256'], 'transfer_preparation_source')
    audit = decode(audit_path.read_bytes())
    require(audit['candidate_freeze_sha256'] == freeze_hash and audit['archive_sha256'] == value['archive_sha256'],
            'transfer_preparation_freeze_binding')
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'transfer_fresh_packet')
    output.mkdir(parents=True)
    model = load_detector(root, value['models'], value['operation_policy'])
    result = predict(prepared_directory, preparation, raw_directory, model, output/'predictions.jsonl')
    check_freeze(root, freeze_path, freeze_hash)
    sealed = {**result, 'schema': 'f1-source-transfer-predictions-1', 'phase': 'predictions_sealed',
        'candidate_freeze_sha256': freeze_hash, 'raw_manifest_sha256': sha(audit_path),
        'observations_manifest_sha256': sha(preparation_path), 'labels_opened': False,
        'evaluation_unit': 'physical_log_line', 'goal_qualified': False}
    manifest = output/'prediction-manifest.json'
    manifest.write_bytes(canonical(sealed)+b'\n')
    return {'manifest_sha256': sha(manifest), **sealed}


def score_packet(root, archive, freeze_path, freeze_hash, raw_directory, prediction_directory,
                 manifest_hash, output):
    value = check_freeze(root, freeze_path, freeze_hash)
    prediction_directory, output = Path(prediction_directory), Path(output)
    require(not output.exists() and not output.is_symlink(), 'transfer_fresh_score')
    truth = truth_after_seal(root, archive, freeze_path, freeze_hash, raw_directory,
        prediction_directory/'prediction-manifest.json', manifest_hash, output)
    sealed = decode((prediction_directory/'prediction-manifest.json').read_bytes())
    result = score(prediction_directory/'predictions.jsonl', output/'truth.jsonl',
                   sealed['predictions_sha256'], truth['truth_sha256'])
    check_freeze(root, freeze_path, freeze_hash)
    result.update(schema='f1-source-heldout-transfer-1', completed=True, source_id=value['source_id'],
        candidate_freeze_sha256=freeze_hash, prediction_manifest_sha256=manifest_hash,
        truth_manifest=truth, evaluation_unit='physical_log_line', model_selection_feedback_allowed=False,
        session_metrics_measured=False, original_six_domain_goal_replaced=False,
        limits=['one simulated testbed and shared dataset generation family',
                'subject, device, session and attack-family independence not verified',
                'publisher attack-related line labels, not human adjudicated real enterprise incidents',
                'Apache/OpenVPN telemetry only; original six-domain coverage unproven',
                'correlated rows; no independent-population confidence or target claim'],
        paid_api_calls=0, aws_calls=0, production_adopted=False)
    (output/'score.json').write_bytes(canonical(result)+b'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('freeze', 'prepare', 'predict', 'score'))
    parser.add_argument('--freeze', type=Path, required=True)
    parser.add_argument('--freeze-sha256')
    parser.add_argument('--acquisition', type=Path)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--raw-directory', type=Path)
    parser.add_argument('--prepared-directory', type=Path)
    parser.add_argument('--prediction-directory', type=Path)
    parser.add_argument('--prediction-manifest-sha256')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    require(get_settings().app_environment in {'local', 'test'}, 'transfer_local_test_only')
    if args.operation == 'freeze':
        require(args.acquisition is not None and args.archive is not None, 'transfer_acquisition_required')
        result = {'candidate_freeze_sha256': freeze(ROOT, decode(args.acquisition.read_bytes()),
                                                   args.freeze, archive=args.archive)}
    else:
        require(args.freeze_sha256 is not None, 'transfer_freeze_anchor_required')
        check_freeze(ROOT, args.freeze, args.freeze_sha256)
        if args.operation == 'prepare':
            require(all(p is not None for p in (args.archive, args.raw_directory, args.prepared_directory)),
                    'transfer_preparation_paths_required')
            raw_sources(ROOT, args.archive, args.freeze, args.freeze_sha256, args.raw_directory)
            prepared = observations_only(args.raw_directory, sha(args.raw_directory/'audit.json'),
                                         args.prepared_directory, include_truth=False)
            result = {'prepared': prepared['completed'], 'labels_loaded': False,
                      'population': sum(p['rows'] for p in prepared['pairs'])}
        elif args.operation == 'predict':
            require(all(p is not None for p in (args.raw_directory, args.prepared_directory, args.output)),
                    'transfer_prediction_paths_required')
            result = prediction_packet(ROOT, args.freeze, args.freeze_sha256, args.raw_directory,
                                       args.prepared_directory, args.output)
        else:
            require(all(p is not None for p in (args.archive, args.raw_directory, args.prediction_directory,
                                                args.prediction_manifest_sha256, args.output)),
                    'transfer_score_paths_required')
            result = score_packet(ROOT, args.archive, args.freeze, args.freeze_sha256, args.raw_directory,
                                  args.prediction_directory, args.prediction_manifest_sha256, args.output)
    print(canonical(result).decode(), flush=True)


if __name__ == '__main__':
    main()
