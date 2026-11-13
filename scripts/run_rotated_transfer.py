"""Freeze, prepare, predict and score the predeclared rotated Wilson transfer."""

import argparse
from dataclasses import asdict
from pathlib import Path

from app.config import get_settings
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.rotation_transfer import (
    POLICY,
    check_freeze,
    freeze,
    pair_predictions,
    select_pairs,
)
from scripts.f1_lab.transfer_evaluation import load_detector, score, sha
from scripts.f1_lab.transfer_evaluation import predict as v49_predict
from scripts.f1_lab.web_post_refinement import SuccessfulPostRefinement
from scripts.prepare_native_stream import prepare as prepare_observations
from scripts.prepare_transfer_source import prepare as prepare_raw
from scripts.prepare_transfer_source import truth_after_seal
from scripts.run_web_command_history import predict as history_predict
from scripts.run_web_command_history import source_evidence
from scripts.run_web_post_refinement import predict as post_predict

ROOT = Path(__file__).resolve().parents[1]


def prediction_packet(root, freeze_path, freeze_hash, raw_directory, prepared_directory, output):
    value = check_freeze(root, freeze_path, freeze_hash)
    prepared_directory, raw_directory, output = Path(prepared_directory), Path(raw_directory), Path(output)
    preparation_path = prepared_directory/'preparation.json'
    preparation = decode(preparation_path.read_bytes())
    require(preparation['schema'] == 'f1-native-raw-observations-1' and preparation['completed'] is True
            and preparation['labels_loaded'] is False and preparation['truth_sidecar_written'] is False
            and set(preparation['files']) == {'inputs.jsonl', 'references.jsonl'}, 'rotated_transfer_raw_only')
    require(not (prepared_directory/'truth.jsonl').exists() and not (raw_directory/'truth.jsonl').exists()
            and not list(raw_directory.glob('pair-*-labels.source')), 'rotated_transfer_labels_in_predictor_mount')
    raw_manifest = raw_directory/'audit.json'
    require(sha(raw_manifest) == preparation['source_manifest_sha256'], 'rotated_transfer_preparation_source')
    audit = decode(raw_manifest.read_bytes())
    require(audit['completed'] is True and audit['candidate_freeze_sha256'] == freeze_hash
            and audit['archive_sha256'] == value['archive_sha256']
            and audit['label_bodies_opened'] == 0, 'rotated_transfer_raw_binding')
    require(not output.exists() and not output.is_symlink(), 'rotated_transfer_fresh_packet')
    output.mkdir(parents=True)
    model = load_detector(root, value['models'], value['operation_policy'])
    baseline_path, history_path, post_path = (output/name for name in
        ('v49-predictions.jsonl', 'v51-predictions.jsonl', 'v52-predictions.jsonl'))
    baseline = v49_predict(prepared_directory, preparation, raw_directory, model, baseline_path)
    evidence = source_evidence(raw_directory, preparation)
    (output/'command-history-evidence.json').write_bytes(canonical({key: asdict(v) for key, v in evidence.items()})+b'\n')
    history = history_predict(prepared_directory, preparation, baseline_path, baseline['predictions_sha256'],
                              evidence, history_path)
    post = post_predict(prepared_directory, preparation, history_path, history['predictions_sha256'],
                        SuccessfulPostRefinement(model.web_model), post_path)
    paired = pair_predictions(baseline_path, post_path, baseline['predictions_sha256'],
                               post['predictions_sha256'], output/'predictions.jsonl')
    population = sum(pair['rows'] for pair in preparation['pairs'])
    require(all(stage['population'] == population for stage in (baseline, history, post, paired)),
            'rotated_transfer_stage_population_drift')
    check_freeze(root, freeze_path, freeze_hash)
    manifest = {**paired, 'schema': 'f1-rotated-transfer-predictions-2', 'phase': 'predictions_sealed',
        'candidate_freeze_sha256': freeze_hash, 'raw_manifest_sha256': sha(raw_manifest),
        'observations_manifest_sha256': sha(preparation_path), 'labels_opened': False,
        'stages': {'v49': baseline, 'v51': history, 'v52': post},
        'evidence_sha256': sha(output/'command-history-evidence.json'), 'evaluation_unit': POLICY['evaluation_unit'],
        'goal_qualified': False, 'automatic_enforcement_allowed': False}
    path = output/'prediction-manifest.json'
    path.write_bytes(canonical(manifest)+b'\n')
    return {'manifest_sha256': sha(path), **manifest}


def score_packet(root, archive, freeze_path, freeze_hash, raw_directory, prediction_directory,
                 manifest_hash, output):
    value = check_freeze(root, freeze_path, freeze_hash)
    prediction_directory, output = Path(prediction_directory), Path(output)
    require(not output.exists() and not output.is_symlink(), 'rotated_transfer_fresh_score')
    manifest_path = prediction_directory/'prediction-manifest.json'
    require(sha(manifest_path) == manifest_hash, 'rotated_transfer_prediction_manifest')
    manifest = decode(manifest_path.read_bytes())
    require(manifest['schema'] == 'f1-rotated-transfer-predictions-2'
            and set(manifest['stages']) == {'v49', 'v51', 'v52'}, 'rotated_transfer_prediction_contract')
    for name, stage in manifest['stages'].items():
        require(sha(prediction_directory/(name+'-predictions.jsonl')) == stage['predictions_sha256'],
                'rotated_transfer_intermediate_changed')
    truth = truth_after_seal(root, archive, freeze_path, freeze_hash, raw_directory,
        manifest_path, manifest_hash, output, freeze_checker=check_freeze)
    result = score(prediction_directory/'predictions.jsonl', output/'truth.jsonl',
                   manifest['predictions_sha256'], truth['truth_sha256'])
    stages = {name: score(prediction_directory/(name+'-predictions.jsonl'), output/'truth.jsonl',
                         stage['predictions_sha256'], truth['truth_sha256']) for name, stage in manifest['stages'].items()}
    check_freeze(root, freeze_path, freeze_hash)
    result.update(schema='f1-rotated-source-transfer-result-2', completed=True, source_id=value['source_id'],
        candidate_freeze_sha256=freeze_hash, prediction_manifest_sha256=manifest_hash,
        stages=stages, truth_manifest=truth, evaluation_unit=POLICY['evaluation_unit'],
        model_selection_feedback_allowed=False, original_six_domain_goal_replaced=False,
        session_metrics_measured=False, forward_time_split=False, production_adopted=False,
        limits=['shared simulated generation family; overlapping development/evaluation periods',
                'subject/device/session/attack-family independence unverified',
                'publisher attack-related line labels; no independent human adjudication',
                'Apache/OpenVPN only; original six domains and enterprise performance unproven'],
        paid_api_calls=0, aws_calls=0)
    (output/'score.json').write_bytes(canonical(result)+b'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('freeze', 'prepare', 'predict', 'score'))
    parser.add_argument('--freeze', required=True, type=Path)
    parser.add_argument('--freeze-sha256')
    for name in ('acquisition', 'archive', 'raw-directory', 'prepared-directory', 'prediction-directory', 'output'):
        parser.add_argument('--'+name, type=Path)
    parser.add_argument('--prediction-manifest-sha256')
    args = parser.parse_args()
    require(get_settings().app_environment in {'local', 'test'}, 'rotated_transfer_local_only')
    if args.operation == 'freeze':
        require(args.acquisition is not None and args.archive is not None, 'rotated_transfer_acquisition_required')
        result = {'candidate_freeze_sha256': freeze(ROOT, decode(args.acquisition.read_bytes()), args.archive, args.freeze)}
    else:
        require(args.freeze_sha256 is not None, 'rotated_transfer_anchor_required')
        check_freeze(ROOT, args.freeze, args.freeze_sha256)
        if args.operation == 'prepare':
            require(all(p is not None for p in (args.archive, args.raw_directory, args.prepared_directory)),
                    'rotated_transfer_paths_required')
            prepare_raw(ROOT, args.archive, args.freeze, args.freeze_sha256, args.raw_directory,
                        freeze_checker=check_freeze, pair_selector=select_pairs)
            value = prepare_observations(args.raw_directory, sha(args.raw_directory/'audit.json'),
                                         args.prepared_directory, include_truth=False)
            result = {'prepared': value['completed'], 'labels_loaded': False, 'population': sum(p['rows'] for p in value['pairs'])}
        elif args.operation == 'predict':
            require(all(p is not None for p in (args.raw_directory, args.prepared_directory, args.output)),
                    'rotated_transfer_paths_required')
            result = prediction_packet(ROOT, args.freeze, args.freeze_sha256, args.raw_directory, args.prepared_directory, args.output)
        else:
            require(all(p is not None for p in (args.archive, args.raw_directory, args.prediction_directory,
                                                args.prediction_manifest_sha256, args.output)), 'rotated_transfer_paths_required')
            result = score_packet(ROOT, args.archive, args.freeze, args.freeze_sha256, args.raw_directory,
                                  args.prediction_directory, args.prediction_manifest_sha256, args.output)
    print(canonical(result).decode(), flush=True)


if __name__ == '__main__':
    main()
