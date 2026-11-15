"""Audit connection-observation support after predictions are sealed and scored."""

import argparse
import hashlib
from contextlib import ExitStack
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.raw_observations import raw_time
from scripts.f1_lab.transfer_evaluation import score, sha, source_pins
from scripts.f1_lab.vpn_observation_segments import VPNObservationSegments

ROOT = Path(__file__).resolve().parents[1]


def rows(path):
    with Path(path).open('rb') as stream:
        while body := stream.readline(MAX_ROW+1):
            require(len(body) <= MAX_ROW, 'vpn_support_jsonl_bound')
            yield decode(body)


def run(directory, expected_score_sha256, expected_manifest_sha256, output):
    directory, output = Path(directory), Path(output)
    require(not output.exists() and not output.is_symlink(), 'vpn_support_fresh_output')
    pins = source_pins(ROOT)
    scored_path = directory/'scoring/score.json'
    manifest_path = directory/'prediction-packet/prediction-manifest.json'
    raw_path, freeze_path = directory/'raw/audit.json', directory/'freeze.json'
    require(sha(scored_path) == expected_score_sha256 and sha(manifest_path) == expected_manifest_sha256,
            'vpn_support_external_hash')
    scored, manifest, raw, frozen = [decode(path.read_bytes()) for path in
                                    (scored_path, manifest_path, raw_path, freeze_path)]
    require(scored['completed'] is True and scored['goal_qualified'] is False
            and manifest['phase'] == 'predictions_sealed'
            and scored['prediction_manifest_sha256'] == expected_manifest_sha256
            and scored['candidate_freeze_sha256'] == manifest['candidate_freeze_sha256'] == sha(freeze_path)
            and raw['candidate_freeze_sha256'] == manifest['candidate_freeze_sha256']
            and raw['archive_sha256'] == frozen['archive_sha256']
            and sha(raw_path) == manifest['raw_manifest_sha256'], 'vpn_support_seal_binding')
    require(raw['completed'] is True and raw['timestamp_basis'] ==
            'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
            'vpn_support_timezone_contract')
    predictions, truth = directory/'prediction-packet/predictions.jsonl', directory/'scoring/truth.jsonl'
    recomputed = score(predictions, truth, manifest['predictions_sha256'], scored['truth_manifest']['truth_sha256'])
    require(all(recomputed[key] == scored[key] for key in ('population', 'metrics', 'per_source', 'changes')),
            'vpn_support_score_drift')
    audits, raw_hashes, ordinals, results = {}, {}, {}, []
    require(isinstance(raw['pairs'], list) and 0 < len(raw['pairs']) <= 64, 'vpn_support_pair_bound')
    vpn_indices = {i for i, pair in enumerate(raw['pairs']) if pair['provenance']['kind'] == 'vpn'}
    require(vpn_indices, 'vpn_support_no_vpn_source')
    global_rows, current_source = 0, -1
    with ExitStack() as stack:
        streams = {}
        for index in sorted(vpn_indices):
            pair = raw['pairs'][index]
            require(type(pair['raw_rows']) is int and 0 < pair['raw_rows'] <= 100000, 'vpn_support_source_bound')
            provenance = pair['provenance']
            require(type(provenance['simulation_start']) is int and type(provenance['simulation_end']) is int
                    and 0 <= provenance['simulation_start'] < provenance['simulation_end'] < 4102444800,
                    'vpn_support_time_bounds')
            path = directory/f'raw/pair-{index}-raw.source'
            raw_hashes[index] = sha(path, 64*1024**2)
            require(raw_hashes[index] == pair['provenance']['raw_sha256'], 'vpn_support_raw_hash')
            streams[index] = stack.enter_context(path.open('rb'))
            audits[index], ordinals[index] = VPNObservationSegments(), 0
        for prediction, gold in zip(rows(predictions), rows(truth), strict=True):
            require(prediction['case_id'] == gold['case_id'], 'vpn_support_truth_alignment')
            index = prediction['source_index']
            require(type(index) is int and 0 <= index < len(raw['pairs']) and index >= current_source,
                    'vpn_support_source_order')
            current_source = index
            global_rows += 1
            if index not in vpn_indices:
                continue
            ordinals[index] += 1
            ordinal, pair = ordinals[index], raw['pairs'][index]
            body = streams[index].readline(MAX_ROW+1)
            require(0 < len(body) <= MAX_ROW and prediction['case_id'] ==
                    hashlib.sha256((raw_hashes[index]+':'+str(ordinal)).encode()).hexdigest(),
                    'vpn_support_physical_row_binding')
            line = body.decode('utf8', errors='replace')
            provenance = pair['provenance']
            try:
                moment = raw_time(line, provenance['simulation_start'], provenance['simulation_end'], source_timezone='UTC')
            except (ValueError, RecursionError):
                moment = None
            audits[index].observe(ordinal, line, moment, gold['malicious'], prediction['before'], prediction['after'])
        require(global_rows == scored['population'], 'vpn_support_global_population')
        for index, audit in audits.items():
            require(not streams[index].read(1) and ordinals[index] == raw['pairs'][index]['raw_rows'],
                    'vpn_support_raw_population')
            result = audit.finish()
            previous = next(row for row in scored['per_source'] if row['source_index'] == index)
            require(result['line_metrics'] == previous['metrics'], 'vpn_support_line_metrics_changed')
            results.append({'source_index': index, 'raw_sha256': raw_hashes[index], **result})
    require(all(sha(directory/f'raw/pair-{i}-raw.source') == value for i, value in raw_hashes.items())
            and sha(predictions) == manifest['predictions_sha256']
            and sha(truth) == scored['truth_manifest']['truth_sha256']
            and sha(scored_path) == expected_score_sha256 and sha(manifest_path) == expected_manifest_sha256
            and sha(raw_path) == manifest['raw_manifest_sha256']
            and sha(freeze_path) == manifest['candidate_freeze_sha256'], 'vpn_support_inputs_changed')
    require(source_pins(ROOT) == pins, 'vpn_support_auditor_changed')
    result = {'schema': 'f1-postseal-vpn-support-audit-1', 'completed': True, 'source_id': scored['source_id'],
        'auditor_source_pins': pins,
        'score_sha256': expected_score_sha256, 'prediction_manifest_sha256': expected_manifest_sha256,
        'candidate_freeze_sha256': manifest['candidate_freeze_sha256'], 'per_source': results,
        'whole_evaluation_population': global_rows, 'vpn_population': sum(row['population'] for row in results),
        'original_line_metrics_unchanged': True, 'rows_removed_from_evaluation': 0,
        'goal_qualified': False, 'authenticated_sessions_measured': False,
        'model_selection_feedback_allowed': False, 'paid_api_calls': 0, 'aws_calls': 0}
    output.mkdir(parents=True)
    (output/'audit.json').write_bytes(canonical(result)+b'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--expected-score-sha256', required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.directory, args.expected_score_sha256, args.expected_manifest_sha256, args.output)
    print(canonical({'completed': result['completed'], 'vpn_population': result['vpn_population'],
                     'goal_qualified': result['goal_qualified']}).decode())


if __name__ == '__main__':
    main()
