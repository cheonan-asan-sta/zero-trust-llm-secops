"""Join verified frame observations to every original VPN row, diagnostically."""

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.vpn_initial_frame_link import FrameIndex
from scripts.f1_lab.vpn_protocol_io import records


def load_frames(path, pin, raw_pin):
    require(sha(path, 2 * 1024**2) == pin, 'wire_intake_pin')
    value = decode(Path(path).read_bytes())
    require(value['schema'] == 'verified-vpn-packet-members-1' and value['completed'] is True
            and value['role'] == 'training' and value['scenario'] == 'russellmitchell'
            and value['publisher_md5_verified'] is True and value['same_vpn_log_bytes_verified'] is True
            and value['vpn_raw_sha256'] == raw_pin and value['new_independent_evaluation'] is False
            and value['goal_qualified'] is False and type(value['members']) is list
            and len(value['members']) == 2, 'wire_intake_scope')
    rows = []
    pins = {Path(path): (pin, 2 * 1024**2)}
    folder = Path(path).parent
    for number, member in enumerate(value['members']):
        require(member['path'] == f'member-{number}.pcap' and member['observations'] == f'member-{number}-initial.jsonl'
                and member['completed'] is True and member['crc_verified'] is True
                and re.fullmatch('[a-f0-9]{64}', member['sha256'])
                and member['source_sha256'] == member['sha256']
                and type(member['packets']) is int and 0 <= member['packets'] <= 10000000
                and type(member['initial_frames']) is int and 0 <= member['initial_frames'] <= 100000,
                'wire_member_binding')
        pcap, observed = folder / member['path'], folder / member['observations']
        require(sha(pcap, 2 * 1024**3) == member['sha256']
                and sha(observed, 128 * 1024**2) == member['observations_sha256'], 'wire_observation_pin')
        pins[pcap] = member['sha256'], 2 * 1024**3
        pins[observed] = member['observations_sha256'], 128 * 1024**2
        count = prior = 0
        with observed.open('rb') as stream:
            for body in iter(lambda: stream.readline(MAX_ROW + 1), b''):
                count += 1
                require(len(body) <= MAX_ROW and count <= 100000, 'wire_observation_bound')
                row = decode(body)
                require(row['source_sha256'] == member['sha256']
                        and type(row['packet_ordinal']) is int and prior < row['packet_ordinal'] <= member['packets'],
                        'wire_observation_source_or_order')
                prior = row['packet_ordinal']
                rows.append(row)
        require(count == member['initial_frames'], 'wire_observation_population')
    return FrameIndex(rows), pins


def run(preparation, preparation_pin, raw, intake, intake_pin, output):
    require(sha(preparation, 2 * 1024**2) == preparation_pin, 'wire_preparation_pin')
    prep = decode(Path(preparation).read_bytes())
    require(prep['completed'] is True and prep['inputs_contain_truth'] is False, 'wire_preparation_scope')
    sources = records(raw, prep)
    require(len(sources) == 1, 'wire_one_vpn_source')
    source, (raw_pin, inputs, errors) = next(iter(sources.items()))
    require(prep['pairs'][source]['raw_member'] == 'gather/vpn/logs/openvpn.log', 'wire_host_source')
    index, pins = load_frames(intake, intake_pin, raw_pin)
    out = Path(output)
    out.mkdir(parents=True, exist_ok=False)
    target = out / 'links.jsonl'
    partial = target.with_suffix('.part')
    raw_source = Path(raw) / f'pair-{source}-raw.source'
    stats = Counter()
    previous = None
    regressions = 0
    with partial.open('xb') as destination, raw_source.open('rb') as original:
        for (ordinal, moment, line), body in zip(inputs, original, strict=True):
            regressed = moment is not None and previous is not None and moment < previous
            regressions += regressed
            if moment is not None:
                previous = moment
            row = index.match(line, moment)
            stats[row['status']] += 1
            if row['matched']:
                stats[row['recorded_time_relation']] += 1
            case = hashlib.sha256((raw_pin + ':' + str(ordinal)).encode()).hexdigest()
            destination.write(canonical({'schema': 'diagnostic-vpn-frame-link-1', 'case_id': case,
                'source_index': source, 'ordinal': ordinal, 'raw_row_sha256': hashlib.sha256(body).hexdigest(),
                'raw_time_regressed': regressed, **row}) + b'\n')
    require(sha(raw_source) == raw_pin and sha(preparation) == preparation_pin
            and all(sha(p, maximum) == pin for p, (pin, maximum) in pins.items()), 'wire_link_source_drift')
    target.with_suffix('.part').rename(target)
    report = {'schema': 'diagnostic-vpn-frame-links-1', 'completed': True, 'population': len(inputs),
        'raw_time_errors': errors, 'raw_time_regressions': regressions,
        'source_sha256': raw_pin, 'links_sha256': sha(target), 'counts': dict(stats),
        'diagnostic_only': True, 'temporal_availability_proven': False, 'admitted_to_predictor': False,
        'validation_labels_opened': False, 'model_fit_or_prediction_performed': False,
        'goal_qualified': False, 'new_independent_evaluation': False, 'aws_calls': 0, 'paid_api_calls': 0}
    (out / 'run.json').write_bytes(canonical(report) + b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('preparation', 'preparation-sha256', 'raw', 'intake', 'intake-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    result = run(args.preparation, args.preparation_sha256, args.raw, args.intake, args.intake_sha256, args.output)
    print(json.dumps({'completed': result['completed'], 'population': result['population'], 'admitted_to_predictor': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
