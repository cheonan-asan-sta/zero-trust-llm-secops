"""Intake already exposed Harrison rotations as development, never as new heldout evidence."""

import argparse
from pathlib import Path

from scripts.f1_lab.bounded_zip import copy_member, inspect
from scripts.f1_lab.line_truth import annotations
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.rotation_selection import select
from scripts.f1_lab.transfer_evaluation import sha, source_pins
from scripts.prepare_transfer_source import timezone


def prepare(root, archive, expected_sha256, output, exposure):
    require(exposure['source_id'] == 'ait-harrison' and exposure['role'] == 'observed_development'
            and exposure['archive_sha256'] == expected_sha256
            and exposure['goal_qualified'] is False, 'rotation_observed_role_required')
    require(type(exposure['simulation_start']) is int and type(exposure['simulation_end']) is int
            and 0 <= exposure['simulation_start'] < exposure['simulation_end'], 'rotation_bounds')
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'rotation_fresh_output')
    inventory = inspect(archive, expected_sha256)
    pairs, excluded = select(inventory['entries'])
    pins = source_pins(root)
    output.mkdir(parents=True)
    report = {'schema': 'f1-observed-rotation-intake-1', 'completed': False, 'goal_qualified': False,
        'scope': 'already exposed Harrison development; not independent evaluation',
        'timestamp_basis': 'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
        'exposure': exposure, 'source_pins': pins, 'archive_sha256': expected_sha256,
        'pairs': [], 'excluded_unpaired': excluded, 'physical_file_context_only': True,
        'labels_changed': False, 'paid_api_calls': 0, 'aws_calls': 0}
    total, hosts = 0, {}
    try:
        for index, pair in enumerate(pairs):
            if pair['facts_member'] not in hosts:
                target = output/f'host-{len(hosts)}.metadata'
                copied = copy_member(archive, expected_sha256, pair['facts_member'], target, maximum_bytes=4*1024**2)
                hosts[pair['facts_member']] = {'sha256': copied['sha256'], 'timezone': timezone(decode(target.read_bytes()))}
            raw_path, label_path = output/f'pair-{index}-raw.source', output/f'pair-{index}-labels.source'
            raw_copy = copy_member(archive, expected_sha256, pair['raw_member'], raw_path,
                                   maximum_bytes=(512 if pair['kind'] == 'access' else 64)*1024**2)
            count = 0
            with raw_path.open('rb') as stream:
                while row := stream.readline(MAX_ROW+1):
                    count += 1
                    require(len(row) <= MAX_ROW and count <= (2000000 if pair['kind'] == 'access' else 100000),
                            'rotation_source_bound')
            total += count
            require(count > 0 and total <= 2000000, 'rotation_population')
            copied = copy_member(archive, expected_sha256, pair['label_member'], label_path)
            labels, _ = annotations(label_path, copied['sha256'])
            require(not labels or max(labels) <= count, 'rotation_labels_outside_source')
            provenance = {**pair, 'raw_sha256': raw_copy['sha256'], 'label_sha256': copied['sha256'],
                'archive_sha256': expected_sha256, 'source_timezone': 'UTC',
                'simulation_start': exposure['simulation_start'], 'simulation_end': exposure['simulation_end'],
                'timezone_metadata': hosts[pair['facts_member']], 'publisher_trimmed_pair': True}
            report['pairs'].append({'pair_id': raw_copy['sha256'], 'raw_rows': count, 'provenance': provenance})
        require(len({p['provenance']['raw_sha256'] for p in report['pairs']}) == len(report['pairs']),
                'rotation_duplicate_physical_source')
        require(source_pins(root) == pins and sha(archive) == expected_sha256, 'rotation_inputs_changed')
        report.update(completed=True, population=total)
    finally:
        (output/'audit.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--exposure', required=True, type=Path)
    parser.add_argument('--expected-exposure-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    require(sha(args.exposure) == args.expected_exposure_sha256, 'rotation_exposure_anchor')
    exposure = decode(args.exposure.read_bytes())
    result = prepare(Path(__file__).resolve().parents[1], args.archive, exposure['archive_sha256'], args.output, exposure)
    print(canonical({'completed': result['completed'], 'population': result['population'], 'goal_qualified': False}).decode())


if __name__ == '__main__':
    main()
