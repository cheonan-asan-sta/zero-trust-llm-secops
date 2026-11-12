"""Bounded training-only diagnostics from externally pinned prepared outputs."""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.f1_lab.cloud_diagnostics import CloudDiagnostics, canonical
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require


def audit(directory, anchors, output):
    directory, output = Path(directory), Path(output)
    names = {f'asset-{index}-{kind}.jsonl' for index in (0, 1) for kind in ('observations', 'truth')}
    require(isinstance(anchors, dict) and set(anchors) == names
            and all(isinstance(v, str) and len(v) == 64 and all(c in '0123456789abcdef' for c in v) for v in anchors.values()),
            'cloud_diagnostic_external_anchors')
    require(not output.exists() and not output.is_symlink(), 'fresh_cloud_diagnostics')
    diagnostics, actual = CloudDiagnostics(), {}
    for index in (0, 1):
        obs_name, gold_name = (f'asset-{index}-{kind}.jsonl' for kind in ('observations', 'truth'))
        for name in (obs_name, gold_name):
            path = directory/name
            require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 128*1024**2, 'cloud_diagnostic_file')
        hashes = [hashlib.sha256(), hashlib.sha256()]
        with (directory/obs_name).open('rb') as observations, (directory/gold_name).open('rb') as truth:
            count = 0
            while True:
                rows = [stream.readline(MAX_ROW+1) for stream in (observations, truth)]
                if not any(rows):
                    break
                require(all(rows) and all(len(row) <= MAX_ROW for row in rows), 'cloud_diagnostic_row_alignment')
                count += 1
                require(count <= 100000, 'cloud_diagnostic_row_bound')
                for digest, row in zip(hashes, rows, strict=True):
                    digest.update(row)
                observation, gold = (decode(row) for row in rows)
                require(isinstance(observation, dict) and isinstance(gold, dict)
                        and isinstance(observation.get('case_id'), str)
                        and observation['case_id'] == gold.get('case_id'), 'cloud_diagnostic_case_alignment')
                diagnostics.add(observation.get('observation'), gold, asset=index)
        for name, digest in zip((obs_name, gold_name), hashes, strict=True):
            actual[name] = digest.hexdigest()
            require(actual[name] == anchors[name], 'cloud_diagnostic_input_hash')
            require(hashlib.sha256((directory/name).read_bytes()).hexdigest() == actual[name], 'cloud_diagnostic_source_changed')
    result = {**diagnostics.summary(), 'completed': True, 'input_sha256': actual, 'paid_api_calls': 0, 'aws_sdk_calls': 0}
    output.mkdir(parents=True, mode=0o700)
    (output/'diagnostics.json').write_bytes(canonical(result)+b'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--anchors', type=Path, required=True, help='External four-file SHA256 object; prepared outputs only')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(args.anchors.is_file() and args.anchors.stat().st_size <= 65536, 'cloud_diagnostic_anchor_file')
    print(json.dumps(audit(args.directory, decode(args.anchors.read_bytes()), args.output)))


if __name__ == '__main__':
    main()
