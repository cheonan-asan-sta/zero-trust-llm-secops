"""Enrich pinned training observations while copying truth sidecars unchanged."""

import argparse
import hashlib
import json
from pathlib import Path

from scripts.f1_lab.cloud_context import enrich
from scripts.f1_lab.cloud_diagnostics import canonical
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require


def prepare(directory, anchors, output):
    directory, output = Path(directory), Path(output)
    names = {f'asset-{i}-{kind}.jsonl' for i in (0, 1) for kind in ('observations', 'truth')}
    require(isinstance(anchors, dict) and set(anchors) == names
            and all(isinstance(v, str) and len(v) == 64 and all(c in '0123456789abcdef' for c in v) for v in anchors.values()),
            'cloud_context_external_anchors')
    require(not output.exists() and not output.is_symlink(), 'fresh_cloud_context_output')
    raw, observations, rows = {}, {}, []
    for index in (0, 1):
        for kind in ('observations', 'truth'):
            name = f'asset-{index}-{kind}.jsonl'
            path = directory/name
            require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 128*1024**2, 'cloud_context_input_file')
            raw[name] = path.read_bytes()
            require(hashlib.sha256(raw[name]).hexdigest() == anchors[name], 'cloud_context_input_hash')
        prepared = []
        for ordinal, body in enumerate(raw[f'asset-{index}-observations.jsonl'].splitlines(), 1):
            require(len(body) <= MAX_ROW and len(rows) < 50000, 'cloud_context_input_rows')
            item = decode(body)
            require(isinstance(item, dict) and isinstance(item.get('case_id'), str), 'cloud_context_input_case')
            # Namespace is only for internal alignment; never an inference
            # feature or historical grouping key. Case IDs/row order stay intact.
            internal = f'{index}:{ordinal}:{item["case_id"]}'
            rows.append((internal, item.get('observation')))
            prepared.append((internal, item))
        labels = raw[f'asset-{index}-truth.jsonl'].splitlines()
        require(len(labels) == len(prepared), 'cloud_context_truth_population')
        for (_, item), body in zip(prepared, labels, strict=True):
            require(len(body) <= MAX_ROW, 'cloud_context_truth_row_bound')
            gold = decode(body)
            require(isinstance(gold, dict) and gold.get('case_id') == item['case_id'], 'cloud_context_truth_alignment')
        observations[index] = prepared
    context, diagnostics = enrich(rows)  # No truth bytes or labels reach this function.
    output.mkdir(parents=True, mode=0o700)
    report = {'schema': 'f1-cloud-context-preparation-3', 'completed': False, 'input_sha256': anchors,
              'feature_profile': 'cloud-causal-context-3', 'context': diagnostics, 'files': {},
              'truth_copied_unchanged': False, 'test_records_read': 0, 'classifier_fitted': False,
              'original_six_domain_goal_replaced': False, 'goal_qualified': False, 'paid_api_calls': 0, 'aws_sdk_calls': 0}
    try:
        for index in (0, 1):
            with (output/f'asset-{index}-observations.jsonl.part').open('xb') as target:
                for identifier, item in observations[index]:
                    additions = context[identifier]
                    view = item['observation']
                    if additions['features'] is not None and view is not None:
                        view = {**view, 'features': {**view['features'], **additions['features']}}
                    else:
                        view = None
                    target.write(canonical({**item, 'observation': view, 'error': additions['error'] or item.get('error')})+b'\n')
            (output/f'asset-{index}-truth.jsonl.part').write_bytes(raw[f'asset-{index}-truth.jsonl'])
        for name in names:
            require(hashlib.sha256((directory/name).read_bytes()).hexdigest() == anchors[name], 'cloud_context_source_changed')
            part = output/(name+'.part')
            body = part.read_bytes()
            digest = hashlib.sha256(body).hexdigest()
            if name.endswith('-truth.jsonl'):
                require(digest == anchors[name], 'cloud_context_truth_changed')
            part.rename(output/name)
            report['files'][name] = {'sha256': digest, 'bytes': len(body)}
        report['truth_copied_unchanged'] = True
        report['completed'] = True
    except (OSError, ValueError, TypeError, KeyError) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        (output/'preparation.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--anchors', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(args.anchors.is_file() and args.anchors.stat().st_size <= 65536, 'cloud_context_anchor_file')
    print(json.dumps(prepare(args.directory, decode(args.anchors.read_bytes()), args.output)))


if __name__ == '__main__':
    main()
