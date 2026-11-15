"""Freeze a reproducible M7 candidate offline; never attest independent review."""

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from scripts.prepare_m7 import SOURCE, verify

FILES = ('development.jsonl', 'evaluation.jsonl', 'labels.jsonl', 'manifest.json',
         'source.json', 'NOTICE.md')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify_frozen(directory: Path, expected: str):
    raw = (directory / 'freeze.json').read_bytes()
    if digest(raw) != expected:
        raise ValueError('freeze_anchor_mismatch')
    freeze = json.loads(raw)
    if (freeze.get('schema') != 'm7-frozen-candidate-1'
            or freeze.get('independent_review') != 'pending'
            or set(freeze.get('files', {})) != set(FILES)
            or {p.name for p in directory.iterdir()} != {*FILES, 'freeze.json'}):
        raise ValueError('freeze_contract_mismatch')
    for name, expected_hash in freeze['files'].items():
        p = directory / name
        if p.is_symlink() or digest(p.read_bytes()) != expected_hash:
            raise ValueError('freeze_file_mismatch')
    verify(directory, json.loads((directory / 'source.json').read_bytes()))
    return freeze


def freeze_candidate(source: Path, destination: Path):
    if destination.exists():
        raise ValueError('freeze_requires_fresh_directory')
    verify(source, json.loads(SOURCE.read_bytes()))
    data = {name: (source / name).read_bytes() for name in FILES[:4]}
    data.update({'source.json': SOURCE.read_bytes(),
                 'NOTICE.md': (SOURCE.parent / 'NOTICE.md').read_bytes()})
    manifest = {'schema': 'm7-frozen-candidate-1', 'independent_review': 'pending',
                'files': {n: digest(v) for n, v in data.items()}}
    raw = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix='.freeze-') as temp:
        stage = Path(temp) / 'candidate'
        stage.mkdir()
        for name, payload in data.items():
            (stage / name).write_bytes(payload)
        (stage / 'freeze.json').write_bytes(raw)
        anchor = digest(raw)
        verify_frozen(stage, anchor)
        stage.rename(destination)
    return anchor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('create', 'verify'))
    parser.add_argument('--source', type=Path, default=SOURCE.parent / 'pilot')
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--expected-sha256')
    args = parser.parse_args()
    if args.mode == 'create':
        print(json.dumps({'freeze_sha256': freeze_candidate(args.source, args.directory),
                          'independent_review': 'pending'}))
    else:
        if not args.expected_sha256:
            parser.error('--expected-sha256 is required; keep it outside the frozen copy')
        print(json.dumps(verify_frozen(args.directory, args.expected_sha256)))


if __name__ == '__main__':
    main()
