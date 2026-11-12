"""Enrich pinned raw observations; copy truth unchanged and compute causal HTTP history."""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

from scripts.f1_lab.native_jsonl import MAX_FILE, MAX_ROW, decode, require
from scripts.f1_lab.raw_context import PROFILE, extra_observations, ordered_http_context
from scripts.f1_lab.raw_observations import REQUEST, raw_features, raw_time
from scripts.f1_lab.vpn_context import PROFILE as VPN_PROFILE
from scripts.f1_lab.vpn_context import empty as empty_vpn
from scripts.f1_lab.vpn_context import ordered_vpn_context
from scripts.fit_native_raw import receipt


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def prepare(base, expected_base_sha256, pairs_directory, output, *, profile=PROFILE):
    require(profile in {PROFILE, VPN_PROFILE}, 'context_feature_profile')
    base, pairs_directory, output = Path(base), Path(pairs_directory), Path(output)
    original = receipt(base, expected_base_sha256)
    require(original.get('feature_profile', 'base') == 'base', 'context_requires_base_profile')
    manifest_path = pairs_directory/'audit.json'
    require(manifest_path.is_file() and not manifest_path.is_symlink() and manifest_path.stat().st_size <= 1024**2,
            'context_source_manifest')
    manifest_body = manifest_path.read_bytes()
    require(hashlib.sha256(manifest_body).hexdigest() == original['source_manifest_sha256'], 'context_manifest_hash')
    source_manifest = decode(manifest_body)
    require(source_manifest.get('completed') is True and len(source_manifest['pairs']) == len(original['pairs']),
            'context_pair_population')
    require(not output.exists() and not output.is_symlink(), 'fresh_context_output')
    output.mkdir(parents=True, mode=0o700)
    report = {**original, 'completed': False, 'feature_profile': profile, 'files': {},
              'base_preparation_sha256': expected_base_sha256,
              'context': 'HTTP per physical source and client; event-time order with original ordinal ties; current and past only',
              'truth_copied_unchanged': False, 'http_context': [], 'goal_qualified': False}
    if profile == VPN_PROFILE:
        report['vpn_context'] = 'one source/host endpoint history; strictly earlier timestamps; equal-time batch withheld; 24-hour lookback; no authority claims'
    try:
        base_input = base/'inputs.jsonl'
        require(base_input.is_file() and not base_input.is_symlink()
                and base_input.stat().st_size == original['files']['inputs.jsonl']['bytes'], 'context_base_inputs')
        input_sha = hashlib.sha256()
        with base_input.open('rb') as previous, (output/'inputs.jsonl.part').open('xb') as target:
            for i, pair in enumerate(original['pairs']):
                provenance = source_manifest['pairs'][i]['provenance']
                require(pair['raw_sha256'] == provenance['raw_sha256'], 'context_pair_anchor')
                source = pairs_directory/f'pair-{i}-raw.source'
                require(source.is_file() and not source.is_symlink() and source.stat().st_size <= MAX_FILE, 'context_raw_file')
                sha, count, total, requests, vpn_records = hashlib.sha256(), 0, 0, [], []
                with source.open('rb') as stream:
                    while body := stream.readline(MAX_ROW+1):
                        count += 1
                        total += len(body)
                        require(len(body) <= MAX_ROW and count <= pair['rows'] and total <= MAX_FILE, 'context_raw_bound')
                        sha.update(body)
                        line = body.decode('utf-8', errors='replace')
                        if REQUEST.search(line):
                            try:
                                moment = raw_time(line, provenance['simulation_start'], provenance['simulation_end'], source_timezone='UTC')
                            except ValueError:
                                moment = None
                            require(len(requests) < 100000, 'context_request_population_bound')
                            requests.append((count, moment, line))
                        if profile == VPN_PROFILE and provenance['raw_member'].endswith('/openvpn.log'):
                            try:
                                moment = raw_time(line, provenance['simulation_start'], provenance['simulation_end'], source_timezone='UTC')
                            except ValueError:
                                moment = None
                            require(len(vpn_records) < 100000, 'context_vpn_population_bound')
                            vpn_records.append((count, moment, line))
                require(sha.hexdigest() == pair['raw_sha256'] and count == pair['rows'], 'context_raw_hash_or_rows')
                windows = ordered_http_context(requests)
                vpn_windows = ordered_vpn_context(vpn_records) if profile == VPN_PROFILE else {}
                histogram, sha = Counter(), hashlib.sha256()
                with source.open('rb') as stream:
                    for ordinal in range(1, pair['rows']+1):
                        body = stream.readline(MAX_ROW+1)
                        require(0 < len(body) <= MAX_ROW, 'context_raw_bound')
                        sha.update(body)
                        prior_body = previous.readline(MAX_ROW+1)
                        require(0 < len(prior_body) <= MAX_ROW, 'context_base_row_bound')
                        input_sha.update(prior_body)
                        item = decode(prior_body)
                        expected_case = hashlib.sha256((pair['raw_sha256']+':'+str(ordinal)).encode()).hexdigest()
                        require(set(item) == {'case_id', 'features', 'observation_error'}
                                and item['case_id'] == expected_case, 'context_original_row_alignment')
                        features = item['features']
                        if features is not None:
                            line = body.decode('utf-8')
                            require(features == raw_features(line), 'context_base_feature_drift')
                            extra = extra_observations(line)
                            if ordinal in windows:
                                extra.update(windows[ordinal])
                            if profile == VPN_PROFILE:
                                extra.update(vpn_windows.get(ordinal, empty_vpn()))
                            histogram.update(name for name, value in extra.items() if value is True)
                            features = {**features, **extra}
                        target.write(canonical({**item, 'features': features})+b'\n')
                    require(not stream.read(1) and sha.hexdigest() == pair['raw_sha256'], 'context_raw_changed')
                report['http_context'].append({'raw_member': pair['raw_member'], 'requests': len(requests),
                                               'positive_extra_flags': dict(histogram)})
            require(not previous.read(1) and input_sha.hexdigest() == original['files']['inputs.jsonl']['sha256'],
                    'context_base_hash_or_rows')
        # Truth and provenance are opaque byte copies, not sources of features.
        for name in ('truth.jsonl', 'references.jsonl'):
            path = base/name
            require(path.is_file() and not path.is_symlink() and path.stat().st_size == original['files'][name]['bytes'],
                    'context_sidecar_file')
            sha = hashlib.sha256()
            with path.open('rb') as stream, (output/(name+'.part')).open('xb') as target:
                while body := stream.read(1024**2):
                    target.write(body)
                    sha.update(body)
            require(sha.hexdigest() == original['files'][name]['sha256'], 'context_sidecar_hash')
        for name in ('inputs.jsonl', 'truth.jsonl', 'references.jsonl'):
            partial, sha = output/(name+'.part'), hashlib.sha256()
            with partial.open('rb') as stream:
                while body := stream.read(1024**2):
                    sha.update(body)
            partial.rename(output/name)
            report['files'][name] = {'sha256': sha.hexdigest(), 'bytes': (output/name).stat().st_size}
        report['truth_copied_unchanged'] = report['files']['truth.jsonl'] == original['files']['truth.jsonl']
        require(report['truth_copied_unchanged'], 'context_truth_changed')
        report['completed'] = True
    except (OSError, ValueError, TypeError, KeyError) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        (output/'preparation.json').write_bytes(canonical(report)+b'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-directory', required=True, type=Path)
    parser.add_argument('--expected-base-sha256', required=True)
    parser.add_argument('--pairs-directory', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--feature-profile', choices=(PROFILE, VPN_PROFILE), default=PROFILE)
    args = parser.parse_args()
    report = prepare(args.base_directory, args.expected_base_sha256, args.pairs_directory, args.output,
                     profile=args.feature_profile)
    print(json.dumps({key: report[key] for key in ('completed', 'truth_copied_unchanged', 'http_context', 'goal_qualified')}))


if __name__ == '__main__':
    main()
