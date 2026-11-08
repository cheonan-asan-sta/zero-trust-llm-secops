"""Validate current-image paired scan evidence without granting a vulnerability waiver.

The scanner runner updates only a disposable DB copy, then scans offline.
This module checks source/image/DB bindings and retains every native finding.
"""

import argparse
import json
import math
import re
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from scripts import compare_supply_chain as scan
from scripts import runtime_release as release
from scripts.review_supply_chain import Campaign, require

MAX_DB_AGE = timedelta(hours=120)
IMAGE = re.compile(r'sha256:[a-f0-9]{64}\Z')


def source_manifest():
    value = release.capture(scan.ROOT, {})['payload']['files']
    for name in ('README.md', 'infra/supply-chain/tools.lock.json',
                 'infra/observability/tools.lock.json', 'infra/observability/alerts.yaml'):
        value[name] = release.file_digest(scan.ROOT / name)
    return dict(sorted(value.items()))


def database_age(document, observed_at):
    """Both providers must report bounded-age UTC instants, including offline reuse."""
    now = datetime.fromisoformat(observed_at)
    require(now.utcoffset() == timedelta(0), 'scan_time_not_utc')
    values = {'grype': document['grype']['built'],
              'trivy': document['trivy']['VulnerabilityDB']['UpdatedAt']}
    require(document['grype'].get('valid') is True, 'grype_database_invalid')
    ages = {}
    for name, value in values.items():
        built = datetime.fromisoformat(value)
        require(built.utcoffset() == timedelta(0), 'database_time_not_utc')
        age = now - built
        require(-timedelta(minutes=10) <= age <= MAX_DB_AGE, 'database_outside_age_bound')
        ages[name] = {'built': value, 'age_seconds': age.total_seconds()}
    return ages


def verify_source(proof, expected):
    require(proof.get('schema') == 'c03-current-image-proof-1', 'image_proof_schema')
    require(IMAGE.fullmatch(proof.get('image_id', '')) is not None, 'image_proof_id')
    require(proof.get('platform') == 'linux/amd64' and proof.get('source_lf_sha256') == expected
            and bool(expected), 'image_source_mismatch')
    require(type(proof.get('runtime_security_checks')) is int and proof['runtime_security_checks'] == 23
            and proof.get('runtime_security_passed') is True, 'runtime_patch_verification_missing')
    require(proof.get('source_commit') and re.fullmatch(r'[a-f0-9]{40}', proof['source_commit']),
            'image_source_commit')


def current_review(summary_path, raw_directory, pin, proof, expected_source):
    campaign = Campaign(summary_path, pin, raw_directory)
    value = campaign.summary
    verify_source(proof, expected_source)
    require(value.get('schema') == 'c03-pilot-1' and value.get('completed') is True,
            'current_scan_incomplete')
    require(value['app_image_id'] == proof['image_id'] and value['source_commit'] == proof['source_commit'],
            'current_scan_source_binding')
    require(value['tools'] == json.loads((scan.ROOT / 'infra/supply-chain/tools.lock.json').read_text('utf-8')),
            'scanner_lock_drift')
    require(value['conditions'] == {'cpus': 2, 'memory_bytes': 2147483648, 'pids': 128,
            'uid': 10001, 'scan_network': 'none', 'db_storage': 'Docker Linux named volume'},
            'current_scan_conditions')
    require(type(value['repeats']) is int and value['repeats'] == 3, 'current_scan_repeats')
    require(bool(value['db_files']) and value['db_files'] == value['db_files_after'], 'database_drift')
    versions = {t['name']: t['tag'].removeprefix('v') for t in value['tools']['tools']}
    required = {f'{prefix}-{tool}' for prefix in ['warmup', 'run-1', 'run-2', 'run-3']
                for tool in ('syft', 'grype', 'trivy')}
    required |= {'grype-db-status', 'trivy-db-status', 'db-hashes-before', 'db-hashes-after'}
    required |= {f'control-{v}-{s}' for v in ('2.31.0', '2.32.0') for s in ('grype', 'trivy')}
    runs = value['runs']
    labels = [r['label'] for r in runs]
    require(len(labels) == len(set(labels)) and required <= set(labels), 'current_scan_stage_missing')
    allowed_network = {'grype-db-update', 'trivy-db-update'}
    for row in runs:
        require(type(row['container_exit']) is int and row['container_exit'] == 0
                and type(row['metrics'].get('exit_code')) is int and row['metrics']['exit_code'] == 0,
                'current_scan_stage_failed')
        require(row['network'] == ('bridge' if row['label'] in allowed_network else 'none'),
                'current_scan_network')
        require(type(row['docker_wall_seconds']) in (int, float)
                and math.isfinite(row['docker_wall_seconds']) and row['docker_wall_seconds'] >= 0,
                'current_scan_duration')
    status = {tool: campaign.read(tool + '-db-status.stdout') for tool in ('grype', 'trivy')}
    freshness = database_age(status, value['scan_started_at'])
    observed = {'grype': [], 'trivy': []}
    inventories = {'syft': [], 'trivy': []}
    for prefix in ['warmup', 'run-1', 'run-2', 'run-3']:
        for tool in ('syft', 'grype', 'trivy'):
            doc = campaign.checked(prefix + '-' + tool)
            image_id = (doc.get('Metadata', {}).get('ImageID') if tool == 'trivy' else
                doc.get('source', {}).get('metadata' if tool == 'syft' else 'target', {}).get('imageID'))
            require(image_id == proof['image_id'], 'current_scan_image_mismatch')
            version = doc.get('Trivy', {}).get('Version') if tool == 'trivy' else doc.get('descriptor', {}).get('version')
            require(version == versions[tool], 'current_scanner_version')
            if tool != 'syft':
                observed[tool].append(scan.findings(doc, tool))
            if tool != 'grype':
                inventories[tool].append((scan.syft_packages if tool == 'syft' else scan.trivy_packages)(doc))
    require(all(all(r == rows[0] for r in rows) for rows in [*observed.values(), *inventories.values()]),
            'current_repeat_drift')
    installed = campaign.read('installed.json')
    expected_inventory = {scan.canonical_package('pypi', n, v) for n, v in installed['pypi']}
    for line in installed['deb'].splitlines():
        name, version, state = line.split('\t')
        if state == 'installed':
            expected_inventory.add(scan.canonical_package('deb', name, version))
    require(value['results']['inventory']['installed_metadata'] == sorted(map(list, expected_inventory)),
            'installed_metadata_summary_drift')
    for tool in ('syft', 'trivy'):
        actual = inventories[tool][0]
        require(value['results']['inventory'][tool] == {
            'observed': sorted(map(list, actual)),
            'missing_installed_metadata': sorted(map(list, expected_inventory - actual)),
            'additional_to_installed_metadata': sorted(map(list, actual - expected_inventory)),
            'matched_count': len(actual & expected_inventory)}, 'inventory_summary_drift')
    for tool in ('grype', 'trivy'):
        require(sorted(map(list, observed[tool][0])) == value['results']['findings'][tool]['rows'],
                'current_findings_summary_drift')
        for version, expected in [('2.31.0', True), ('2.32.0', False)]:
            doc = campaign.checked(f'control-{version}-{tool}')
            ids = {r[-1] for r in scan.findings(doc, tool)}
            if tool == 'grype':
                ids |= {v['id'] for r in doc['matches'] for v in r.get('relatedVulnerabilities', [])}
            require(bool(ids & {'CVE-2024-35195', 'GHSA-9wx4-h78v-vm56'}) == expected,
                    'current_control_failed')
    rows = []
    for tool in ('grype', 'trivy'):
        for ecosystem, name, version, advisory in sorted(observed[tool][0]):
            rows.append({'scanner': tool, 'ecosystem': ecosystem, 'package': name, 'version': version,
                'native_advisory': advisory, 'applicability': 'pending_independent_review', 'suppressed': False})
    return {'schema': 'c03-current-review-1', 'image_id': proof['image_id'], 'source_commit': proof['source_commit'],
        'trusted_summary_sha256': pin, 'verified_raw_inputs': campaign.used,
        'source_lf_sha256': expected_source, 'database_files': value['db_files'], 'database_freshness': freshness,
        'scan_started_at': value['scan_started_at'], 'repeats': 3,
        'counts': {s: len(observed[s][0]) for s in ('grype', 'trivy')},
        'inventory_comparison': value['results']['inventory'],
        'ecosystems': dict(sorted(Counter(r['ecosystem'] for r in rows).items())),
        'inventory_scope': 'Debian/Python installed metadata comparison; embedded binary findings retained separately',
        'finding_rows': rows, 'security_gate_passed': False, 'production_approved': False,
        'independent_review_complete': False}


def pair_reviews(app, monitoring):
    require(app['schema'] == monitoring['schema'] == 'c03-current-review-1', 'pair_review_schema')
    require(app['image_id'] != monitoring['image_id'], 'pair_same_image')
    require(app['source_commit'] == monitoring['source_commit']
            and app['source_lf_sha256'] == monitoring['source_lf_sha256'], 'pair_source_drift')
    require(bool(app['database_files']) and app['database_files'] == monitoring['database_files'], 'pair_database_drift')
    require(all(v['independent_review_complete'] is False and v['security_gate_passed'] is False
                and v['production_approved'] is False for v in (app, monitoring)), 'pair_approval_overclaim')
    return {'schema': 'c03-current-pair-1', 'source_commit': app['source_commit'],
        'source_lf_sha256': app['source_lf_sha256'], 'same_database_snapshot': True,
        'images': {'application': app, 'monitoring': monitoring},
        'status': 'local_scan_verified_independent_review_pending', 'security_gate_passed': False,
        'production_approved': False, 'all_runtime_images_covered': False,
        'limits': ['Application and Prometheus/Alertmanager image only; not CA, DB, NGINX, Lambda or test images.',
                   'Different DB/image from historical evidence: finding deltas are not remediation efficacy.',
                   'No suppression, exploit/reachability proof, independent review or production approval.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--summary', type=Path, required=True)
    parser.add_argument('--summary-sha256', required=True)
    parser.add_argument('--raw-directory', type=Path, required=True)
    parser.add_argument('--proof', type=Path, required=True)
    parser.add_argument('--source-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    expected = json.loads(args.source_manifest.read_text('utf-8'))
    require(expected == source_manifest(), 'current_source_manifest_drift')
    report = current_review(args.summary, args.raw_directory, args.summary_sha256,
        json.loads(args.proof.read_text('utf-8')), expected)
    with args.output.open('x', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(json.dumps({'status': 'reported', 'counts': report['counts'], 'security_gate_passed': False}))


if __name__ == '__main__':
    main()
