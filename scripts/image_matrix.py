"""Explicit seven-image C03 contracts; no finding suppression or production approval."""

import json
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from scripts import compare_supply_chain as scan
from scripts import current_supply_chain as current
from scripts import runtime_release as release
from scripts.review_supply_chain import Campaign, require

PROFILES = ('application', 'monitoring', 'authority', 'database', 'nginx', 'lambda', 'tests')
PYTHON_PROFILES = frozenset(PROFILES) - {'database', 'nginx'}
ROOT_FILES = {'README.md', 'pyproject.toml', 'Dockerfile', 'Dockerfile.lambda', 'Dockerfile.test',
              '.dockerignore', 'compose.yaml', 'compose.signals.yaml'}
TEXT = {'.py', '.md', '.toml', '.json', '.jsonl', '.txt', '.yaml', '.yml', '.sh', '.conf', '.lock', '.csv', '.xml',
        '.js', '.css', '.html', '.svg', '.patch', '.c', '.h', '.sql', '.cfg', '.ini', '.pem'}
OS_TYPES = {'debian': 'deb', 'alpine': 'apk', 'amazon': 'rpm', 'redhat': 'rpm',
            'centos': 'rpm', 'rocky': 'rpm', 'oracle': 'rpm', 'alma': 'rpm', 'suse': 'rpm'}


def text_input(name):
    return Path(name).suffix.lower() in TEXT or Path(name).name.startswith('Dockerfile') or name == '.dockerignore'


def manifest():
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=scan.ROOT).decode('utf-8').split('\0')
    result = {}
    for name in sorted(names):
        if name and (name in ROOT_FILES or name.startswith(('app/', 'scripts/', 'infra/', 'docs/', 'tests/', '.github/'))):
            path = scan.ROOT/name
            require(path.is_file() and not path.is_symlink(), 'matrix_regular_source_input')
            result[name] = release.file_digest(path) if text_input(name) else scan.sha256(path)
    return result


def payload_paths(profile, source):
    require(profile in PROFILES, 'matrix_profile')
    if profile not in PYTHON_PROFILES:
        return {}
    root = '/var/task' if profile == 'lambda' else '/workspace' if profile == 'tests' else '/app'
    result = {}
    for name in source:
        included = (profile == 'tests' or name.startswith(('app/', 'infra/runtime/'))
                    or name in {'README.md', 'pyproject.toml'}
                    or (profile != 'lambda' and name.startswith('scripts/')))
        if not included:
            continue
        if name.startswith('infra/runtime/') and profile != 'tests':
            result[name] = '/opt/secops-runtime/install/' + name.removeprefix('infra/runtime/')
        else:
            result[name] = root + '/' + name
        if profile == 'tests' and name.startswith('infra/runtime/'):
            result['installed-runtime:'+name] = '/opt/secops-runtime/install/' + name.removeprefix('infra/runtime/')
    return result


def expected_payload(profile, source):
    return {name: source[name.removeprefix('installed-runtime:')] for name in payload_paths(profile, source)}


def epoch_version(version, release_part='', epoch=None):
    require(isinstance(version, str) and bool(version), 'matrix_package_version')
    result = version + ('-' + release_part if release_part else '')
    if epoch not in (None, '', '(none)', 0, '0'):
        require(str(epoch).isdigit(), 'matrix_package_epoch')
        result = str(int(epoch)) + ':' + result
    return result


def installed_inventory(value):
    require(value.get('schema') == 'c03-installed-packages-1' and value.get('manager') in {'deb', 'apk', 'rpm'},
            'matrix_installed_schema')
    rows = value['packages']
    require(isinstance(rows, list) and bool(rows), 'matrix_installed_empty')
    result = {scan.canonical_package(value['manager'], row['name'], row['version']) for row in rows}
    result |= {scan.canonical_package('pypi', n, v) for n, v in value['pypi']}
    return result


def syft_inventory(value):
    result = set()
    for row in value['artifacts']:
        kind = row['type']
        if kind not in {'python', 'deb', 'apk', 'rpm'}:
            continue
        version = row['version']
        if kind == 'rpm':
            metadata = row['metadata']
            version = epoch_version(metadata['version'], metadata['release'], metadata.get('epoch'))
        result.add(scan.canonical_package(kind, row['name'], version))
    return result


def trivy_inventory(value):
    result = set()
    for row in value.get('Results', []):
        kind = OS_TYPES.get(row.get('Type'), 'pypi' if row.get('Type') == 'python-pkg' else None)
        if kind is None:
            continue
        for package in row.get('Packages', []):
            version = epoch_version(package['Version'], package.get('Release', ''), package.get('Epoch'))
            result.add(scan.canonical_package(kind, package['Name'], version))
    return result


READERS = {'syft': syft_inventory, 'trivy': trivy_inventory}
CONDITIONS = {**current.CURRENT_CONDITIONS, 'memory_bytes': 3*1024**3, 'scratch_tmpfs_bytes': 2*1024**3}
JAVA_FILES = {'trivy/java-db/trivy-java.db', 'trivy/java-db/metadata.json'}


def java_database_age(metadata, observed_at):
    require(metadata.get('Version') == 1, 'matrix_java_db_schema')
    now, built = datetime.fromisoformat(observed_at), datetime.fromisoformat(metadata['UpdatedAt'])
    require(now.utcoffset() == built.utcoffset() == timedelta(0), 'matrix_java_db_not_utc')
    age = now-built
    require(-timedelta(minutes=10) <= age <= current.MAX_DB_AGE, 'matrix_java_db_outside_age_bound')
    return {'built': metadata['UpdatedAt'], 'age_seconds': age.total_seconds(), 'version': metadata['Version']}


def verify_proof(proof, source):
    require(proof.get('schema') == 'c03-matrix-image-proof-1', 'matrix_proof_schema')
    profile = proof.get('profile')
    require(profile in PROFILES and proof.get('platform') == 'linux/amd64', 'matrix_profile_platform')
    require(current.IMAGE.fullmatch(proof.get('image_id', '')) is not None, 'matrix_image_id')
    require(re.fullmatch(r'[a-f0-9]{40}', proof.get('source_commit', '')) is not None, 'matrix_source_commit')
    require(bool(source) and proof.get('source_lf_or_raw_sha256') == source, 'matrix_source_drift')
    require(ROOT_FILES <= source.keys() and all(re.fullmatch(r'[a-f0-9]{64}', v) for v in source.values()),
            'matrix_incomplete_source_inputs')
    if profile in PYTHON_PROFILES:
        require(any(n.startswith('app/') for n in source) and any(n.startswith('infra/runtime/') for n in source),
                'matrix_missing_python_source')
    require(proof.get('payload_sha256') == expected_payload(profile, source), 'matrix_payload_drift')
    require(proof.get('image_identity_verified') is True and proof.get('build_binding_verified') is True,
            'matrix_build_binding')
    if profile in PYTHON_PROFILES:
        checks = proof.get('runtime_security_report', {}).get('checks', {})
        require(proof.get('runtime_security_report', {}).get('passed') is True and len(checks) == 23
                and all(v is True for v in checks.values()), 'matrix_python_runtime_checks')
    else:
        lock = json.loads((scan.ROOT / ('infra/mtls/ca-ha-tools.lock.json' if profile == 'database'
                                      else 'infra/pep/tools.lock.json')).read_text('utf-8'))
        reference = lock['postgres']['image'] if profile == 'database' else lock['tools']['nginx']['image']
        require(proof.get('upstream_reference') == reference and proof.get('binary_version_verified') is True,
                'matrix_upstream_binding')
    expected_binaries = {'monitoring': {'prometheus', 'promtool', 'alertmanager', 'amtool'},
                         'authority': {'prometheus', 'promtool', 'alertmanager', 'amtool', 'step', 'step-ca'}}
    if profile in expected_binaries:
        binaries = proof.get('binary_sha256', {})
        require(set(binaries) == expected_binaries[profile]
                and proof.get('binary_payload_verified') is True
                and all(re.fullmatch(r'[a-f0-9]{64}', v) for v in binaries.values()), 'matrix_binary_payload')


def review(summary_path, raw_directory, pin, proof, source):
    result = current.review_evidence(summary_path, raw_directory, pin, proof, source,
        verify_proof=verify_proof, expected_conditions=CONDITIONS,
        installed_packages=installed_inventory, inventory_readers=READERS,
        inventory_scope='Installed DEB/RPM/APK and Python metadata; binary module findings retained separately')
    require(JAVA_FILES <= set(result['database_files']), 'matrix_java_db_files_missing')
    campaign = Campaign(summary_path, pin, raw_directory)
    metrics = campaign.read('trivy-java-db-status.metrics.json')
    require(type(metrics.get('exit_code')) is int and metrics['exit_code'] == 0, 'matrix_java_db_status_failed')
    result['database_freshness']['trivy_java'] = java_database_age(
        campaign.read('trivy-java-db-status.stdout'), result['scan_started_at'])
    result['verified_raw_inputs'].update(campaign.used)
    installed = json.loads((Path(raw_directory)/'installed.json').read_text('utf-8'))
    for scanner in READERS:
        inventory = result['inventory_comparison'][scanner]['observed']
        require(any(row[0] == installed['manager'] for row in inventory), 'matrix_os_inventory_unavailable')
        if installed['pypi']:
            require(any(row[0] == 'pypi' for row in inventory), 'matrix_python_inventory_unavailable')
    result.update(schema='c03-matrix-review-1', profile=proof['profile'],
                  source_lf_or_raw_sha256=result.pop('source_lf_sha256'))
    return result


def cohort(reviews):
    require(set(reviews) == set(PROFILES), 'matrix_incomplete_catalog')
    first = reviews['application']
    require(len({r['image_id'] for r in reviews.values()}) == len(PROFILES), 'matrix_duplicate_image')
    for name, item in reviews.items():
        require(item['schema'] == 'c03-matrix-review-1' and item['profile'] == name, 'matrix_profile_swap')
        require(item['source_commit'] == first['source_commit']
                and item['source_lf_or_raw_sha256'] == first['source_lf_or_raw_sha256'],
                'matrix_cohort_source_drift')
        require(bool(item['database_files']) and item['database_files'] == first['database_files'], 'matrix_cohort_db_drift')
        require(all(item[k] is False for k in ('security_gate_passed', 'production_approved', 'independent_review_complete')),
                'matrix_approval_overclaim')
    return {'schema': 'c03-seven-image-cohort-1', 'source_commit': first['source_commit'], 'images': reviews,
            'same_database_snapshot': True, 'catalog_complete': True, 'security_gate_passed': False,
            'production_approved': False, 'independent_review_complete': False,
            'scope': list(PROFILES), 'all_builder_helper_and_ci_images_covered': False}
