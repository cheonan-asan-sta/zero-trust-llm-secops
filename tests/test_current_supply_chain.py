import copy
import hashlib
import json

import pytest

from scripts import current_supply_chain as current

IMAGE = 'sha256:' + 'a' * 64
COMMIT = 'b' * 40
CVE = 'CVE-2024-35195'
NOW = '2026-11-08T12:30:00+00:00'


@pytest.fixture
def evidence(tmp_path):
    raw = tmp_path / 'out'
    raw.mkdir()
    lock = json.loads((current.scan.ROOT / 'infra/supply-chain/tools.lock.json').read_text('utf-8'))
    versions = {t['name']: t['tag'].removeprefix('v') for t in lock['tools']}
    s = {'schema': 'c03-pilot-1', 'completed': True, 'source_commit': COMMIT, 'app_image_id': IMAGE,
        'repeats': 3, 'conditions': {'cpus': 2, 'memory_bytes': 2147483648, 'pids': 128,
            'uid': 10001, 'scan_network': 'none', 'db_storage': 'Docker Linux named volume'},
        'scan_started_at': NOW, 'tools': lock, 'db_files': {'db': 'c' * 64},
        'db_files_after': {'db': 'c' * 64}, 'runs': [],
        'results': {'raw_artifacts': {}, 'findings': {}, 'inventory': {}}}

    def write(name, value):
        data = json.dumps(value).encode()
        (raw / name).write_bytes(data)
        s['results']['raw_artifacts']['out/' + name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

    def stage(label):
        s['runs'].append({'label': label, 'container_exit': 0, 'metrics': {'exit_code': 0},
                          'network': 'none', 'docker_wall_seconds': 1.0})

    for tool in ('grype', 'trivy'):
        write(tool + '-db-status.stdout', {'built': '2026-11-08T12:00:00Z', 'valid': True}
              if tool == 'grype' else {'VulnerabilityDB': {'UpdatedAt': '2026-11-08T12:00:00Z'}})
        stage(tool + '-db-status')
    for phase in ('before', 'after'):
        stage('db-hashes-' + phase)
    package = ('pypi', 'requests', '2.31.0')
    for prefix in ('warmup', 'run-1', 'run-2', 'run-3'):
        for tool in ('syft', 'grype', 'trivy'):
            if tool == 'syft':
                doc = {'artifacts': [{'type': 'python', 'name': 'requests', 'version': '2.31.0'}]}
            elif tool == 'grype':
                doc = {'matches': [{'artifact': {'type': 'python', 'name': 'requests', 'version': '2.31.0'},
                                    'vulnerability': {'id': CVE}}]}
            else:
                doc = {'Results': [{'Type': 'python-pkg', 'Packages': [{'Name': 'requests', 'Version': '2.31.0'}],
                    'Vulnerabilities': [{'PkgName': 'requests', 'InstalledVersion': '2.31.0', 'VulnerabilityID': CVE}]}]}
            if tool == 'trivy':
                doc.update(Metadata={'ImageID': IMAGE}, Trivy={'Version': versions[tool]})
            else:
                doc.update(source={'metadata' if tool == 'syft' else 'target': {'imageID': IMAGE}},
                           descriptor={'version': versions[tool]})
            write(prefix + '-' + tool + '.json', doc)
            write(prefix + '-' + tool + '.metrics.json', {'exit_code': 0})
            stage(prefix + '-' + tool)
    for tool in ('grype', 'trivy'):
        s['results']['findings'][tool] = {'rows': [[*package, CVE]]}
        for version in ('2.31.0', '2.32.0'):
            if tool == 'grype':
                doc = {'matches': [] if version == '2.32.0' else [{'artifact': {'type': 'python',
                    'name': 'requests', 'version': version}, 'vulnerability': {'id': CVE}}]}
            else:
                doc = {'Results': [{'Type': 'python-pkg', 'Vulnerabilities': [] if version == '2.32.0' else [
                    {'PkgName': 'requests', 'InstalledVersion': version, 'VulnerabilityID': CVE}]}]}
            label = f'control-{version}-{tool}'
            write(label + '.json', doc)
            write(label + '.metrics.json', {'exit_code': 0})
            stage(label)
    write('installed.json', {'pypi': [['requests', '2.31.0']], 'deb': ''})
    inv = {'observed': [list(package)], 'missing_installed_metadata': [],
           'additional_to_installed_metadata': [], 'matched_count': 1}
    s['results']['inventory'] = {'installed_metadata': [list(package)], 'syft': inv, 'trivy': inv.copy()}
    source = {'scripts/candidate.py': 'd' * 64}
    proof = {'schema': 'c03-current-image-proof-1', 'image_id': IMAGE, 'platform': 'linux/amd64',
             'source_lf_sha256': source.copy(), 'runtime_security_checks': 23,
             'runtime_security_passed': True, 'source_commit': COMMIT}
    path = tmp_path / 'summary.json'

    def review():
        path.write_text(json.dumps(s), encoding='utf-8')
        return current.current_review(path, raw, hashlib.sha256(path.read_bytes()).hexdigest(), proof, source)
    return s, proof, source, raw, write, review


def test_full_evidence_keeps_all_findings_pending_and_verifies_raw_inputs(evidence):
    report = evidence[-1]()
    assert report['counts'] == {'grype': 1, 'trivy': 1}
    assert report['database_freshness']['grype']['age_seconds'] == 1800
    assert len(report['finding_rows']) == 2 and len(report['verified_raw_inputs']) > 25
    assert all(r['applicability'] == 'pending_independent_review' and not r['suppressed'] for r in report['finding_rows'])
    assert not any(report[k] for k in ('security_gate_passed', 'production_approved', 'independent_review_complete'))


@pytest.mark.parametrize('tool', ['grype', 'trivy'])
@pytest.mark.parametrize('date', ['2026-11-01T12:00:00Z', '2026-11-09T12:00:00Z',
                                 '2026-11-08T12:00:00', '2026-11-08T12:00:00+09:00'])
def test_old_future_naive_and_non_utc_database_times_are_rejected(tool, date):
    doc = {'grype': {'built': '2026-11-08T12:00:00Z', 'valid': True},
           'trivy': {'VulnerabilityDB': {'UpdatedAt': '2026-11-08T12:00:00Z'}}}
    if tool == 'grype':
        doc[tool]['built'] = date
    else:
        doc[tool]['VulnerabilityDB']['UpdatedAt'] = date
    with pytest.raises(ValueError):
        current.database_age(doc, NOW)


@pytest.mark.parametrize('fault', ['complete','db','source','image','network','exit','duration','duplicate',
                                 'missing','inventory','findings','proof','patch','version','control','raw'])
def test_corruption_and_incomplete_inputs_fail_closed(evidence, fault):
    s, proof, _source, raw, write, review = evidence
    if fault == 'complete': s['completed'] = False
    elif fault == 'db': s['db_files_after']['db'] = 'f' * 64
    elif fault == 'source': s['source_commit'] = 'e' * 40
    elif fault == 'image': s['app_image_id'] = 'sha256:' + 'e' * 64
    elif fault == 'network': s['runs'][0]['network'] = 'bridge'
    elif fault == 'exit': s['runs'][0]['metrics']['exit_code'] = 1
    elif fault == 'duration': s['runs'][0]['docker_wall_seconds'] = -1
    elif fault == 'duplicate': s['runs'].append(copy.deepcopy(s['runs'][0]))
    elif fault == 'missing': s['runs'] = s['runs'][1:]
    elif fault == 'inventory': s['results']['inventory']['syft']['matched_count'] = 9
    elif fault == 'findings': s['results']['findings']['grype']['rows'] = []
    elif fault == 'proof': proof['source_lf_sha256'] = {'scripts/candidate.py': 'f' * 64}
    elif fault == 'patch': proof['runtime_security_passed'] = False
    elif fault == 'version':
        path = raw / 'run-1-syft.json'
        doc = json.loads(path.read_text()); doc['descriptor']['version'] = '0'
        write(path.name, doc)
    elif fault == 'control':
        write('control-2.31.0-grype.json', {'matches': []})
    else:
        (raw / 'run-1-syft.json').write_text('{}')
    with pytest.raises(ValueError): review()


@pytest.mark.parametrize('fault', ['same_image', 'db', 'source', 'approved'])
def test_two_image_pair_requires_same_source_and_database_without_approval_overclaim(evidence, fault):
    a = evidence[-1](); b = copy.deepcopy(a); b['image_id'] = 'sha256:' + 'e' * 64
    if fault == 'same_image': b['image_id'] = a['image_id']
    elif fault == 'db': b['database_files'] = {'db': 'f' * 64}
    elif fault == 'source': b['source_lf_sha256']['scripts/candidate.py'] = 'f' * 64
    else: b['production_approved'] = True
    with pytest.raises(ValueError): current.pair_reviews(a, b)


def test_pair_scope_stays_explicit(evidence):
    a = evidence[-1](); b = copy.deepcopy(a); b['image_id'] = 'sha256:' + 'e' * 64
    result = current.pair_reviews(a, b)
    assert result['same_database_snapshot'] and not result['all_runtime_images_covered']
    assert result['status'] == 'local_scan_verified_independent_review_pending'
