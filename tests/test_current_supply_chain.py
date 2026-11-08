import copy
import hashlib
import json
from types import SimpleNamespace

import pytest

from scripts import current_supply_chain as current
from scripts import test_current_supply_chain_runtime as runtime

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
        'repeats': 3, 'trivy_scan_timeout': '15m', 'conditions': {'cpus': 2, 'memory_bytes': 2147483648, 'pids': 128,
            'uid': 10001, 'scan_network': 'none', 'db_storage': 'Docker Linux named volume',
            'scratch_tmpfs_bytes': 1536 * 1024**2},
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
                                 'missing','inventory','findings','proof','patch','version','control','raw','timeout'])
def test_corruption_and_incomplete_inputs_fail_closed(evidence, fault):
    s, proof, _source, raw, write, review = evidence
    if fault == 'complete': s['completed'] = False
    elif fault == 'db': s['db_files_after']['db'] = 'f' * 64
    elif fault == 'source': s['source_commit'] = 'e' * 40
    elif fault == 'image': s['app_image_id'] = 'sha256:' + 'e' * 64
    elif fault == 'network': s['runs'][0]['network'] = 'bridge'
    elif fault == 'exit': s['runs'][0]['metrics']['exit_code'] = 1
    elif fault == 'timeout': s.pop('trivy_scan_timeout')
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


@pytest.mark.parametrize('fault', [None, 'source', 'runtime'])
def test_image_probe_has_bounded_scratch_space_without_writable_root_or_network(monkeypatch, fault):
    calls = []
    expected = {'scripts/candidate.py': 'c' * 64}

    def command(argv):
        if argv[1:3] == ['image', 'inspect']:
            return json.dumps([{'Id': IMAGE, 'Os': 'linux', 'Architecture': 'amd64'}])
        calls.append(argv)
        return json.dumps({'passed': fault != 'runtime', 'checks': {str(i): True for i in range(23)}})

    def process(argv, **kwargs):
        calls.append(argv)
        assert json.loads(kwargs['input']) == list(expected)
        return SimpleNamespace(stdout=json.dumps(expected if fault != 'source' else {}))

    monkeypatch.setattr(runtime.scan, 'run', command)
    monkeypatch.setattr(runtime.subprocess, 'run', process)
    if fault:
        with pytest.raises(ValueError): runtime.image_proof(IMAGE, expected, COMMIT, 'c03-owned')
    else:
        proof = runtime.image_proof(IMAGE, expected, COMMIT, 'c03-owned')
        assert proof['runtime_security_checks'] == 23 and len(calls) == 2
    for argv in calls:
        assert '--read-only' in argv and '--cap-drop=ALL' in argv and '--security-opt=no-new-privileges:true' in argv
        assert argv[argv.index('--network') + 1] == 'none'
        mounts = [argv[i+1] for i, a in enumerate(argv[:-1]) if a == '--tmpfs']
        assert any(m.startswith('/tmp:rw,nosuid,nodev,size=64m,') for m in mounts)
        assert any(m.startswith('/data:rw,nosuid,nodev,size=1m,') for m in mounts)


def test_cleanup_reads_docker_inspect_as_utf8_and_refuses_foreign_owner(monkeypatch):
    cleaned = []
    pilot = SimpleNamespace(containers=['c03-owned'], ident='c03-owned', cleanup=lambda: cleaned.append(True))
    def inspect(argv, **kwargs):
        assert kwargs['encoding'] == 'utf-8'
        return SimpleNamespace(returncode=0, stdout=json.dumps([{'Name': '/c03-owned',
            'Config': {'Labels': {'secops.c03': 'foreign'}, 'WorkingDir': '/한글'}}], ensure_ascii=False))
    monkeypatch.setattr(runtime.subprocess, 'run', inspect)
    with pytest.raises(ValueError, match='current_cleanup_ownership'):
        runtime.owned_cleanup(pilot)
    assert not cleaned


def test_cleanup_releases_all_cross_copy_mounts_before_removing_any_database(monkeypatch):
    pilots = [SimpleNamespace(ident=n, cache_volume=n+'-db') for n in ('c03-a', 'c03-b')]
    cleaned = []
    monkeypatch.setattr(runtime, 'owned_cleanup', lambda p: cleaned.append(p.ident))
    def process(argv, **kwargs):
        assert kwargs['encoding'] == 'utf-8' and len(cleaned) == 2
        owner = argv[-1].removesuffix('-db')
        return SimpleNamespace(returncode=0, stdout=json.dumps([{'Labels': {'secops.c03': owner}}]))
    removed = []
    def command(argv):
        if argv[1:3] == ['volume', 'rm']:
            assert len(cleaned) == 2
            removed.append(argv[-1])
        return ''
    monkeypatch.setattr(runtime.subprocess, 'run', process)
    monkeypatch.setattr(runtime.scan, 'run', command)
    cleanup, errors = runtime.cleanup_pilots(pilots, 'c03-build')
    assert removed == ['c03-a-db', 'c03-b-db']
    assert cleanup == {'owned_resources_remaining': 0} and not errors


@pytest.mark.parametrize('scratch', [512, 1536])
def test_scanner_scratch_budget_preserves_memory_cpu_and_network_boundaries(tmp_path, monkeypatch, scratch):
    pilot = object.__new__(current.scan.Pilot)
    pilot.directory, pilot.ident = tmp_path, 'c03-owned'
    pilot.cache_volume, pilot.runner_image = 'c03-owned-db', 'c03-owned-runner'
    pilot.scratch_mib, pilot.containers, pilot.report = scratch, [], {'runs': []}
    (tmp_path/'out').mkdir()
    def process(argv, **kwargs):
        assert f'/tmp:rw,nosuid,nodev,size={scratch}m' in argv
        assert '--memory=2g' in argv and '--memory-swap=2g' in argv and '--cpus=2' in argv
        assert argv[argv.index('--network')+1] == 'none'
        assert '--read-only' in argv and '--cap-drop=ALL' in argv
        (tmp_path/'out/probe.metrics.json').write_text('{"exit_code":0}')
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    monkeypatch.setattr(current.scan.subprocess, 'run', process)
    pilot.container('probe', ['/tools/syft','version'])
    assert pilot.report['runs'][0]['metrics']['exit_code'] == 0
