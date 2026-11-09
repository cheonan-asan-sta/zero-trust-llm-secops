import copy
import hashlib
import json
from types import SimpleNamespace

import pytest
from test_current_supply_chain import (
    evidence as evidence,  # noqa: PLC0414 - pytest fixture re-export
)

from scripts import image_matrix as matrix
from scripts import test_image_matrix_runtime as runtime


def proof(profile, source):
    value = {'schema': 'c03-matrix-image-proof-1', 'profile': profile, 'image_id': 'sha256:'+'a'*64,
        'source_commit': 'b'*40, 'platform': 'linux/amd64', 'source_lf_or_raw_sha256': source,
        'payload_sha256': matrix.expected_payload(profile, source), 'image_identity_verified': True,
        'build_binding_verified': True}
    if profile in matrix.PYTHON_PROFILES:
        value['runtime_security_report'] = {'passed': True, 'checks': {str(i): True for i in range(23)}}
    if profile in {'monitoring', 'authority'}:
        names = {'prometheus', 'promtool', 'alertmanager', 'amtool'}
        if profile == 'authority':
            names |= {'step', 'step-ca'}
        value.update(binary_payload_verified=True, binary_sha256={n: 'c'*64 for n in names})
    if profile in {'nginx', 'database'}:
        name = 'infra/pep/tools.lock.json' if profile == 'nginx' else 'infra/mtls/ca-ha-tools.lock.json'
        lock = json.loads((matrix.scan.ROOT/name).read_text('utf-8'))
        value.update(binary_version_verified=True, upstream_reference=lock['tools']['nginx']['image']
                     if profile == 'nginx' else lock['postgres']['image'])
    return value


@pytest.fixture
def source():
    return {n: 'd'*64 for n in (*matrix.ROOT_FILES, 'app/main.py', 'scripts/candidate.py',
                               'infra/runtime/verify_security.py', 'docs/source.md', 'tests/example.py')}


@pytest.mark.parametrize('profile', matrix.PROFILES)
def test_profile_contract_checks_only_files_present_in_that_image(profile, source):
    value = proof(profile, source)
    matrix.verify_proof(value, source)
    paths = matrix.payload_paths(profile, source)
    if profile in {'database', 'nginx'}:
        assert not paths and 'runtime_security_report' not in value
    elif profile == 'lambda':
        assert paths['app/main.py'] == '/var/task/app/main.py' and 'scripts/candidate.py' not in paths
    elif profile == 'tests':
        assert paths['tests/example.py'] == '/workspace/tests/example.py'
        assert paths['docs/source.md'] == '/workspace/docs/source.md'
        assert paths['installed-runtime:infra/runtime/verify_security.py'].startswith('/opt/')
    else:
        assert paths['scripts/candidate.py'] == '/app/scripts/candidate.py' and 'docs/source.md' not in paths


@pytest.mark.parametrize('fault', ['id', 'platform', 'source', 'payload', 'binding', 'runtime', 'missing_inputs'])
def test_forged_or_incomplete_python_proof_is_rejected(source, fault):
    value = proof('application', source)
    if fault == 'id': value['image_id'] = 'mutable:latest'
    elif fault == 'platform': value['platform'] = 'linux/arm64'
    elif fault == 'source': value['source_lf_or_raw_sha256'] = {}
    elif fault == 'payload': value['payload_sha256'] = {}
    elif fault == 'binding': value['build_binding_verified'] = False
    elif fault == 'runtime': value['runtime_security_report']['checks']['0'] = False
    else:
        source.pop('Dockerfile.lambda')
        value['payload_sha256'] = matrix.expected_payload('application', source)
    with pytest.raises(ValueError): matrix.verify_proof(value, source)


@pytest.mark.parametrize('profile', ['database', 'nginx'])
def test_upstream_mutable_reference_is_never_accepted(profile, source):
    value = proof(profile, source); value['upstream_reference'] = profile+':latest'
    with pytest.raises(ValueError, match='matrix_upstream_binding'): matrix.verify_proof(value, source)


@pytest.mark.parametrize('profile', ['monitoring', 'authority'])
def test_missing_embedded_tool_cannot_pass_image_proof(profile, source):
    value = proof(profile, source); value['binary_sha256'].pop('promtool')
    with pytest.raises(ValueError, match='matrix_binary_payload'): matrix.verify_proof(value, source)


@pytest.mark.parametrize(('manager', 'text', 'expected'), [
    ('deb', 'bash\t1:5-2\tinstalled\nold\t1\tconfig-files\n', ('deb','bash','1:5-2')),
    ('rpm', 'openssl\t3.0.1\t5.amzn2023\t1\tx86_64\n', ('rpm','openssl','1:3.0.1-5.amzn2023')),
    ('apk', 'P:busybox\nV:1.37.0-r1\nA:x86_64\n\n', ('apk','busybox','1.37.0-r1')),
])
def test_installed_inventory_reads_native_manager_without_starting_a_service(manager, text, expected):
    value = runtime.parse_inventory('ID=test\n\nC03_MANAGER\n'+manager+'\nC03_PACKAGES\n'+text, [])
    assert matrix.installed_inventory(value) == {expected}


@pytest.mark.parametrize(('manager','text'), [('other','pkg\t1'), ('deb',''), ('rpm','a\t1\t2\tbad\tx86_64'),
                                            ('apk','P:broken\nA:x86_64')])
def test_unknown_empty_or_malformed_os_metadata_fails_closed(manager, text):
    with pytest.raises(ValueError):
        runtime.parse_inventory('ID=test\n\nC03_MANAGER\n'+manager+'\nC03_PACKAGES\n'+text, [])


def test_rpm_epoch_release_and_raw_finding_identity_are_both_preserved():
    syft = {'artifacts': [{'type':'rpm','name':'pkg','version':'1-2','metadata':{'version':'1','release':'2','epoch':3}}]}
    trivy = {'Results': [{'Type':'amazon','Packages':[{'Name':'pkg','Version':'1','Release':'2','Epoch':3}],
        'Vulnerabilities':[{'PkgName':'pkg','InstalledVersion':'3:1-2','VulnerabilityID':'CVE-2026-1234'}]}]}
    assert matrix.syft_inventory(syft) == matrix.trivy_inventory(trivy) == {('rpm','pkg','3:1-2')}
    assert matrix.scan.findings(trivy, 'trivy') == {('amazon','pkg','3:1-2','CVE-2026-1234')}


@pytest.fixture
def matrix_evidence(evidence, source):
    summary, _old_proof, _old_source, raw, write, _review = evidence
    installed = {'schema':'c03-installed-packages-1','manager':'deb','packages':[{'name':'bash','version':'1:5-2'}],
                 'pypi':[['requests','2.31.0']]}
    write('installed.json', installed)
    for prefix in ('warmup','run-1','run-2','run-3'):
        for scanner in ('syft','trivy'):
            name=prefix+'-'+scanner+'.json';doc=json.loads((raw/name).read_text('utf-8'))
            if scanner=='syft': doc['artifacts'].append({'type':'deb','name':'bash','version':'1:5-2'})
            else: doc['Results'].append({'Type':'debian','Packages':[{'Name':'bash','Version':'5','Release':'2','Epoch':1}]})
            write(name,doc)
    expected=matrix.installed_inventory(installed)
    summary['results']['inventory']={'installed_metadata':sorted(map(list,expected))}
    for scanner in matrix.READERS:
        summary['results']['inventory'][scanner]={'observed':sorted(map(list,expected)),
            'missing_installed_metadata':[],'additional_to_installed_metadata':[],'matched_count':len(expected)}
    value=proof('application',source)
    path=raw.parent/'matrix-summary.json'
    def review():
        path.write_text(json.dumps(summary),encoding='utf-8')
        return matrix.review(path,raw,hashlib.sha256(path.read_bytes()).hexdigest(),value,source)
    return summary,raw,write,review


def test_matrix_reuses_all_raw_repeat_control_and_db_checks_without_granting_approval(matrix_evidence):
    result=matrix_evidence[-1]()
    assert result['schema']=='c03-matrix-review-1' and result['counts']=={'grype':1,'trivy':1}
    assert all(r['applicability']=='pending_independent_review' and not r['suppressed'] for r in result['finding_rows'])
    assert not result['production_approved'] and result['inventory_comparison']['syft']['matched_count']==2


def test_silent_loss_of_entire_os_catalog_cannot_be_reported_as_success(matrix_evidence):
    summary,raw,write,review=matrix_evidence
    for prefix in ('warmup','run-1','run-2','run-3'):
        name=prefix+'-syft.json';doc=json.loads((raw/name).read_text('utf-8'))
        doc['artifacts']=[r for r in doc['artifacts'] if r['type']=='python'];write(name,doc)
    summary['results']['inventory']['syft']={'observed':[['pypi','requests','2.31.0']],
        'missing_installed_metadata':[['deb','bash','1:5-2']], 'additional_to_installed_metadata':[], 'matched_count':1}
    with pytest.raises(ValueError,match='matrix_os_inventory_unavailable'): review()


@pytest.mark.parametrize('fault',[None,'missing','duplicate','source','database','profile','approved'])
def test_complete_cohort_requires_seven_distinct_profiles_same_source_db_and_no_approval(matrix_evidence,fault):
    first=matrix_evidence[-1]();reviews={}
    for i,name in enumerate(matrix.PROFILES):
        reviews[name]=copy.deepcopy(first);reviews[name].update(profile=name,image_id='sha256:'+f'{i+1:064x}')
    if fault=='missing': reviews.pop('nginx')
    elif fault=='duplicate': reviews['tests']['image_id']=reviews['application']['image_id']
    elif fault=='source': reviews['tests']['source_commit']='e'*40
    elif fault=='database': reviews['tests']['database_files']={'db':'e'*64}
    elif fault=='profile': reviews['tests']['profile']='application'
    elif fault=='approved': reviews['tests']['production_approved']=True
    if fault:
        with pytest.raises(ValueError): matrix.cohort(reviews)
    else:
        result=matrix.cohort(reviews)
        assert result['catalog_complete'] and not result['all_builder_helper_and_ci_images_covered']
        assert not result['production_approved'] and len(result['images'])==7


def test_metadata_probe_is_unprivileged_readonly_offline_and_overrides_image_entrypoint(monkeypatch):
    batch=object.__new__(runtime.Batch);batch.label='c03-test';batch.probes=[]
    def process(argv,**kwargs):
        assert argv[argv.index('--entrypoint')+1]=='sh' and argv[argv.index('--network')+1]=='none'
        assert '--read-only' in argv and '--cap-drop=ALL' in argv and '--memory=2g' in argv
        assert argv[argv.index('--user')+1]=='10001:10001' and kwargs['encoding']=='utf-8'
        assert argv[-2:]==['-c',runtime.OS_PROBE]
        return SimpleNamespace(returncode=0,stdout='metadata',stderr='')
    monkeypatch.setattr(runtime.subprocess,'run',process)
    assert batch.probe('sha256:'+'a'*64,['-c',runtime.OS_PROBE],entrypoint='sh').stdout=='metadata'


def test_one_shared_db_is_removed_only_after_every_reader_container(monkeypatch):
    batch=object.__new__(runtime.Batch);batch.label='c03-shared';batch.probes=[]
    batch.scanner=SimpleNamespace(ident='c03-shared',cache_volume='c03-shared-db',runner_image='c03-shared-runner')
    batch.pilots=[SimpleNamespace(ident='c03-image')]
    removed=[]
    def command(argv):
        if argv[1:3]==['ps','-aq']: return 'reader' if not removed and argv[-1].endswith('c03-image') else ''
        if argv[1]=='inspect': return json.dumps([{'Config':{'Labels':{'secops.c03':'c03-image'}}}])
        if argv[1]=='rm': removed.append(argv[-1])
        if argv[1:3]==['volume','rm']:
            assert removed==['reader'];removed.append(argv[-1])
        return ''
    def process(argv,**kwargs):
        if argv[1:3]==['volume','inspect']:
            return SimpleNamespace(returncode=0,stdout=json.dumps([{'Labels':{'secops.c03':'c03-shared'}}]))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(runtime.scan,'run',command);monkeypatch.setattr(runtime.subprocess,'run',process)
    assert batch.cleanup()=={'owned_resources_remaining':0,'errors':[]}
    assert removed==['reader','c03-shared-db']


def test_late_preflight_failure_never_starts_db_downloads_or_scans(monkeypatch,tmp_path):
    batch=object.__new__(runtime.Batch);batch.directory=tmp_path;batch.label='c03-batch';batch.commit='b'*40
    batch.source={};batch.pilots=[];batch.report={'completed':False};batch.scanner=SimpleNamespace(
        runner_image='c03-batch-runner',cache_volume='c03-batch-db')
    history=json.loads((runtime.scan.ROOT/runtime.HISTORY).read_text('utf-8'))
    monkeypatch.setattr(runtime,'original_database_hashes',lambda *_:history['db_files_after'])
    monkeypatch.setattr(batch,'build_images',lambda:{n:n for n in matrix.PROFILES})
    monkeypatch.setattr(batch,'unchanged',lambda:None)
    monkeypatch.setattr(batch,'image_input',lambda *_:None)
    monkeypatch.setattr(batch,'save',lambda:None)
    cleaned=[];monkeypatch.setattr(batch,'cleanup',lambda:cleaned.append(True) or {'owned_resources_remaining':0,'errors':[]})
    visited=[]
    def preflight(profile,image):
        visited.append(profile)
        if profile=='lambda':raise runtime.ReviewError('lambda_metadata_unavailable')
        return {}
    def pilot(directory,*args,**kwargs):
        return SimpleNamespace(directory=directory,report={})
    monkeypatch.setattr(batch,'image_proof',preflight)
    monkeypatch.setattr(runtime.scan,'Pilot',pilot)
    monkeypatch.setattr(runtime,'prepare',lambda *_:pytest.fail('DB preparation before all preflights completed'))
    with pytest.raises(ValueError,match='lambda_metadata_unavailable'):batch.run()
    assert visited==list(matrix.PROFILES[:6]) and cleaned==[True]
    assert not batch.report['completed'] and batch.report['failure']=='lambda_metadata_unavailable'
