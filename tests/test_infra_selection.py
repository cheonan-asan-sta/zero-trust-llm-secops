import copy
import json
import shutil

import pytest

from scripts import infra_selection as selection
from scripts.infra_load_probe import run, validate_rows
from scripts.pep_lab import DOCUMENT_HASH
from scripts.test_infra_selection_runtime import SelectionChecks


def rows(allowed):
    return [{'status': 200 if i < allowed else 403, 'body_sha256': DOCUMENT_HASH if i < allowed else '0' * 64,
             'tls_version': 'TLSv1.3', 'http_ms': 1.0 + i} for i in range(16)]


@pytest.fixture
def report():
    workloads = []
    for repeat in range(1, 4):
        for concurrency in (1, 4, 8):
            for kind, delivered in [('valid', 16), ('shared', 1), ('missing', 0)]:
                value = {'repeat': repeat, 'concurrency': concurrency, 'kind': kind,
                         'rows': rows(delivered), 'delivered': delivered, 'passed': True}
                if kind == 'shared':
                    value['replay'] = {'rows': rows(0)}
                workloads.append(value)
    return {'schema': 'infrastructure-selection-verification-2', 'completed': True,
            'cleanup': {'containers': 0, 'volumes': 0, 'networks': 0},
            'image_source_verified': True, 'release_image_payload_verified': True,
            'conditions': {'repeats': 3, 'concurrency': [1, 4, 8], 'requests_per_wave': 16,
                'resource_scope': 'steady workloads after three valid snapshots; sampler joined before gateway stop',
                'order': 'alternate ascending/descending concurrency each repetition',
                'timing': 'HTTP inside operator includes mTLS handshake; excludes mint and Docker exec startup',
                'capacity_claim': False, 'production_approval': False, 'independent_review': False},
            'checks': [{'label': str(i), 'passed': True} for i in range(37)],
            'workloads': workloads,
            'recoveries': [{'repeat': i, 'denied_status': 403, 'outage_deliveries': 0, 'post_recovery_deliveries': 1,
                            'gateway_ready_status': 422,
                            'stop_seconds': 1, 'start_to_new_grant_delivery_seconds': 2,
                            'start_to_monitoring_healthy_seconds': 3} for i in range(1, 4)],
            'services': {str(i): {'published_ports': False, 'host_binds': False} for i in range(14)},
            'resource_samples': [{'service': str(i), 'window': r} for r in range(1, 4) for i in range(14)],
            'resource_errors': [],
            'resource_warmup': [{'repeat': r, 'ready': True, 'service_counts': {str(i): 3 for i in range(14)},
                                 'samples': 42, 'errors': []} for r in range(1, 4)],
            'resource_windows': [{'repeat': r, 'samples': 14} for r in range(1, 4)]}


def test_counts_keep_load_and_fault_probes_separate(report):
    result = selection.measurement(report)
    assert result['requests'] == 576 and result['allowed'] == 153 and result['denied'] == 423
    assert all(v['n'] == 48 for v in result['valid_http_ms_by_concurrency'].values())
    assert result['gateway_start_to_new_grant_delivery_ms']['n'] == 3


@pytest.mark.parametrize('fault', ['partial', 'cleanup', 'image', 'checks', 'duplicate_check', 'missing_wave',
    'duplicate_wave', 'false_allow', 'wrong_content', 'plaintext', 'transport_error', 'unexpected_delivery',
    'replay', 'missing_fault', 'fault_allow', 'fault_delivery', 'fault_recovery', 'nan', 'bool',
    'resource_error', 'missing_service', 'port', 'bind', 'production_claim', 'failed_wave', 'gateway_readiness',
    'legacy_schema', 'missing_window', 'short_warmup', 'wrong_window'])
def test_partial_unsafe_or_malformed_evidence_never_becomes_selection_advice(report, fault):
    if fault == 'partial':
        report['completed'] = False
    elif fault == 'cleanup':
        report['cleanup']['volumes'] = 1
    elif fault == 'image':
        report['image_source_verified'] = False
    elif fault == 'checks':
        report['checks'][0]['passed'] = False
    elif fault == 'duplicate_check':
        report['checks'][1] = copy.deepcopy(report['checks'][0])
    elif fault == 'missing_wave':
        report['workloads'].pop()
    elif fault == 'duplicate_wave':
        report['workloads'][1] = copy.deepcopy(report['workloads'][0])
    elif fault in {'false_allow', 'wrong_content', 'plaintext', 'transport_error'}:
        row = report['workloads'][0]['rows'][0]
        if fault == 'false_allow':
            row.update(status=403, body_sha256='0' * 64)
        elif fault == 'wrong_content':
            row['body_sha256'] = '0' * 64
        elif fault == 'plaintext':
            row['tls_version'] = None
        else:
            row['status'] = 0
    elif fault == 'unexpected_delivery':
        report['workloads'][2]['delivered'] = 1
    elif fault == 'replay':
        report['workloads'][1]['replay']['rows'] = rows(1)
    elif fault == 'missing_fault':
        report['recoveries'].pop()
    elif fault == 'fault_allow':
        report['recoveries'][0]['denied_status'] = 200
    elif fault == 'fault_delivery':
        report['recoveries'][0]['outage_deliveries'] = 1
    elif fault == 'fault_recovery':
        report['recoveries'][0]['post_recovery_deliveries'] = 0
    elif fault in {'nan', 'bool'}:
        report['workloads'][0]['rows'][0]['http_ms'] = float('nan') if fault == 'nan' else True
    elif fault == 'resource_error':
        report['resource_errors'] = [{'error_type': 'Timeout'}]
    elif fault == 'missing_service':
        report['resource_samples'].pop()
    elif fault == 'port':
        report['services']['0']['published_ports'] = True
    elif fault == 'bind':
        report['services']['0']['host_binds'] = True
    elif fault == 'failed_wave':
        report['workloads'][0]['passed'] = False
    elif fault == 'gateway_readiness':
        report['recoveries'][0]['gateway_ready_status'] = 403
    elif fault == 'legacy_schema':
        report['schema'] = 'infrastructure-selection-verification-1'
    elif fault == 'missing_window':
        report['resource_windows'].pop()
    elif fault == 'short_warmup':
        report['resource_warmup'][0]['service_counts']['0'] = 2
    elif fault == 'wrong_window':
        report['resource_samples'][0]['window'] = 2
    else:
        report['conditions']['production_approval'] = True
    with pytest.raises(ValueError):
        selection.measurement(report)


@pytest.mark.parametrize('kind,concurrency', [('valid', 1000), ('unknown', 1), ('valid', True)])
def test_out_of_scope_load_is_refused_before_mint(kind, concurrency, monkeypatch):
    monkeypatch.setattr('scripts.infra_load_probe.mint', lambda *a: pytest.fail('unexpected mint'))
    with pytest.raises(ValueError, match='workload_scope'):
        run(kind, concurrency)


def test_actual_load_probe_keeps_credentials_out_of_results(monkeypatch):
    from scripts import infra_load_probe as probe
    monkeypatch.setattr(probe, 'mint', lambda *a: {'status': 200, 'body': {
        'session': {'status': 'ACTIVE'}, 'grant_token': 'private-grant-sentinel'}})
    monkeypatch.setattr(probe, '_request', lambda *a: {'status': 200, 'body_sha256': DOCUMENT_HASH,
                                                     'tls_version': 'TLSv1.3', 'body': 'private-body-sentinel'})
    value = run('valid', 4)
    assert validate_rows(value['rows'], 16, 16)['n'] == 16
    assert 'sentinel' not in json.dumps(value)


def test_outside_existing_directory_is_refused_before_runtime(tmp_path):
    with pytest.raises(ValueError, match='fresh_scoped'):
        SelectionChecks(tmp_path)


def test_failed_wave_is_saved_before_assertion_with_actual_responses_and_resource_counters(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace

    from scripts import test_infra_selection_runtime as driver

    obj = object.__new__(SelectionChecks)
    obj.report, obj.path = {"workloads": []}, tmp_path / "verification.json"
    obj.runtime = SimpleNamespace()
    monkeypatch.setattr(
        driver,
        "execute_probe",
        lambda *a: {
            "exit_code": 0,
            "failure": None,
            "report": {
                "kind": "valid",
                "concurrency": 8,
                "probe_completed": True,
                "rows": rows(15),
                "wave_seconds": 0.1,
            },
        },
    )
    counter = iter([0, 15])
    obj.served = lambda: next(counter)
    with pytest.raises(ValueError, match="delivery_count"):
        obj.workload(2, 8, "valid")
    saved = json.loads(obj.path.read_text())["workloads"][0]
    assert saved["passed"] is False and saved["expected_delivered"] == 16
    assert saved["resource_before"] == 0 and saved["resource_after"] == saved["delivered"] == 15
    assert len(saved["rows"]) == 16 and saved["rows"][-1]["status"] == 403


def test_resource_sampler_joins_before_fault_and_each_new_window_has_a_fresh_valid_baseline(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from scripts import test_infra_selection_runtime as driver
    active = []

    class Sampler:
        def __init__(self, containers, destination, interval):
            self.rows = [{'service': s, 'at': '2026-11-08T00:00:00+00:00'} for s in containers.values() for _ in range(3)]
            self.errors = []
            self.thread = SimpleNamespace(start=lambda: active.append(self))

        def stop(self):
            active.remove(self)

    monkeypatch.setattr(driver, 'Sampler', Sampler)
    obj = object.__new__(SelectionChecks)
    obj.report = {'resource_samples': [], 'resource_errors': [], 'resource_windows': [], 'resource_warmup': []}
    obj.path = tmp_path / 'verification.json'
    obj.runtime = SimpleNamespace(services=tuple(str(i) for i in range(14)), container=lambda s: s,
                                  wait=lambda predicate, **kw: predicate() or pytest.fail('baseline missing'))
    calls = []
    obj.workload = lambda *args: calls.append(args) if len(active) == 1 else pytest.fail('workload not sampled')
    def recover(repeat):
        assert not active, 'stats query must be joined before stopping a service'
        assert obj.report['resource_warmup'][-1]['ready'] is True
    obj.recovery = recover
    obj.measure_workloads()
    assert len(calls) == 27 and not active and len(obj.report['resource_windows']) == 3
    assert len(obj.report['resource_samples']) == 126 and obj.report['resource_errors'] == []


def history_root(tmp_path):
    root = selection.ROOT
    for name in ['infra/selection/evidence.json', 'docs/infrastructure-results/c01-windows-20261103.json',
                 'infra/observability/tools.lock.json', 'infra/pep/tools.lock.json',
                 'docs/infrastructure-results/c02-windows-20261103.json',
                 'docs/infrastructure-results/c03-patched-scan-20261105.json']:
        destination = tmp_path / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / name, destination)
    return tmp_path


def test_history_records_are_pinned_and_remain_historical():
    value = selection.historical(selection.ROOT)
    assert set(value) == {'C01', 'C02', 'C03'} and all(v['historical_only'] for v in value.values())


def test_changed_history_is_refused_even_if_success_flag_is_preserved(tmp_path):
    root = history_root(tmp_path)
    path = root / 'docs/infrastructure-results/c01-windows-20261103.json'
    path.write_bytes(path.read_bytes() + b' ')
    with pytest.raises(ValueError, match='history_hash'):
        selection.historical(root)


@pytest.mark.parametrize('fault', ['failure', 'duplicate', 'scan_change'])
def test_repinning_an_incomplete_or_inconsistent_history_does_not_bypass_checks(tmp_path, fault):
    import hashlib
    root = history_root(tmp_path)
    contract_path = root / 'infra/selection/evidence.json'
    contract = json.loads(contract_path.read_text())
    name = 'C03' if fault == 'scan_change' else 'C01'
    path = root / contract['inputs'][name]['path']
    value = json.loads(path.read_text())
    if fault == 'scan_change':
        value['db_files_after'] = {}
    elif fault == 'failure':
        value['runs'][0]['checks'][0]['passed'] = False
    else:
        value['runs'][1] = copy.deepcopy(value['runs'][0])
    path.write_text(json.dumps(value))
    contract['inputs'][name]['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    contract_path.write_text(json.dumps(contract))
    with pytest.raises(ValueError):
        selection.historical(root)
