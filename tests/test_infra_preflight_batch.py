import hashlib
import json
from pathlib import Path

import pytest

from scripts import test_infra_preflight_batch as batch


def test_batch_rejects_existing_or_outside_directory_before_docker(tmp_path, monkeypatch):
    monkeypatch.setattr(batch, 'ROOT', tmp_path)
    monkeypatch.setattr(batch, 'output', lambda *a: pytest.fail('out-of-scope Docker call'))
    allowed = tmp_path / 'runtime/c02/infra-batches'
    allowed.mkdir(parents=True)
    for path in (tmp_path, allowed, allowed / '../foreign'):
        with pytest.raises(ValueError, match='fresh_directory'):
            batch.Batch(path)


@pytest.mark.parametrize('fault', ['source', 'head', 'engine'])
def test_source_or_engine_change_refuses_next_stage_before_execution(monkeypatch, fault):
    obj = object.__new__(batch.Batch)
    obj.source, obj.head, obj.engine = {'source': 'approved'}, 'head', 'engine'
    monkeypatch.setattr(batch, 'source_manifest', lambda: {'source': 'changed' if fault == 'source' else 'approved'})
    monkeypatch.setattr(batch, 'output', lambda *a: ('changed' if fault == 'head' else 'head') if a[0] == 'git'
                       else 'changed' if fault == 'engine' else 'engine')
    with pytest.raises(ValueError, match='source_or_engine'):
        obj.admit()


@pytest.fixture
def report(tmp_path, monkeypatch):
    monkeypatch.setattr(batch, 'ROOT', tmp_path)
    (tmp_path / 'scripts').mkdir()
    path = tmp_path / 'scripts/example.py'
    path.write_text('public-test-source')
    return {'completed': True, 'checks': [{'passed': True}] * 3,
        'cleanup': {'containers': 0, 'volumes': 0, 'networks': 0}, 'source_commit': 'head',
        'image_source_verified': True, 'release_image_payload_verified': True,
        'source_input_sha256': {'scripts/example.py': hashlib.sha256(path.read_bytes()).hexdigest()}}


@pytest.mark.parametrize('fault', ['failed', 'short', 'leak', 'head', 'image', 'payload', 'source_missing', 'source_hash', 'source_path'])
def test_public_batch_never_turns_partial_wrong_source_or_unclean_report_into_success(report, fault):
    if fault == 'failed':
        report['completed'] = False
    elif fault == 'short':
        report['checks'].pop()
    elif fault == 'leak':
        report['cleanup']['volumes'] = 1
    elif fault == 'head':
        report['source_commit'] = 'foreign'
    elif fault in {'image', 'payload'}:
        report['image_source_verified' if fault == 'image' else 'release_image_payload_verified'] = False
    elif fault == 'source_missing':
        report['source_input_sha256'] = {}
    elif fault == 'source_hash':
        report['source_input_sha256']['scripts/example.py'] = '0' * 64
    else:
        report['source_input_sha256'] = {'../foreign': '0' * 64}
    with pytest.raises(ValueError):
        batch.validate_report(report, 3, {'scripts/example.py': 'approved'}, 'head')


def test_complete_report_preserves_actual_check_count(report):
    assert batch.validate_report(report, 3, {'scripts/example.py': 'approved'}, 'head') == 3


def test_one_failed_stage_is_recorded_without_retry_and_independent_stages_still_execute(tmp_path):
    obj = object.__new__(batch.Batch)
    obj.directory = tmp_path
    obj.report = {'stages': []}
    obj.admit = lambda: None
    obj.linux = lambda: (_ for _ in ()).throw(ValueError('private-error-sentinel'))
    calls = []
    obj.acceptance = lambda name, *a: calls.append(name) or {'checks': 100}
    assert obj.run() is False
    assert calls == ['monitored', 'authority-ha']
    value = json.loads((tmp_path / 'verification.json').read_text())
    assert len(value['stages']) == 3 and value['stages'][0]['passed'] is False
    assert 'private-error-sentinel' not in json.dumps(value)


def test_acceptance_commands_stay_inside_fresh_owned_child_scope(tmp_path, monkeypatch):
    obj = object.__new__(batch.Batch)
    obj.directory = tmp_path
    obj.source, obj.head = {}, 'head'
    calls = []
    monkeypatch.setattr(obj, 'run_command', lambda name, argv: calls.append(argv))
    # No fabricated report can make an absent child descriptor successful.
    with pytest.raises((ValueError, OSError)):
        obj.acceptance('monitored', 'scripts.test_continuous_mtls_runtime', 75)
    assert calls[0][-1] == '--monitoring' and Path(calls[0][-2]).parent == tmp_path
