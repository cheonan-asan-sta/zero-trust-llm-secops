"""Diagnose failed acceptance replies without disclosing credentials or retrying."""

import json
from types import SimpleNamespace

import pytest

from scripts import test_execution_mtls_runtime as module
from scripts.continuous_mtls_runtime import RuntimeFailure


@pytest.fixture(autouse=True)
def isolated_runtime(monkeypatch):
    # These are HTTP failure/cleanup tests. Never create a Docker runtime or
    # relax the production runtime's repository-directory restriction.
    monkeypatch.setattr(module, 'ExecutionRuntime', lambda directory: SimpleNamespace(
        descriptor=directory / 'runtime.json'))


@pytest.mark.parametrize('status,detail,category', [
    (401, 'Signal source, signature, scope or freshness rejected', 'signal_rejected'),
    (409, 'Session version, identity, order or event conflict', 'session_conflict'),
    (503, 'Zero Trust journal unavailable; access denied', 'journal_unavailable'),
    (503, 'Trusted signal registry unavailable; access denied', 'registry_unavailable'),
    (422, [{'input': {'private_key': 'never-publish-this'}}], 'validation_rejected'),
    (500, 'unexpected-secret-response', 'unclassified_response'),
])
def test_fixture_failure_is_saved_before_cleanup_without_retry(tmp_path, status, detail, category):
    checks = module.Checks(tmp_path / 'acceptance')
    calls = []

    def mint(request):
        calls.append(request)
        return {'status': status, 'body': {'detail': detail, 'grant_token': 'secret-grant'},
                'body_sha256': 'a' * 64, 'tls_version': 'TLSv1.3', 'headers': {'X-API-Key': 'secret-key'}}

    checks.runtime = SimpleNamespace(mint=mint)
    with pytest.raises(RuntimeFailure, match='execution_fixture_session'):
        checks.fixture('baseline-1')
    saved = json.loads(checks.path.read_text())
    diagnostic = saved['failure_diagnostics']
    assert diagnostic['observed_status'] == status and diagnostic['expected_status'] == 200
    assert diagnostic['category'] == category and diagnostic['response_sha256'] == 'a' * 64
    assert len(calls) == 1 and not saved['completed']
    for secret in ('never-publish-this', 'unexpected-secret-response', 'secret-grant', 'secret-key'):
        assert secret not in checks.path.read_text()


@pytest.mark.parametrize('reply', [None, [], {'status': True}, {'status': 200.0},
                                   {'status': 503, 'tls_version': [], 'body_sha256': 'secret'},
                                   {'status': 200, 'tls_version': 'TLSv1.2'}])
def test_malformed_reply_cannot_pass_or_crash_diagnostic_writer(tmp_path, reply):
    checks = module.Checks(tmp_path / 'acceptance')
    with pytest.raises(RuntimeFailure):
        checks.expect_reply(reply, 200, 'execution_fixture_session')
    assert json.loads(checks.path.read_text())['failure_diagnostics']['response_sha256'] is None


def test_success_status_with_missing_session_is_a_failure_without_body_disclosure(tmp_path):
    checks = module.Checks(tmp_path / 'acceptance')
    checks.runtime = SimpleNamespace(mint=lambda request: {
        'status': 200, 'body': {'grant_token': 'secret-grant'}, 'tls_version': 'TLSv1.3',
    })
    with pytest.raises(RuntimeFailure, match='execution_fixture_payload'):
        checks.fixture('baseline-1')
    assert json.loads(checks.path.read_text())['failure_diagnostics']['stage'] == 'execution_fixture_payload'
    assert 'secret-grant' not in checks.path.read_text()


@pytest.mark.parametrize('primary_failure', [True, False])
def test_cleanup_failure_keeps_original_error_and_returns_failure(tmp_path, monkeypatch, primary_failure):
    class Checks:
        def __init__(self, directory):
            self.report = {'completed': False}
            descriptor = tmp_path / 'runtime.json'
            descriptor.touch()
            self.runtime = SimpleNamespace(descriptor=descriptor, down=self.down)

        def run(self):
            if primary_failure:
                raise RuntimeFailure('execution_fixture_session')
            self.report['completed'] = True

        def down(self, **kwargs):
            raise RuntimeFailure('private cleanup details')

        def save(self):
            (tmp_path / 'verification.json').write_text(json.dumps(self.report))

    monkeypatch.setattr(module, 'Checks', Checks)
    assert module.main(['--directory', str(tmp_path)]) == 1
    saved = json.loads((tmp_path / 'verification.json').read_text())
    assert saved['completed'] is False and saved['cleanup'] == {'purged': False, 'error': 'RuntimeFailure'}
    if primary_failure:
        assert saved['error_code'] == 'execution_fixture_session'
    assert 'private cleanup details' not in (tmp_path / 'verification.json').read_text()
