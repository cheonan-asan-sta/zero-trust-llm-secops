import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from scripts import continuous_mtls_runtime as runtime
from scripts import test_continuous_mtls_runtime as checks
from scripts import test_monitored_mtls_runtime as monitored


@pytest.mark.parametrize('monitoring', [False, True])
@pytest.mark.parametrize('kind', ['exit', 'timeout', 'value'])
def test_failed_main_retains_safe_origin_and_cleanup_without_child_output(tmp_path, monkeypatch, capsys, monitoring, kind):
    observed = []
    canary = 'PRIVATE_PAYLOAD_CANARY_MUST_NOT_LEAK'

    class FakeChecks:
        def __init__(self, directory):
            self.path = directory/'verification.json'
            self.report = {'completed': False, 'checks': [], 'operation_stage': 'runtime_start'}
            observed.append(self)

        def run(self):
            if kind == 'exit':
                runtime.command(['docker', 'build', canary], payload=canary)
            if kind == 'timeout':
                raise subprocess.TimeoutExpired(['docker', canary], 7, output=canary, stderr=canary)
            raise ValueError(canary)

        def cleanup(self):
            self.report['cleanup'] = {'containers': 0, 'volumes': 0, 'networks': 0}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.report))

    monkeypatch.setattr(checks, 'Checks', FakeChecks)
    monkeypatch.setattr(monitored, 'MonitoredChecks', FakeChecks)
    monkeypatch.setattr(runtime.subprocess, 'run', lambda *a, **kw: SimpleNamespace(
        returncode=1, stdout=canary, stderr=canary))
    argv = ['checks', '--directory', str(tmp_path/'result')]
    monkeypatch.setattr(sys, 'argv', argv+(['--monitoring'] if monitoring else []))
    assert checks.main() == 1
    report = json.loads(observed[0].path.read_text())
    assert not report['completed'] and report['checks'] == []
    assert report['operation_stage'] == 'runtime_start'
    assert report['cleanup'] == {'containers': 0, 'volumes': 0, 'networks': 0}
    if kind == 'exit':
        assert report['failure'] == 'runtime_command_failed_1'
        assert report['failure_detail']['cli_exit_code'] == 1
        assert any(f['file'] == 'scripts/continuous_mtls_runtime.py' for f in report['failure_detail']['frames'])
    elif kind == 'timeout':
        assert report['failure_detail']['reason'] == 'runtime_command_timeout'
        assert report['failure_detail']['command_timeout_seconds'] == 7
    assert canary not in json.dumps(report) and str(tmp_path) not in json.dumps(report)
    assert canary not in capsys.readouterr().out


def test_initial_runtime_stage_does_not_publish_or_start_anything_early():
    probe = object.__new__(checks.Checks)
    probe.report = {'checks': []}

    def failed_start():
        assert probe.report['operation_stage'] == 'runtime_start'
        raise runtime.RuntimeFailure('runtime_command_failed_1')

    probe.runtime = SimpleNamespace(up=failed_start)
    with pytest.raises(runtime.RuntimeFailure, match='runtime_command_failed_1'):
        probe.run()
    assert probe.report == {'checks': [], 'operation_stage': 'runtime_start'}
