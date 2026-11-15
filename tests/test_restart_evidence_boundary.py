from types import SimpleNamespace

from scripts.test_continuous_mtls_runtime import Checks


def test_restart_count_increment_alone_does_not_finish_wait(monkeypatch):
    before = {'Id': 'same', 'RestartCount': 0,
              'State': {'Running': True, 'StartedAt': '2020-01-01T00:00:00+00:00'}}
    transitional = {**before, 'RestartCount': 1}
    after = {**transitional, 'State': {'Running': True, 'StartedAt': '2020-01-02T00:00:00+00:00'}}
    snapshots = iter([before, transitional, after, after])
    checks = object.__new__(Checks)
    checks.runtime = SimpleNamespace(execute=lambda *args: None)
    monkeypatch.setattr(checks, 'inspect', lambda _: next(snapshots))
    observations = []
    def wait(predicate, label):
        observations.append(predicate())
        assert observations[-1] is False
        observations.append(predicate())
        assert observations[-1] is True
    monkeypatch.setattr(checks, 'wait', wait)
    recorded = []
    monkeypatch.setattr(checks, 'add', lambda *args, **kwargs: recorded.append(kwargs))
    checks.restart('worker')
    assert observations == [False, True]
    assert recorded == [{'same_container': True, 'before': 0, 'after': 1,
                         'exit_signal': 'SIGKILL to Python child, not Docker stop'}]
