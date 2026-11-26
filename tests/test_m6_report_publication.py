"""Atomic report publication must survive sharing races without hiding failures."""

import errno
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from scripts import evaluate_m6 as evaluation


def denied(winerror=None):
    error = PermissionError(errno.EACCES, "synthetic replace denial")
    if winerror is not None:
        error.winerror = winerror
    return error


@pytest.mark.parametrize('winerror', [5, 32, 33])
def test_transient_sharing_conflict_keeps_previous_report_until_atomic_replace(tmp_path, monkeypatch, winerror):
    output = tmp_path / 'report.json'
    output.write_text('{"previous":true}', encoding='utf-8')
    original = Path.replace
    calls, delays = [], []

    def replace(source, target):
        calls.append(source)
        if len(calls) < 4:
            assert json.loads(output.read_text()) == {'previous': True}
            assert json.loads(source.read_text()) == {'new': True}
            raise denied(winerror)
        return original(source, target)

    monkeypatch.setattr(Path, 'replace', replace)
    monkeypatch.setattr(evaluation.time, 'sleep', delays.append)
    evaluation.write_report(output, {'new': True})
    assert len(calls) == 4 and delays == [0.01, 0.02, 0.04]
    assert json.loads(output.read_text()) == {'new': True}
    assert list(tmp_path.iterdir()) == [output]


@pytest.mark.parametrize('winerror,attempts', [(None, 1), (2, 1), (5, 10), (32, 10), (33, 10)])
def test_persistent_or_unrelated_denial_preserves_old_report_and_cleans_temporary(tmp_path, monkeypatch, winerror, attempts):
    output = tmp_path / 'report.json'
    before = b'{"previous":true}\n'
    output.write_bytes(before)
    calls, delays = [], []
    error = denied(winerror)

    def replace(source, target):
        calls.append(source)
        raise error

    monkeypatch.setattr(Path, 'replace', replace)
    monkeypatch.setattr(evaluation.time, 'sleep', delays.append)
    with pytest.raises(PermissionError) as caught:
        evaluation.write_report(output, {'new': True})
    assert caught.value is error
    assert len(calls) == attempts and len(delays) == attempts - 1
    assert sum(delays) < 1
    assert output.read_bytes() == before
    assert list(tmp_path.iterdir()) == [output]


def test_repeated_concurrent_publishers_leave_a_complete_single_report(tmp_path):
    output = tmp_path / 'report.json'
    reports = [{'publisher': i, 'data': str(i) * 100_000} for i in range(8)]
    for _ in range(10):
        with ThreadPoolExecutor(max_workers=8) as executor:
            for future in [executor.submit(evaluation.write_report, output, report) for report in reports]:
                future.result()
        assert json.loads(output.read_text()) in reports
        assert list(tmp_path.iterdir()) == [output]
