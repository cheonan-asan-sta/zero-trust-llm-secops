"""Windows mutex handles must be bounded and released on every owned exit."""

import pytest

from scripts import evaluate_m6 as evaluation


class Kernel:
    def __init__(self, status=0, handle=41, release=True):
        self.status, self.handle, self.release = status, handle, release
        self.calls = []

    def CreateMutexW(self, security, initial, name):
        self.calls.append(('create', security, initial, name))
        return self.handle

    def WaitForSingleObject(self, handle, timeout):
        self.calls.append(('wait', handle, timeout))
        return self.status

    def ReleaseMutex(self, handle):
        self.calls.append(('release', handle))
        return self.release

    def CloseHandle(self, handle):
        self.calls.append(('close', handle))
        return True


@pytest.mark.parametrize('status', [0, 128])
@pytest.mark.parametrize('body_error', [False, True])
def test_normal_and_abandoned_mutex_are_released_even_when_publication_raises(tmp_path, monkeypatch, status, body_error):
    kernel = Kernel(status)
    monkeypatch.setattr(evaluation, '_report_mutex_kernel', lambda: kernel)
    try:
        with evaluation._windows_report_mutex(tmp_path / 'report.json'):
            assert kernel.calls[-1] == ('wait', 41, 5000)
            if body_error:
                raise ValueError('synthetic publication error')
    except ValueError:
        assert body_error
    assert kernel.calls[-2:] == [('release', 41), ('close', 41)]
    assert kernel.calls[0][3].startswith('Local\\SecopsM6Report-')
    assert str(tmp_path) not in kernel.calls[0][3]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('status,error', [(258, TimeoutError), (0xFFFFFFFF, OSError)])
def test_failed_wait_closes_handle_without_releasing_an_unowned_mutex(tmp_path, monkeypatch, status, error):
    kernel = Kernel(status)
    monkeypatch.setattr(evaluation, '_report_mutex_kernel', lambda: kernel)
    with pytest.raises(error), evaluation._windows_report_mutex(tmp_path / 'report.json'):
        pytest.fail('failed acquisition admitted publication')
    assert kernel.calls[-1] == ('close', 41)
    assert not any(call[0] == 'release' for call in kernel.calls)


def test_failed_creation_never_waits_or_closes_invalid_handle(tmp_path, monkeypatch):
    kernel = Kernel(handle=None)
    monkeypatch.setattr(evaluation, '_report_mutex_kernel', lambda: kernel)
    with pytest.raises(OSError, match='creation'), evaluation._windows_report_mutex(tmp_path / 'report.json'):
        pytest.fail('invalid handle admitted publication')
    assert len(kernel.calls) == 1


def test_release_failure_still_closes_handle(tmp_path, monkeypatch):
    kernel = Kernel(release=False)
    monkeypatch.setattr(evaluation, '_report_mutex_kernel', lambda: kernel)
    with pytest.raises(OSError, match='release'), evaluation._windows_report_mutex(tmp_path / 'report.json'):
        pass
    assert kernel.calls[-1] == ('close', 41)
