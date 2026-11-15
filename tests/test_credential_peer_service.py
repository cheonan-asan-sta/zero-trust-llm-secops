import pytest

from scripts.f1_lab.credential_peer_service import cgroup_membership

EXPECTED = '/system.slice/system-collector\\x2dtest.slice/collector-test@owned.service'


@pytest.mark.parametrize('raw', [
    '0::'+EXPECTED+'\n',
    '15:name=systemd:'+EXPECTED+'\n12:pids:'+EXPECTED+'\n6:devices:/system.slice/parent.slice\n0::'+EXPECTED+'\n',
])
def test_exact_unified_membership_handles_pure_and_hybrid_kernel_lists(raw):
    assert cgroup_membership(raw.encode(), EXPECTED)


@pytest.mark.parametrize('raw', [
    '0::/different.service\n',
    '0::'+EXPECTED+'-suffix\n',
    '0::'+EXPECTED+'\n0::'+EXPECTED+'\n',
    '1:name=systemd:/different.service\n0::'+EXPECTED+'\n',
    '1:name=systemd:'+EXPECTED+'\n',
    '0:cpu:'+EXPECTED+'\n',
    '1:cpu:'+EXPECTED+'\n1:memory:'+EXPECTED+'\n0::'+EXPECTED+'\n',
    'malformed\n0::'+EXPECTED+'\n',
    '0::relative\n',
    '0::'+EXPECTED+'\x00\n',
])
def test_ambiguous_wrong_or_malformed_membership_never_authenticates_peer(raw):
    with pytest.raises(ValueError):
        cgroup_membership(raw.encode(), EXPECTED)


@pytest.mark.parametrize('mutation', ['valid', 'other_unit', 'other_main_pid', 'inactive',
    'finished', 'empty_invocation', 'outside_system_slice', 'other_kernel_group', 'pid_reused',
    'manager_timeout', 'manager_failure', 'duplicate_manager_field'])
def test_peer_authentication_requires_current_unit_main_pid_and_kernel_membership(mutation, monkeypatch):
    import io
    import struct
    import subprocess
    from types import SimpleNamespace

    from scripts.f1_lab import credential_peer_service as peer

    unit = 'collector-test@owned.service'
    fields = {'Id': unit, 'MainPID': '1234', 'ControlGroup': EXPECTED,
        'InvocationID': 'a'*32, 'ActiveState': 'activating', 'SubState': 'start'}
    changes = {'other_unit': ('Id', 'health@owned.service'), 'other_main_pid': ('MainPID', '1235'),
        'inactive': ('ActiveState', 'inactive'), 'finished': ('SubState', 'exited'),
        'empty_invocation': ('InvocationID', '0'*32),
        'outside_system_slice': ('ControlGroup', '/user.slice/collector.service')}
    if mutation in changes:
        key, value = changes[mutation]
        fields[key] = value
    kernel = '/different.service' if mutation == 'other_kernel_group' else EXPECTED
    starts = iter([99, 100 if mutation == 'pid_reused' else 99])
    monkeypatch.setattr(peer, 'process_start', lambda pid: next(starts))

    class ProcPath:
        def __init__(self, *_):
            pass

        def __truediv__(self, _):
            return self

        def open(self, mode):
            assert mode == 'rb'
            return io.BytesIO(('15:name=systemd:'+kernel+'\n0::'+kernel+'\n').encode())

    monkeypatch.setattr(peer, 'Path', ProcPath)

    def manager(argv, **kwargs):
        assert argv[-2:] == ['--', unit] and kwargs['timeout'] == .35
        assert kwargs['capture_output'] and not kwargs['check']
        if mutation == 'manager_timeout':
            raise subprocess.TimeoutExpired(argv, .35)
        body = '\n'.join(key+'='+value for key, value in fields.items())+'\n'
        if mutation == 'duplicate_manager_field':
            body += 'Id='+unit+'\n'
        return SimpleNamespace(returncode=int(mutation == 'manager_failure'), stdout=body.encode(), stderr=b'')

    monkeypatch.setattr(peer.subprocess, 'run', manager)
    connection = SimpleNamespace(getsockopt=lambda *_: struct.pack('3i', 1234, 1, 1))
    if mutation == 'valid':
        assert peer.peer_service(connection, unit)
    else:
        with pytest.raises(ValueError):
            peer.peer_service(connection, unit)
