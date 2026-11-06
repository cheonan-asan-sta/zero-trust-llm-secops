import json
import ssl
import struct
import time
from pathlib import Path

import pytest

from scripts import authority_database_guard as guard

ANCHOR = 'a' * 48


@pytest.mark.parametrize('anchor,counts,expected', [
    ([ANCHOR, 'false'], None, True), ([ANCHOR, 'true'], ['39', '0', '39'], True),
    (['b' * 48, 'true'], ['39', '1', '39'], False),
    ([ANCHOR, 't'], ['39', '1', '39'], False),
    ([ANCHOR, 'true'], ['0', '0', '0'], False),
    ([ANCHOR, 'true'], ['38', '9', '39'], False),
    ([ANCHOR, 'true'], ['39', '0', '38'], False),
    ([ANCHOR, 'true'], ['39', '-1', '39'], False),
    ([ANCHOR, 'true'], ['39'], False),
    ([ANCHOR, 'true'], ['9' * 21, '1', '99'], False),
])
def test_fixed_probe_binds_database_identity_and_retained_state(tmp_path, anchor, counts, expected):
    (tmp_path / 'database-anchor.json').write_text(json.dumps({'identifier': ANCHOR}))
    seen = []

    class Probe:
        def query(self, statement):
            seen.append(statement)
            return anchor if len(seen) == 1 else counts

        def close(self):
            seen.append('closed')

    if expected:
        assert guard.verify(tmp_path, probe_class=Probe) == {'verified': True, 'enrolled': anchor[1] == 'true'}
    else:
        with pytest.raises(guard.DatabaseGuardError):
            guard.verify(tmp_path, probe_class=Probe)
    assert seen[-1] == 'closed'
    assert all('INSERT' not in s and 'UPDATE' not in s and 'DELETE' not in s for s in seen)


def frame(kind, data):
    return kind + struct.pack('!I', len(data) + 4) + data


class Stream:
    def __init__(self, body):
        self.body, self.sent, self.closed = body, [], False

    def sendall(self, body):
        self.sent.append(body)

    def recv(self, size):
        result, self.body = self.body[:min(size, 7)], self.body[min(size, 7):]
        return result

    def settimeout(self, seconds):
        assert 0 < seconds <= 2

    def close(self):
        self.closed = True


def install(monkeypatch, body, *, certificate_error=False):
    stream, seen = Stream(body), []

    def connect(address, *, timeout):
        assert address == ('ca-db', 5432) and timeout == 2
        return stream

    class Context:
        minimum_version = None

        def load_cert_chain(self, certificate, key):
            assert Path(certificate) == Path('/db-tls/client.pem') and Path(key) == Path('/db-tls/client.key')
            seen.append('client-certificate')

        def wrap_socket(self, raw, *, server_hostname):
            assert raw == stream and server_hostname == 'ca-db'
            assert self.minimum_version == ssl.TLSVersion.TLSv1_2
            if certificate_error:
                raise ssl.SSLCertVerificationError('synthetic')
            return stream

    def context(*, cafile):
        assert Path(cafile) == Path('/db-tls/root.pem')
        return Context()

    monkeypatch.setattr(guard.socket, 'create_connection', connect)
    monkeypatch.setattr(guard.ssl, 'create_default_context', context)
    return stream, seen


def test_fragmented_tls_certificate_only_startup_and_fixed_rows(monkeypatch):
    row = struct.pack('!H', 2) + struct.pack('!i', 3) + b'abc' + struct.pack('!i', 4) + b'true'
    body = b'S' + frame(b'R', struct.pack('!I', 0)) + frame(b'Z', b'I')
    body += frame(b'T', struct.pack('!H', 2)) + frame(b'D', row) + frame(b'C', b'SELECT 1\0') + frame(b'Z', b'I')
    stream, seen = install(monkeypatch, body)
    probe = guard.Probe()
    assert probe.query('SELECT fixed') == ['abc', 'true']
    probe.close()
    assert seen == ['client-certificate'] and stream.closed
    assert stream.sent[0] == struct.pack('!II', 8, 80877103)
    assert b'secops_ca\0' in stream.sent[1] and all(not s.startswith(b'p') for s in stream.sent)


@pytest.mark.parametrize('body', [
    b'N', b'', b'S' + frame(b'R', struct.pack('!I', 3)),
    b'S' + frame(b'R', struct.pack('!I', 5)),
    b'S' + frame(b'R', struct.pack('!I', 10)),
    b'S' + frame(b'Z', b'I'), b'S' + frame(b'E', b'private-server-detail'),
    b'S' + b'R' + struct.pack('!I', 65537),
    b'S' + b'R' + struct.pack('!I', 3),
])
def test_authentication_or_protocol_fault_never_becomes_permission(monkeypatch, body):
    stream, _ = install(monkeypatch, body)
    with pytest.raises(guard.DatabaseGuardError):
        guard.Probe()
    assert stream.closed and all(not s.startswith(b'p') for s in stream.sent)


def test_database_certificate_failure_is_not_plaintext_or_password_retry(monkeypatch):
    stream, _ = install(monkeypatch, b'S', certificate_error=True)
    with pytest.raises(ssl.SSLCertVerificationError):
        guard.Probe()
    assert stream.closed and stream.sent == [struct.pack('!II', 8, 80877103)]


def test_probe_has_absolute_deadline_and_does_not_spin_on_empty_peer():
    probe = object.__new__(guard.Probe)
    probe.stream = Stream(b'x')
    probe.deadline = time.monotonic() - 1
    with pytest.raises(guard.DatabaseGuardError, match='timeout'):
        probe.read(1)
    probe.deadline = time.monotonic() + 1
    probe.stream = Stream(b'')
    with pytest.raises(guard.DatabaseGuardError, match='truncated'):
        probe.read(1)


def test_peer_communication_timeout_propagates_fail_closed(monkeypatch):
    def fail(*args, **kwargs):
        raise TimeoutError('synthetic')
    monkeypatch.setattr(guard.socket, 'create_connection', fail)
    with pytest.raises(OSError):
        guard.Probe()


@pytest.mark.parametrize('value', ['a', 'x' * 48, 42])
def test_invalid_anchor_is_refused_before_any_connection(tmp_path, value):
    (tmp_path / 'database-anchor.json').write_text(json.dumps({'identifier': value}))
    with pytest.raises(guard.DatabaseGuardError, match='anchor_shape'):
        guard.verify(tmp_path, probe_class=lambda: pytest.fail('connected before validating anchor'))
