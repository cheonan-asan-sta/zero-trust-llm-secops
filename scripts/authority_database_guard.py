"""Bounded, certificate-only PostgreSQL preflight for the optional CA graph.

This is a fixed read-only startup probe, not a general SQL driver. No password
authentication, plaintext fallback, arbitrary query input or write retry exists.
"""

import json
import socket
import ssl
import struct
import time
from pathlib import Path


class DatabaseGuardError(ValueError):
    pass


class Probe:
    def __init__(self, directory=Path('/db-tls')):
        self.deadline = time.monotonic() + 5
        self.stream = socket.create_connection(('ca-db', 5432), timeout=2)
        try:
            self.stream.sendall(struct.pack('!II', 8, 80877103))
            if self.read(1) != b'S':
                raise DatabaseGuardError('authority_database_tls_required')
            context = ssl.create_default_context(cafile=str(directory / 'root.pem'))
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(directory / 'client.pem'), str(directory / 'client.key'))
            self.stream = context.wrap_socket(self.stream, server_hostname='ca-db')
            body = struct.pack('!I', 196608) + b'user\0secops_ca\0database\0stepca\0application_name\0ca-start-guard\0\0'
            self.stream.sendall(struct.pack('!I', len(body) + 4) + body)
            authenticated = False
            for kind, data in self.messages():
                if kind == b'R':
                    if data != struct.pack('!I', 0) or authenticated:
                        raise DatabaseGuardError('authority_database_certificate_auth_required')
                    authenticated = True
                elif kind == b'Z':
                    if not authenticated or data != b'I':
                        raise DatabaseGuardError('authority_database_authentication_required')
                    return
                elif kind not in {b'S', b'K', b'N'}:
                    raise DatabaseGuardError('authority_database_protocol')
            raise DatabaseGuardError('authority_database_protocol')
        except BaseException:
            self.close()
            raise

    def read(self, length):
        parts = bytearray()
        while len(parts) < length:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise DatabaseGuardError('authority_database_timeout')
            self.stream.settimeout(min(2, remaining))
            part = self.stream.recv(length - len(parts))
            if not part:
                raise DatabaseGuardError('authority_database_truncated')
            parts.extend(part)
        return bytes(parts)

    def messages(self):
        for _ in range(128):
            kind, length = self.read(1), struct.unpack('!I', self.read(4))[0]
            if not 4 <= length <= 65536:
                raise DatabaseGuardError('authority_database_message_size')
            yield kind, self.read(length - 4)
        raise DatabaseGuardError('authority_database_message_limit')

    def query(self, statement):
        # Only the two fixed callers below construct these literals. Never expose
        # this function as an RPC or accept a query from a descriptor/request.
        body = statement.encode() + b'\0'
        self.stream.sendall(b'Q' + struct.pack('!I', len(body) + 4) + body)
        rows, columns = [], None
        for kind, data in self.messages():
            if kind == b'T':
                columns = struct.unpack('!H', data[:2])[0]
                if not 1 <= columns <= 4:
                    raise DatabaseGuardError('authority_database_columns')
            elif kind == b'D':
                count = struct.unpack('!H', data[:2])[0]
                if count != columns or rows:
                    raise DatabaseGuardError('authority_database_rows')
                row, offset = [], 2
                for _ in range(count):
                    size = struct.unpack('!i', data[offset:offset + 4])[0]
                    offset += 4
                    if not 0 <= size <= 128 or offset + size > len(data):
                        raise DatabaseGuardError('authority_database_cell')
                    row.append(data[offset:offset + size].decode('ascii'))
                    offset += size
                if offset != len(data):
                    raise DatabaseGuardError('authority_database_row_size')
                rows.append(row)
            elif kind == b'Z':
                if data != b'I' or len(rows) != 1:
                    raise DatabaseGuardError('authority_database_result')
                return rows[0]
            elif kind not in {b'C', b'N'}:
                raise DatabaseGuardError('authority_database_query_failed')
        raise DatabaseGuardError('authority_database_protocol')

    def close(self):
        self.stream.close()


def verify(directory=Path('/ca'), *, probe_class=Probe):
    path = directory / 'database-anchor.json'
    if path.is_symlink() or not path.is_file():
        raise DatabaseGuardError('authority_database_anchor_required')
    with path.open('rb') as stream:
        body = stream.read(1025)
    if not 0 < len(body) <= 1024:
        raise DatabaseGuardError('authority_database_anchor_shape')
    marker = json.loads(body)
    if (set(marker) != {'identifier'} or not isinstance(marker['identifier'], str) or len(marker['identifier']) != 48
            or any(c not in '0123456789abcdef' for c in marker['identifier'])):
        raise DatabaseGuardError('authority_database_anchor_shape')
    probe = probe_class()
    try:
        row = probe.query('SELECT identifier::text, enrollment_complete::text FROM runtime_guard.anchor WHERE singleton=1')
        if row != [marker['identifier'], 'false'] and row != [marker['identifier'], 'true']:
            raise DatabaseGuardError('authority_database_anchor_mismatch')
        if row[1] == 'true':
            counts = probe.query('SELECT (SELECT count(*) FROM used_ott)::text, '
                                 '(SELECT count(*) FROM revoked_x509_certs)::text, '
                                 '(SELECT count(*) FROM x509_certs)::text')
            if (len(counts) != 3 or any(not n.isdigit() or len(n) > 20 for n in counts)
                    or int(counts[0]) < 39 or int(counts[2]) < 39):
                raise DatabaseGuardError('authority_database_state_required')
        return {'verified': True, 'enrolled': row[1] == 'true'}
    finally:
        probe.close()
