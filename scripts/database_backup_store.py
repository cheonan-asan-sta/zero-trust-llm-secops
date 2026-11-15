"""Offline encrypted DB archive store; no network, SQL execution or live mounts."""

import base64
import hashlib
import json
import re
import sys
from pathlib import Path

from scripts.ca_recovery_state import atomic, opened, sealed
from scripts.certificate_controller import LifecycleError

LIMIT = 32 * 1024**2
MAX_ARCHIVES = 16


def validate_manifest(value):
    if (not isinstance(value, dict) or set(value) != {'schema', 'id', 'project', 'profile', 'security', 'created_at'}
            or value['schema'] != 'database-backup-1'
            or not isinstance(value['id'], str) or re.fullmatch('[a-f0-9]{24}', value['id']) is None
            or not isinstance(value['project'], str) or re.fullmatch('kmtls-[a-f0-9]{12}', value['project']) is None
            or not isinstance(value['profile'], str) or re.fullmatch('[a-f0-9]{64}', value['profile']) is None
            or type(value['created_at']) is not int or value['created_at'] <= 0
            or not isinstance(value['security'], dict)
            or set(value['security']) != {'public.used_ott', 'public.revoked_x509_certs',
                'public.x509_certs', 'public.x509_certs_data', 'runtime_guard.anchor'}):
        raise LifecycleError('backup_manifest_invalid')
    for entry in value['security'].values():
        if (not isinstance(entry, dict) or set(entry) != {'rows', 'sha256'}
                or type(entry['rows']) is not int or not 0 <= entry['rows'] <= 100000
                or not isinstance(entry['sha256'], str) or re.fullmatch('[a-f0-9]{64}', entry['sha256']) is None):
            raise LifecycleError('backup_security_invalid')
    return value


def decode_dump(value):
    if not isinstance(value, str) or len(value) > (LIMIT + 2) // 3 * 4:
        raise LifecycleError('backup_dump_limit')
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        raise LifecycleError('backup_dump_invalid') from None
    if not raw.startswith(b'PGDMP') or len(raw) > LIMIT:
        raise LifecycleError('backup_dump_invalid')
    return raw


def operation(request, directory=Path('/backup'), key_path=Path('/key/key.hex')):
    manifest = validate_manifest(request['manifest'])
    mode = request['operation']
    if mode not in {'seal', 'inspect', 'read', 'capacity'}:
        raise LifecycleError('backup_operation_invalid')
    key = bytes.fromhex(key_path.read_text())
    if len(key) != 32:
        raise LifecycleError('backup_key_invalid')
    path = directory / (manifest['id'] + '.json')
    if path.is_symlink() or key_path.is_symlink():
        raise LifecycleError('backup_path_invalid')
    if mode == 'capacity':
        return {'available': max(0, MAX_ARCHIVES - len(list(directory.glob('*.json'))))}
    if not path.exists():
        if mode != 'seal':
            return {'exists': False}
        if len(list(directory.glob('*.json'))) >= MAX_ARCHIVES:
            raise LifecycleError('backup_retention_capacity')
        raw = decode_dump(request['dump'])
        body = {'dump': request['dump'], 'sha256': hashlib.sha256(raw).hexdigest()}
        atomic(path, json.dumps(sealed(body, key, manifest), sort_keys=True))
    if path.stat().st_size > LIMIT * 2:
        raise LifecycleError('backup_archive_limit')
    encoded = path.read_bytes()
    envelope = json.loads(encoded)
    # Authenticate before trusting the public associated data.
    body = opened(envelope, key)
    if envelope['manifest'] != manifest:
        raise LifecycleError('backup_manifest_mismatch')
    raw = decode_dump(body['dump'])
    digest = hashlib.sha256(raw).hexdigest()
    if body['sha256'] != digest or (mode == 'seal' and request['dump'] != body['dump']):
        raise LifecycleError('backup_content_mismatch')
    result = {'exists': True, 'archive_sha256': hashlib.sha256(encoded).hexdigest(),
              'dump_sha256': digest, 'bytes': len(raw)}
    if mode == 'read':
        result['dump'] = body['dump']
    return result


def main():
    try:
        raw = sys.stdin.buffer.read(LIMIT * 2 + 1)
        if len(raw) > LIMIT * 2:
            raise LifecycleError('backup_request_limit')
        print(json.dumps(operation(json.loads(raw))))
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'verified': False, 'reason': 'database_backup_store_failed'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
