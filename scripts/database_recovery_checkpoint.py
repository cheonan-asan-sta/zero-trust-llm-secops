"""Encrypted manual security checkpoint; host anchor detects volume rollback.

This store does not prove freshness after its last explicit publication and never
merges database rows or authorizes a live restore.
"""

import json
import sys
from pathlib import Path

from scripts.ca_recovery_state import atomic, digest, opened, sealed
from scripts.certificate_controller import LifecycleError
from scripts.database_backup_store import validate_manifest

ZERO = {'sequence': 0, 'sha256': '0' * 64}


def anchor(value):
    import re
    if (not isinstance(value, dict) or set(value) != {'sequence', 'sha256'}
            or type(value['sequence']) is not int or not 0 <= value['sequence'] < 2**53
            or not isinstance(value['sha256'], str) or re.fullmatch('[a-f0-9]{64}', value['sha256']) is None
            or (value['sequence'] == 0) != (value['sha256'] == ZERO['sha256'])):
        raise LifecycleError('checkpoint_anchor_invalid')
    return value


def head(value):
    return {'sequence': value['sequence'], 'sha256': digest(value)}


def operation(request, directory=Path('/checkpoint'), key_path=Path('/key/key.hex')):
    manifest = validate_manifest(request['manifest'])
    expected = anchor(request['expected'])
    mode = request['operation']
    if mode not in {'publish', 'assess'}:
        raise LifecycleError('checkpoint_operation_invalid')
    path = directory / 'latest.json'
    if path.is_symlink() or key_path.is_symlink() or not key_path.is_file():
        raise LifecycleError('checkpoint_path_invalid')
    key = bytes.fromhex(key_path.read_text())
    if len(key) != 32:
        raise LifecycleError('checkpoint_key_invalid')
    current = None
    if path.exists():
        with path.open('rb') as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise LifecycleError('checkpoint_size_limit')
        envelope = json.loads(raw)
        current = opened(envelope, key)
        if (not isinstance(current, dict) or set(current) != {'schema', 'sequence', 'previous', 'manifest'}
                or current['schema'] != 'database-recovery-checkpoint-1'
                or type(current['sequence']) is not int or not 1 <= current['sequence'] < 2**53
                or envelope['manifest'] != {'project': manifest['project'], 'purpose': current['schema']}):
            raise LifecycleError('checkpoint_shape_invalid')
        anchor(current['previous'])
        validate_manifest(current['manifest'])
        if (current['previous']['sequence'] + 1 != current['sequence']
                or current['manifest']['project'] != manifest['project']):
            raise LifecycleError('checkpoint_chain_invalid')
    actual = head(current) if current else ZERO
    if mode == 'publish':
        candidate = {'schema': 'database-recovery-checkpoint-1', 'sequence': expected['sequence'] + 1,
                     'previous': expected, 'manifest': manifest}
        if actual == expected:
            if current and current['manifest'] == manifest:
                return {'head': actual, 'published': True}
            atomic(path, json.dumps(sealed(candidate, key, {'project': manifest['project'], 'purpose': candidate['schema']})))
            return {'head': head(candidate), 'published': True}
        # Adopt exactly one authenticated publication after a lost host save.
        if current == candidate:
            return {'head': actual, 'published': True}
        raise LifecycleError('checkpoint_anchor_mismatch')
    if actual != expected or current is None:
        raise LifecycleError('checkpoint_anchor_mismatch')
    if current['manifest']['security'] != manifest['security']:
        raise LifecycleError('checkpoint_security_rollback')
    return {'head': actual, 'checkpoint_compatible': True, 'live_restore_authorized': False,
            'freshness': 'last_explicit_quiesced_checkpoint'}


def main():
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ValueError('request_limit')
        print(json.dumps(operation(json.loads(raw))))
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'verified': False, 'reason': 'database_recovery_checkpoint_failed'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
