"""Synthetic observation fixtures for the local Docker acceptance, never live telemetry."""

import base64
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from app.behavior_context_models import SignedBehaviorCapture
from app.services.trusted_signals import canonical_behavior_capture
from scripts.execution_mtls_runtime import SCOPE


def build(data):
    session, identifier = data['session'], data['capture_id']
    now = datetime.now(UTC) - timedelta(seconds=1)
    connection = 'connection-' + identifier
    capture = SignedBehaviorCapture(
        tenant_id='local', capture_id=identifier, source_id='runtime-behavior', key_id='key-1',
        issued_at=now, expires_at=now + timedelta(seconds=115), scope=SCOPE,
        session_id=session['session_id'], session_version=session['version'],
        session_input_sha256=session['input_digest_sha256'], connection_ids=[connection],
        activity={'source': 'cloudtrail', 'original_group_id': 'group-' + identifier, 'events': [{
            'id': 'event-' + identifier, 'timestamp': now, 'kind': 'AwsApiCall',
            'api_service': 's3.amazonaws.com', 'api_action': 'PutObject', 'connection_id': connection,
            'principal_hash': SCOPE['principal_hash'], 'resource_hashes': ['runtime-object'], 'outcome': 'success',
        }]}, signature='A' * 86,
    )
    key = serialization.load_pem_private_key(Path('/auth/behavior-private.pem').read_bytes(), password=None)
    signature = base64.urlsafe_b64encode(key.sign(canonical_behavior_capture(capture))).decode().rstrip('=')
    capture = capture.model_copy(update={'signature': signature})
    record = {'evidence_id': 'execution-' + identifier, 'observed_at': now.isoformat(), 'scope': SCOPE,
              'session_id': capture.session_id, 'session_version': capture.session_version,
              'session_input_sha256': capture.session_input_sha256, 'capture_id': identifier,
              'capture_input_sha256': hashlib.sha256(canonical_behavior_capture(capture)).hexdigest(),
              'event_ids': [event.id for event in capture.activity.events], 'connection_ids': [connection],
              'actor': data.get('actor'), 'destinations': data.get('destinations')}
    return {'capture': capture.model_dump(mode='json'), 'execution': record}


def main():
    raw = sys.stdin.buffer.read(65_537)
    if len(raw) > 65_536:
        raise ValueError('fixture_input_size')
    print(json.dumps(build(json.loads(raw))))


if __name__ == '__main__':
    main()
