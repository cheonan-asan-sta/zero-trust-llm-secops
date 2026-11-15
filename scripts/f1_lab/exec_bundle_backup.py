"""AES-GCM recovery bundle, externally pinned, isolated review restore only.

Typed state is separate from the ordinary capture archive. No fabricated event
or restored application service is used to fit heterogeneous recovery data.
"""

import base64
import secrets
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scripts.f1_lab.capture_archive import ArchiveScope
from scripts.f1_lab.capture_backup import (
    fresh_file,
    pinned,
    private_directory,
    private_file,
    reserve,
    sha,
)
from scripts.f1_lab.exec_bundle_snapshot import (
    MAX_BODY,
    MAX_DB,
    encoded,
    take_snapshot,
    validate_snapshot,
)
from scripts.f1_lab.exec_outbox import distinct
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.web_verified_context import SHA, Identifier

SCHEMA = 'zt-exec-recovery-bundle-1'
CHECKPOINT = 'zt-exec-recovery-bundle-checkpoint-1'
RECEIPT = 'zt-exec-recovery-review-1'


def utc(text):
    require(type(text) is str and len(text) <= 40, 'exec_bundle_utc')
    value = datetime.fromisoformat(text)
    require(value.tzinfo is not None and value.utcoffset().total_seconds() == 0, 'exec_bundle_utc_zone')
    return value


def hash_value(value):
    import re

    require(type(value) is str and re.fullmatch('[a-f0-9]{64}', value), 'exec_bundle_sha256')
    return value


def aad(manifest):
    return canonical({k: v for k, v in manifest.items() if k not in {'payload_sha256', 'payload_bytes'}})


def validate_manifest(value, scope):
    require(type(value) is dict and set(value) == {'schema', 'algorithm', 'key_id', 'snapshot_id',
            'scope_sha256', 'created_at', 'snapshot_sha256', 'snapshot_bytes', 'nonce',
            'payload_sha256', 'payload_bytes'} and value['schema'] == SCHEMA
            and value['algorithm'] == 'AES-256-GCM' and value['scope_sha256'] == sha(canonical(scope.model_dump())),
            'exec_bundle_manifest_shape')
    from pydantic import TypeAdapter

    TypeAdapter(Identifier).validate_python(value['key_id'])
    for key in ('scope_sha256', 'snapshot_sha256', 'payload_sha256'):
        TypeAdapter(SHA).validate_python(value[key])
    require(type(value['snapshot_id']) is str and len(value['snapshot_id']) == 32
            and set(value['snapshot_id']) <= set('0123456789abcdef')
            and type(value['snapshot_bytes']) is int and 0 < value['snapshot_bytes'] <= MAX_BODY
            and type(value['payload_bytes']) is int and value['payload_bytes'] == value['snapshot_bytes']+16,
            'exec_bundle_manifest_bounds')
    nonce = base64.b64decode(value['nonce'], altchars=b'-_', validate=True)
    require(len(nonce) == 12 and base64.urlsafe_b64encode(nonce).decode() == value['nonce'],
            'exec_bundle_manifest_nonce')
    utc(value['created_at'])
    return nonce


def checkpoint_file(path, expected, scope):
    raw = pinned(Path(path), expected, 16384)
    value = decode(raw)
    require(type(value) is dict and set(value) == {'schema', 'scope_sha256', 'snapshot_id', 'created_at',
            'snapshot_sha256', 'manifest_sha256', 'payload_sha256', 'automatic_activation_allowed'}
            and value['schema'] == CHECKPOINT and value['scope_sha256'] == sha(canonical(scope.model_dump()))
            and value['automatic_activation_allowed'] is False, 'exec_bundle_checkpoint_shape')
    for key in ('scope_sha256', 'snapshot_sha256', 'manifest_sha256', 'payload_sha256'):
        hash_value(value[key])
    require(type(value['snapshot_id']) is str and len(value['snapshot_id']) == 32
            and set(value['snapshot_id']) <= set('0123456789abcdef'), 'exec_bundle_checkpoint_id')
    utc(value['created_at'])
    return value


class ExecutionRecoveryBundle:
    def __init__(self, scope, service_pin, caller_pin):
        self.scope = ArchiveScope.model_validate(scope.model_dump())
        self.service_pin, self.caller_pin = service_pin, caller_pin

    def backup(self, journal, broker, operations, worker_directories, output, checkpoint, key, key_id):
        require(type(key) is bytes and len(key) == 32, 'exec_bundle_recovery_key')
        output, checkpoint = Path(output), Path(checkpoint)
        worker_directories = tuple(worker_directories)
        require(output.is_absolute() and checkpoint.is_absolute(), 'exec_bundle_output_absolute')
        sources = [journal.directory, broker.path.parent, operations.path.parent,
                   *worker_directories]
        # A pinned checkpoint and package must survive a lost source tree.
        for source in sources:
            distinct(source, output, checkpoint)
        distinct(output, checkpoint)
        raw = take_snapshot(journal, broker, operations, self.scope, worker_directories)
        _, _, _, _, summary = validate_snapshot(raw, self.scope, self.service_pin, self.caller_pin)
        nonce = secrets.token_bytes(12)
        manifest = {'schema': SCHEMA, 'algorithm': 'AES-256-GCM', 'key_id': key_id,
                    'snapshot_id': secrets.token_hex(16),
                    'scope_sha256': sha(canonical(self.scope.model_dump())),
                    'created_at': datetime.now(UTC).isoformat(), 'snapshot_sha256': sha(raw),
                    'snapshot_bytes': len(raw), 'nonce': base64.urlsafe_b64encode(nonce).decode(),
                    'payload_sha256': '0'*64, 'payload_bytes': len(raw)+16}
        validate_manifest(manifest, self.scope)
        payload = AESGCM(key).encrypt(nonce, raw, aad(manifest))
        manifest['payload_sha256'] = sha(payload)
        manifest_raw = canonical(manifest)+b'\n'
        package = reserve(output, sources+[checkpoint], capacity=16)
        fresh_file(package/'payload.aesgcm', payload)
        fresh_file(package/'manifest.json', manifest_raw)
        pin = {'schema': CHECKPOINT, 'scope_sha256': manifest['scope_sha256'],
               'snapshot_id': manifest['snapshot_id'], 'created_at': manifest['created_at'],
               'snapshot_sha256': sha(raw), 'manifest_sha256': sha(manifest_raw),
               'payload_sha256': sha(payload), 'automatic_activation_allowed': False}
        pin_raw = canonical(pin)+b'\n'
        fresh_file(checkpoint, pin_raw)
        return {'completed': True, 'checkpoint_sha256': sha(pin_raw), **summary,
                'manifest_sha256': sha(manifest_raw), 'payload_sha256': sha(payload),
                'encrypted_bytes': len(payload), 'automatic_activation_allowed': False}

    def restore(self, package, output, checkpoint, checkpoint_sha256, key, key_id):
        require(type(key) is bytes and len(key) == 32, 'exec_bundle_recovery_key')
        package = private_directory(package)
        checkpoint = Path(checkpoint)
        output = Path(output)
        distinct(package, checkpoint, output)
        require({p.name for p in package.iterdir()} == {'manifest.json', 'payload.aesgcm'},
                'exec_bundle_package_inventory')
        pin = checkpoint_file(checkpoint, checkpoint_sha256, self.scope)
        manifest_raw = pinned(package/'manifest.json', pin['manifest_sha256'], 16384)
        manifest = decode(manifest_raw)
        nonce = validate_manifest(manifest, self.scope)
        require(all(manifest[k] == pin[k] for k in ('scope_sha256', 'snapshot_id', 'created_at',
                                                  'snapshot_sha256', 'payload_sha256'))
                and manifest['key_id'] == key_id and utc(manifest['created_at']) <= datetime.now(UTC),
                'exec_bundle_checkpoint_package_binding')
        payload = pinned(package/'payload.aesgcm', pin['payload_sha256'], MAX_BODY+16)
        require(len(payload) == manifest['payload_bytes'], 'exec_bundle_ciphertext_bound')
        raw = AESGCM(key).decrypt(nonce, payload, aad(manifest))
        require(len(raw) == manifest['snapshot_bytes'] and sha(raw) == pin['snapshot_sha256'],
                'exec_bundle_decrypted_binding')
        value, verified, app_raw, broker_raw, summary = validate_snapshot(
            raw, self.scope, self.service_pin, self.caller_pin)
        require(utc(value['created_at']) <= utc(manifest['created_at']), 'exec_bundle_snapshot_manifest_clock')
        # All validation completes before reserving an isolated destination.
        # No restored paths are read from signed worker_directory values.
        review = reserve(output, [package, checkpoint], capacity=16)
        fresh_file(review/'app.sqlite3', app_raw)
        fresh_file(review/'broker.sqlite3', broker_raw)
        intents = review/'intents'
        intents.mkdir(mode=0o700)
        workers = review/'worker-artifacts'
        workers.mkdir(mode=0o700)
        for rid, intent_raw, capture_raw, worker_raw in verified:
            run = reserve(intents/rid)
            fresh_file(run/'intent.json', intent_raw)
            if capture_raw is not None:
                fresh_file(run/'capture.json', capture_raw)
            if worker_raw is not None:
                worker = reserve(workers/rid)
                fresh_file(worker/'capture.json', worker_raw)
        files = {}
        metadata = {**value, 'app_database': None, 'broker_database': None, 'runs': []}
        for record, (rid, intent_raw, capture_raw, worker_raw) in zip(value['runs'], verified, strict=True):
            reduced = {**record}
            for artifact_key, body, name in [('intent', intent_raw, 'intents/'+rid+'/intent.json'),
                                    ('capture', capture_raw, 'intents/'+rid+'/capture.json'),
                                    ('worker', worker_raw, 'worker-artifacts/'+rid+'/capture.json')]:
                reduced[artifact_key] = sha(body) if body is not None else None
                if body is not None:
                    files[name] = sha(body)
            metadata['runs'].append(reduced)
        inventory_raw = canonical({'schema': 'zt-exec-recovery-review-inventory-1',
                                   'snapshot_metadata': metadata, 'files': files})+b'\n'
        fresh_file(review/'inventory.json', inventory_raw)
        receipt = {'schema': RECEIPT, 'checkpoint_sha256': checkpoint_sha256,
                   'manifest_sha256': pin['manifest_sha256'], 'snapshot_sha256': sha(raw),
                   'app_database_sha256': sha(app_raw), 'broker_database_sha256': sha(broker_raw),
                   'restored_at': datetime.now(UTC).isoformat(), **summary,
                   'inventory_sha256': sha(inventory_raw),
                   'automatic_activation_allowed': False, 'grant_refunded': False,
                   'command_reexecuted': False, 'original_worker_paths_followed': False}
        receipt_raw = canonical(receipt)+b'\n'
        # Completion marker is last. A partial directory is never a valid review.
        fresh_file(review/'restore.json', receipt_raw)
        return {'completed': True, **summary, 'receipt_sha256': sha(receipt_raw),
                'automatic_activation_allowed': False}

    def verify_review(self, review, receipt_sha256, checkpoint, checkpoint_sha256):
        review = private_directory(review)
        pin = checkpoint_file(checkpoint, checkpoint_sha256, self.scope)
        receipt = decode(pinned(review/'restore.json', receipt_sha256, 16384))
        require(receipt.get('schema') == RECEIPT and receipt.get('checkpoint_sha256') == checkpoint_sha256
                and receipt.get('manifest_sha256') == pin['manifest_sha256']
                and receipt.get('snapshot_sha256') == pin['snapshot_sha256']
                and receipt.get('automatic_activation_allowed') is False
                and receipt.get('authorization_asserted') is False,
                'exec_bundle_review_receipt')
        require(set(receipt) == {'schema', 'checkpoint_sha256', 'manifest_sha256', 'snapshot_sha256',
                'app_database_sha256', 'broker_database_sha256', 'restored_at', 'intents', 'sealed',
                'indeterminate', 'worker_artifacts', 'app_entries', 'broker_requests',
                'automatic_execution_allowed', 'authorization_asserted', 'inventory_sha256',
                'automatic_activation_allowed', 'grant_refunded', 'command_reexecuted',
                'original_worker_paths_followed'}
                and all(receipt[k] is False for k in ('automatic_execution_allowed', 'authorization_asserted',
                    'automatic_activation_allowed', 'grant_refunded', 'command_reexecuted',
                    'original_worker_paths_followed'))
                and utc(pin['created_at']) <= utc(receipt['restored_at']) <= datetime.now(UTC),
                'exec_bundle_review_receipt_shape')
        inventory = decode(pinned(review/'inventory.json', receipt['inventory_sha256'], MAX_BODY))
        require(type(inventory) is dict and set(inventory) == {'schema', 'snapshot_metadata', 'files'}
                and inventory['schema'] == 'zt-exec-recovery-review-inventory-1',
                'exec_bundle_review_inventory')
        value, records = inventory['snapshot_metadata'], inventory['files']
        require(type(value) is dict and type(records) is dict and len(records) <= 3*10000
                and type(value.get('runs')) is list and len(value['runs']) <= 10000
                and value['app_database'] is value['broker_database'] is None,
                'exec_bundle_review_index_bound')
        expected = {'app.sqlite3', 'broker.sqlite3', 'restore.json', 'inventory.json', 'intents', 'worker-artifacts'}
        require({p.name for p in review.iterdir()} == expected, 'exec_bundle_review_directory')
        ids = [record['id'] for record in value['runs']]
        require(ids == sorted(set(ids)), 'exec_bundle_review_request_ids')
        actual = {}
        from itertools import islice

        for root_name in ('intents', 'worker-artifacts'):
            root = private_directory(review/root_name)
            for ordinal, directory in enumerate(root.iterdir(), 1):
                require(ordinal <= 10000 and directory.name in ids, 'exec_bundle_review_request')
                private_directory(directory)
                names = list(islice(directory.iterdir(), 3))
                require(len(names) <= (2 if root_name == 'intents' else 1), 'exec_bundle_review_run_files')
                for file in names:
                    relative = file.relative_to(review).as_posix()
                    require(relative in records, 'exec_bundle_review_unknown_file')
                    actual[relative] = sha(private_file(file, 2*1024**2))
        require(actual == records, 'exec_bundle_review_file_binding')
        value['app_database'] = encoded(pinned(review/'app.sqlite3', receipt['app_database_sha256'], MAX_DB))
        value['broker_database'] = encoded(pinned(review/'broker.sqlite3', receipt['broker_database_sha256'], MAX_DB))
        for record in value['runs']:
            rid = record['id']
            for key, name in [('intent', 'intents/'+rid+'/intent.json'),
                              ('capture', 'intents/'+rid+'/capture.json'),
                              ('worker', 'worker-artifacts/'+rid+'/capture.json')]:
                if record[key] is not None:
                    require(records.get(name) == record[key], 'exec_bundle_review_record_pin')
                    record[key] = encoded(pinned(review/name, record[key], 2*1024**2))
        raw = canonical(value)+b'\n'
        require(sha(raw) == pin['snapshot_sha256'], 'exec_bundle_review_original_snapshot')
        require(utc(value['created_at']) <= utc(pin['created_at']), 'exec_bundle_review_snapshot_clock')
        _, _, _, _, summary = validate_snapshot(raw, self.scope, self.service_pin, self.caller_pin)
        require(all(receipt[k] == v for k, v in summary.items()), 'exec_bundle_review_summary')
        return {'completed': True, 'verified_files': len(records), **summary,
                'automatic_activation_allowed': False}

