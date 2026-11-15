"""Pinned encrypted PAM history, isolated review and keyless revalidation.

The operator, OS and independently retained pins are trusted. No live store,
current authority/freshness, human authentication or permission is restored.
"""

import base64
import secrets
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import TypeAdapter

from scripts.f1_lab.capture_backup import (
    fresh_file,
    pinned,
    private_directory,
    reserve,
    sha,
)
from scripts.f1_lab.exec_bundle_backup import hash_value, utc
from scripts.f1_lab.exec_outbox import distinct
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.pam_observation_ledger import MAX_DATABASE, PamObservationLedger
from scripts.f1_lab.web_verified_context import Identifier

SCHEMA = 'zt-pam-observation-backup-1'
PIN = 'zt-pam-observation-backup-checkpoint-1'
REVIEW = 'zt-pam-observation-review-1'
FLAGS = {'current_freshness_verified': False, 'human_authenticated': False,
         'authorization_asserted': False, 'automatic_activation_allowed': False,
         'automatic_enforcement_allowed': False, 'goal_qualified': False}
MANIFEST_FIELDS = {'schema', 'algorithm', 'key_id', 'configuration_sha256',
    'observation_checkpoint_sha256', 'created_at', 'nonce', 'database_sha256',
    'database_bytes', 'payload_sha256', 'payload_bytes'}
PIN_FIELDS = {'schema', 'configuration_sha256', 'observation_checkpoint_sha256',
              'manifest_sha256', 'payload_sha256', 'database_sha256', 'automatic_activation_allowed'}


def aad(value):
    return canonical({k: v for k, v in value.items() if k not in {'payload_sha256', 'payload_bytes'}})


def exact_entries(path, expected):
    # Stop scanning an unexpectedly large directory, including foreign files.
    names = []
    for entry in path.iterdir():
        names.append(entry.name)
        require(len(names) <= len(expected), 'pam_backup_directory_bound')
    require(set(names) == set(expected), 'pam_backup_directory_inventory')


class PamObservationBackup:
    def __init__(self, ledger):
        require(type(ledger) is PamObservationLedger and ledger.directory.is_absolute(), 'pam_backup_ledger')
        self.ledger = ledger
        self.configuration_sha256 = sha(ledger.config)

    def inspect_database(self, raw, expected_checkpoint):
        """Validate a bounded private copy using the same ledger contract.

        The short-lived plaintext DB is owner-only and removed on every exit.
        No source path from the encrypted payload is opened or followed.
        """
        hash_value(expected_checkpoint)
        require(type(raw) is bytes and 0 < len(raw) <= MAX_DATABASE
                and raw[:16] == b'SQLite format 3\x00' and raw[18:20] == b'\x01\x01',
                'pam_backup_database_bound')
        with tempfile.TemporaryDirectory(prefix='zt-pam-review-') as temporary:
            directory = Path(temporary)
            fresh_file(directory/'observations.sqlite3', raw)
            review = PamObservationLedger(directory, self.ledger.scope,
                capacity=self.ledger.capacity, event_capacity=self.ledger.event_capacity)
            return review.checkpoint(expected_checkpoint)

    def backup(self, output, checkpoint, expected_observation_sha256, key, key_id):
        require(type(key) is bytes and len(key) == 32, 'pam_backup_key')
        TypeAdapter(Identifier).validate_python(key_id)
        hash_value(expected_observation_sha256)
        output, checkpoint = Path(output), Path(checkpoint)
        distinct(self.ledger.directory, output, checkpoint)
        private_directory(checkpoint.parent)
        require(not checkpoint.exists() and not checkpoint.is_symlink(), 'pam_backup_fresh_checkpoint')
        with self.ledger._connect() as con:
            # SQLite serializes one committed view while the existing writer
            # fence excludes admissions. The copied view is validated before
            # any package/checkpoint publication, never a second live read.
            raw = con.serialize()
        inventory = self.inspect_database(raw, expected_observation_sha256)
        nonce = secrets.token_bytes(12)
        manifest = {'schema': SCHEMA, 'algorithm': 'AES-256-GCM', 'key_id': key_id,
            'configuration_sha256': self.configuration_sha256,
            'observation_checkpoint_sha256': expected_observation_sha256,
            'created_at': datetime.now(UTC).isoformat(),
            'nonce': base64.urlsafe_b64encode(nonce).decode(),
            'database_sha256': sha(raw), 'database_bytes': len(raw),
            'payload_sha256': '0'*64, 'payload_bytes': len(raw)+16}
        payload = AESGCM(key).encrypt(nonce, raw, aad(manifest))
        manifest['payload_sha256'] = sha(payload)
        manifest_raw = canonical(manifest)+b'\n'
        package = reserve(output, [self.ledger.directory, checkpoint], capacity=16)
        fresh_file(package/'manifest.json', manifest_raw)
        fresh_file(package/'payload.aesgcm', payload)
        pin = {'schema': PIN, 'configuration_sha256': self.configuration_sha256,
            'observation_checkpoint_sha256': expected_observation_sha256,
            'manifest_sha256': sha(manifest_raw), 'payload_sha256': sha(payload),
            'database_sha256': sha(raw), 'automatic_activation_allowed': False}
        pin_raw = canonical(pin)+b'\n'
        fresh_file(checkpoint, pin_raw)
        return {'completed': True, 'checkpoint_sha256': sha(pin_raw),
            'captures': inventory['captures'], 'unique_events': inventory['unique_events'], **FLAGS}

    def package(self, package, checkpoint, expected):
        package, checkpoint = private_directory(package), Path(checkpoint)
        distinct(self.ledger.directory, package, checkpoint)
        private_directory(checkpoint.parent)
        pin = decode(pinned(checkpoint, expected, 16384))
        require(type(pin) is dict and set(pin) == PIN_FIELDS and pin['schema'] == PIN
            and pin['configuration_sha256'] == self.configuration_sha256
            and pin['automatic_activation_allowed'] is False, 'pam_backup_checkpoint_shape')
        for name in PIN_FIELDS-{'schema', 'automatic_activation_allowed'}:
            hash_value(pin[name])
        exact_entries(package, {'manifest.json', 'payload.aesgcm'})
        manifest = decode(pinned(package/'manifest.json', pin['manifest_sha256'], 16384))
        require(type(manifest) is dict and set(manifest) == MANIFEST_FIELDS
            and manifest['schema'] == SCHEMA and manifest['algorithm'] == 'AES-256-GCM', 'pam_backup_manifest_shape')
        TypeAdapter(Identifier).validate_python(manifest['key_id'])
        require(all(manifest[k] == pin[k] for k in ('configuration_sha256',
            'observation_checkpoint_sha256', 'database_sha256', 'payload_sha256')),
            'pam_backup_package_binding')
        require(type(manifest['database_bytes']) is int and 0 < manifest['database_bytes'] <= MAX_DATABASE
            and type(manifest['payload_bytes']) is int
            and manifest['payload_bytes'] == manifest['database_bytes']+16, 'pam_backup_manifest_bound')
        require(utc(manifest['created_at']) <= datetime.now(UTC), 'pam_backup_future_package')
        require(type(manifest['nonce']) is str and len(manifest['nonce']) == 16, 'pam_backup_nonce')
        nonce = base64.b64decode(manifest['nonce'], altchars=b'-_', validate=True)
        require(len(nonce) == 12 and base64.urlsafe_b64encode(nonce).decode() == manifest['nonce'], 'pam_backup_nonce')
        payload = pinned(package/'payload.aesgcm', pin['payload_sha256'], MAX_DATABASE+16)
        require(len(payload) == manifest['payload_bytes'], 'pam_backup_payload_size')
        return package, pin, manifest, nonce, payload

    def restore(self, package, output, checkpoint, expected, key, key_id):
        require(type(key) is bytes and len(key) == 32, 'pam_backup_key')
        package, pin, manifest, nonce, payload = self.package(package, checkpoint, expected)
        output = Path(output)
        distinct(self.ledger.directory, package, output, checkpoint)
        require(manifest['key_id'] == key_id, 'pam_backup_key_identity')
        try:
            raw = AESGCM(key).decrypt(nonce, payload, aad(manifest))
        except InvalidTag:
            raise ValueError('pam_backup_authentication_failed') from None
        require(len(raw) == manifest['database_bytes'] and sha(raw) == pin['database_sha256'],
                'pam_backup_database_binding')
        inventory = self.inspect_database(raw, pin['observation_checkpoint_sha256'])
        receipt = {'schema': REVIEW, 'checkpoint_sha256': expected,
            'configuration_sha256': self.configuration_sha256,
            'database_sha256': sha(raw), 'restored_at': datetime.now(UTC).isoformat(),
            'captures': inventory['captures'], 'unique_events': inventory['unique_events'], **FLAGS}
        receipt_raw = canonical(receipt)+b'\n'
        destination = reserve(output, [self.ledger.directory, package, checkpoint], capacity=16)
        fresh_file(destination/'review.sqlite3', raw)
        fresh_file(destination/'restore.json', receipt_raw)
        return {'completed': True, 'review_receipt_sha256': sha(receipt_raw), **receipt}

    def check_review(self, package, review, checkpoint, expected, review_receipt_sha256):
        package, pin, manifest, _nonce, _payload = self.package(package, checkpoint, expected)
        review = private_directory(review)
        distinct(self.ledger.directory, package, review, checkpoint)
        exact_entries(review, {'review.sqlite3', 'restore.json'})
        receipt = decode(pinned(review/'restore.json', review_receipt_sha256, 16384))
        fields = {'schema', 'checkpoint_sha256', 'configuration_sha256', 'database_sha256',
                  'restored_at', 'captures', 'unique_events', *FLAGS}
        require(type(receipt) is dict and set(receipt) == fields and receipt['schema'] == REVIEW
            and receipt['checkpoint_sha256'] == expected
            and receipt['configuration_sha256'] == self.configuration_sha256
            and receipt['database_sha256'] == pin['database_sha256']
            and all(receipt[k] is False for k in FLAGS), 'pam_backup_review_receipt')
        require(utc(manifest['created_at']) <= utc(receipt['restored_at']) <= datetime.now(UTC),
                'pam_backup_review_time')
        raw = pinned(review/'review.sqlite3', pin['database_sha256'], MAX_DATABASE)
        inventory = self.inspect_database(raw, pin['observation_checkpoint_sha256'])
        require(all(type(receipt[k]) is int and receipt[k] == inventory[k]
            for k in ('captures', 'unique_events')), 'pam_backup_review_counts')
        return {'completed': True, 'state': 'verified_historical_copy',
            'captures': inventory['captures'], 'unique_events': inventory['unique_events'], **FLAGS}

    def status(self, *args):
        """Fail closed for monitoring: never reuse successful historical counts."""
        try:
            return self.check_review(*args)
        except (OSError, ValueError, TypeError, KeyError, RuntimeError, sqlite3.Error):
            return {'completed': False, 'state': 'unavailable',
                    'captures': None, 'unique_events': None, **FLAGS}
