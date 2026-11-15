"""Encrypted local ledger snapshots and externally pinned recovery checkpoints."""

import base64
import hashlib
import secrets
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import Field, field_validator, model_validator

from app.models import StrictModel
from app.security import Principal, Role
from scripts.ca_recovery_state import atomic
from scripts.f1_lab.native_jsonl import decode
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.web_evidence_ledger import (
    MAX_DATABASE,
    ZERO,
    LedgerUnavailable,
    WebEvidenceLedger,
    bounded,
    require,
)
from scripts.f1_lab.web_verified_context import SHA, Identifier

MAX_PACKAGE = 2*MAX_DATABASE+65536


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Head(StrictModel):
    store_id: str = Field(pattern=r'^[a-f0-9]{32}$')
    configuration: SHA
    seq: int = Field(strict=True, ge=0, le=10000)
    hash: SHA
    last_now: str | None

    @field_validator('last_now')
    @classmethod
    def aware(cls, value):
        if value is not None:
            WebEvidenceLedger._now(datetime.fromisoformat(value))
        return value


class Checkpoint(StrictModel):
    schema_version: Literal['zt-web-external-checkpoint-1']
    head: Head
    observed_until: str
    issued_at: str

    @field_validator('observed_until','issued_at')
    @classmethod
    def aware(cls, value):
        WebEvidenceLedger._now(datetime.fromisoformat(value))
        return value

    @model_validator(mode='after')
    def consistent_head(self):
        require((self.head.hash == ZERO and self.head.last_now is None) if self.head.seq == 0
                else self.head.last_now is not None,'web_checkpoint_head_shape')
        require(datetime.fromisoformat(self.issued_at) >= datetime.fromisoformat(self.observed_until)
                and (self.head.last_now is None or datetime.fromisoformat(self.observed_until) >=
                     datetime.fromisoformat(self.head.last_now)), 'web_checkpoint_time_order')
        return self


class BackupManifest(StrictModel):
    schema_version: Literal['zt-web-ledger-backup-1']
    algorithm: Literal['AES-256-GCM']
    key_id: Identifier
    capacity: int = Field(strict=True, ge=2, le=10000)
    snapshot: Checkpoint
    nonce: str = Field(pattern=r'^[A-Za-z0-9_-]{16}$')
    payload_sha256: SHA
    payload_bytes: int = Field(strict=True, ge=16, le=MAX_PACKAGE)


def pinned(path, expected, maximum):
    path = Path(path)
    require(isinstance(expected,str) and len(expected) == 64 and set(expected) <= set('0123456789abcdef'),
            'web_backup_external_pin')
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum,'web_backup_file')
    with path.open('rb') as stream:
        raw = stream.read(maximum+1)
    require(len(raw) <= maximum and sha(raw) == expected,'web_backup_file_pin')
    return raw


def load_checkpoint(path, expected):
    return Checkpoint.model_validate(decode(pinned(path,expected,8192)))


def check_anchor(db, records, head, high, checkpoint):
    expected = checkpoint.head
    require(head['store_id'] == expected.store_id and head['configuration'] == expected.configuration
            and len(records) >= expected.seq,'web_checkpoint_store_or_rollback')
    actual_hash = ZERO if expected.seq == 0 else db.execute(
        'SELECT record_hash FROM web_records WHERE seq=?',(expected.seq,)).fetchone()[0]
    require(actual_hash == expected.hash,'web_checkpoint_history_conflict')
    require(expected.last_now == (records[expected.seq-1]['accepted_at'] if expected.seq else None),
            'web_checkpoint_head_time_conflict')
    require(high is not None and high >= datetime.fromisoformat(checkpoint.observed_until),
            'web_checkpoint_clock_rollback')


class CheckpointedWebLedger(WebEvidenceLedger):
    def __init__(self, database, control, checkpoint_path, expected_checkpoint_sha256, *, capacity=2000):
        super().__init__(database,control,capacity=capacity)
        self.checkpoint_path, self.checkpoint_sha256 = Path(checkpoint_path).absolute(),expected_checkpoint_sha256
        require(not self.checkpoint_path.resolve().is_relative_to(self.control.resolve())
                and self.checkpoint_path.resolve() != self.database.resolve(),
                'web_checkpoint_separate_path')
        load_checkpoint(self.checkpoint_path,self.checkpoint_sha256)

    def _recover(self, db, key):
        records,head,high = super()._recover(db,key)
        check_anchor(db,records,head,high,load_checkpoint(self.checkpoint_path,self.checkpoint_sha256))
        return records,head,high


def encode(raw):
    return base64.b64encode(raw).decode('ascii')


def unencode(text, maximum):
    require(isinstance(text,str) and len(text) <= 4*((maximum+2)//3),'web_backup_payload_bound')
    raw = base64.b64decode(text,validate=True)
    require(len(raw) <= maximum and encode(raw) == text,'web_backup_payload_encoding')
    return raw


class WebLedgerBackup:
    def __init__(self, ledger, recovery_key, key_id, *, maintainers):
        require(isinstance(ledger,WebEvidenceLedger) and type(recovery_key) is bytes and len(recovery_key) == 32,
                'web_backup_recovery_key')
        require(isinstance(key_id,str) and 1 <= len(key_id) <= 128
                and all(c.isascii() and (c.isalnum() or c in '._-') for c in key_id),'web_backup_key_id')
        require(isinstance(maintainers,frozenset) and 0 < len(maintainers) <= 100
                and all(isinstance(v,tuple) and len(v) == 2 and all(isinstance(s,str) and s.strip() for s in v)
                        for v in maintainers),'web_backup_maintainers')
        self.ledger,self.cipher,self.key_id,self.maintainers = ledger,AESGCM(recovery_key),key_id,maintainers

    def _authorize(self, principal):
        self.ledger._local()
        require(isinstance(principal,Principal) and principal.auth_method in {'api_key','oidc'}
                and Role.ADMIN in principal.effective_roles
                and (principal.tenant_id,principal.subject) in self.maintainers,'web_backup_store_maintainer')

    def _external(self, path, output=None):
        path = Path(path).absolute()
        require(not path.is_symlink() and path.resolve() != self.ledger.database.resolve()
                and not path.resolve().is_relative_to(self.ledger.control.resolve()),
                'web_backup_external_checkpoint_path')
        if output is not None:
            require(not path.resolve().is_relative_to(Path(output).resolve()),'web_backup_checkpoint_not_in_package')
        return path

    def _output(self, path):
        path = Path(path).absolute()
        require(not path.exists() and not path.is_symlink() and path != self.ledger.database
                and not path.resolve().is_relative_to(self.ledger.control.resolve())
                and not self.ledger.control.resolve().is_relative_to(path.resolve())
                and not self.ledger.database.resolve().is_relative_to(path.resolve()),'web_backup_fresh_output')
        path.parent.mkdir(parents=True,exist_ok=True)
        path.mkdir(mode=0o700)  # Exclusive reservation. Failed outputs are retained; never overwrite a directory.
        return path

    def _phase(self, _point):
        """Process-exit injection boundary; never enabled by normal callers."""

    @bounded
    def checkpoint(self, path, principal, *, previous_path=None, expected_previous_sha256=None, now=None):
        self._authorize(principal)
        path = self._external(path)
        require(not path.exists(),'web_checkpoint_fresh_file')
        require((previous_path is None) == (expected_previous_sha256 is None),'web_checkpoint_previous_pin_required')
        previous = load_checkpoint(self._external(previous_path),expected_previous_sha256) if previous_path is not None else None
        now = self.ledger._now(datetime.now(UTC) if now is None else now)
        with self.ledger._transaction(now) as (db,key,records,head):
            if previous is not None:
                high = datetime.fromisoformat(decode(self.ledger._read(self.ledger.control/'witness.json',8192))['state']['observed_until'])
                check_anchor(db,records,head,high,previous)
            checkpoint = Checkpoint(schema_version='zt-web-external-checkpoint-1',head=Head.model_validate(head),
                observed_until=now.isoformat(),issued_at=now.isoformat())
            path.parent.mkdir(parents=True,exist_ok=True)
            # Exclusive file creation prevents replacing a prior external anchor.
            with path.open('xb') as stream:
                raw = canonical(checkpoint.model_dump(mode='json'))+b'\n'
                stream.write(raw)
                stream.flush()
                import os
                os.fsync(stream.fileno())
            self.ledger._save({'current':head,'pending':None,'observed_until':now.isoformat()},key)
        return {'path':str(path),'sha256':sha(raw),'checkpoint':checkpoint.model_dump(mode='json')}

    @staticmethod
    def _aad(manifest):
        return canonical(manifest.model_dump(mode='json',exclude={'payload_sha256','payload_bytes'}))

    @bounded
    def backup(self, output, checkpoint_path, expected_checkpoint_sha256, principal, *, now=None):
        self._authorize(principal)
        cp_path = self._external(checkpoint_path,output)
        checkpoint = load_checkpoint(cp_path,expected_checkpoint_sha256)
        now = self.ledger._now(datetime.now(UTC) if now is None else now)
        require(now >= datetime.fromisoformat(checkpoint.issued_at),'web_backup_future_checkpoint')
        output = self._output(output)
        with self.ledger._transaction(now) as (db,key,records,head):
            witness = decode(self.ledger._read(self.ledger.control/'witness.json',8192))
            high = datetime.fromisoformat(witness['state']['observed_until']) if witness['state']['observed_until'] else None
            check_anchor(db,records,head,high,checkpoint)
            require(Head.model_validate(head) == checkpoint.head,'web_backup_checkpoint_not_current_head')
            with closing(sqlite3.connect(self.ledger.database.as_uri()+'?mode=ro',uri=True)) as source, closing(sqlite3.connect(':memory:')) as copy:
                source.backup(copy,pages=256)
                raw_database = copy.serialize()
            require(len(raw_database) <= MAX_DATABASE,'web_backup_database_bound')
            self.ledger._save({'current':head,'pending':None,'observed_until':now.isoformat()},key)
            raw_witness = self.ledger._read(self.ledger.control/'witness.json',8192)
            snapshot = Checkpoint(schema_version='zt-web-external-checkpoint-1',head=Head.model_validate(head),
                observed_until=now.isoformat(),issued_at=now.isoformat())
            raw = canonical({'schema':'zt-web-ledger-backup-payload-1','database':encode(raw_database),
                             'witness':encode(raw_witness),'witness_key':encode(key)})
            require(len(raw)+16 <= MAX_PACKAGE,'web_backup_package_bound')
            nonce = secrets.token_bytes(12)
            manifest = BackupManifest(schema_version='zt-web-ledger-backup-1',algorithm='AES-256-GCM',key_id=self.key_id,
                capacity=self.ledger.capacity,snapshot=snapshot,nonce=base64.urlsafe_b64encode(nonce).decode(),
                payload_sha256=ZERO,payload_bytes=16)
            payload = self.cipher.encrypt(nonce,raw,self._aad(manifest))
        atomic(output/'payload.aesgcm',payload)
        self._phase('after_backup_payload')
        manifest = manifest.model_copy(update={'payload_sha256':sha(payload),'payload_bytes':len(payload)})
        raw_manifest = canonical(manifest.model_dump(mode='json'))+b'\n'
        atomic(output/'manifest.json',raw_manifest)  # Publication marker, after the entire encrypted payload.
        self._phase('after_backup_publish')
        return {'manifest_sha256':sha(raw_manifest),'checkpoint_sha256':expected_checkpoint_sha256,
                'snapshot':snapshot.model_dump(mode='json'),'payload_bytes':len(payload)}

    @bounded
    def restore(self, backup, expected_manifest_sha256, checkpoint_path, expected_checkpoint_sha256,
                output, principal, *, now=None):
        self._authorize(principal)
        backup = Path(backup).absolute()
        require(backup.is_dir() and not backup.is_symlink()
                and {p.name for p in backup.iterdir()} == {'manifest.json','payload.aesgcm'},'web_backup_exact_inventory')
        checkpoint = load_checkpoint(self._external(checkpoint_path,output),expected_checkpoint_sha256)
        require(not Path(checkpoint_path).resolve().is_relative_to(backup.resolve()),'web_backup_checkpoint_not_in_package')
        manifest = BackupManifest.model_validate(decode(pinned(backup/'manifest.json',expected_manifest_sha256,16384)))
        require(manifest.key_id == self.key_id and manifest.capacity == self.ledger.capacity
                and manifest.snapshot.head.configuration == self.ledger.config,'web_backup_configuration')
        require(manifest.snapshot.head.store_id == checkpoint.head.store_id
                and manifest.snapshot.head.configuration == checkpoint.head.configuration
                and manifest.snapshot.head.seq >= checkpoint.head.seq
                and datetime.fromisoformat(manifest.snapshot.observed_until) >= datetime.fromisoformat(checkpoint.observed_until),
                'web_backup_older_than_checkpoint')
        require(not Path(output).resolve().is_relative_to(backup.resolve())
                and not backup.resolve().is_relative_to(Path(output).resolve()), 'web_backup_restore_path_overlap')
        payload = pinned(backup/'payload.aesgcm',manifest.payload_sha256,MAX_PACKAGE)
        require(len(payload) == manifest.payload_bytes,'web_backup_payload_size')
        try:
            raw = self.cipher.decrypt(base64.urlsafe_b64decode(manifest.nonce),payload,self._aad(manifest))
        except InvalidTag:
            raise LedgerUnavailable('web_backup_authentication_failed') from None
        require(len(raw) <= MAX_PACKAGE,'web_backup_decrypted_bound')
        data = decode(raw)
        require(set(data) == {'schema','database','witness','witness_key'}
                and data['schema'] == 'zt-web-ledger-backup-payload-1','web_backup_payload_schema')
        raw_database,raw_witness,key = (unencode(data[name],limit) for name,limit in
            [('database',MAX_DATABASE),('witness',8192),('witness_key',32)])
        require(len(key) == 32,'web_backup_witness_key')
        now = self.ledger._now(datetime.now(UTC) if now is None else now)
        require(now >= datetime.fromisoformat(checkpoint.issued_at)
                and now >= datetime.fromisoformat(manifest.snapshot.observed_until),'web_backup_restore_clock')
        output = self._output(output)
        self._phase('before_restore_state')
        stage = output/'.state-incomplete'
        stage.mkdir(mode=0o700)
        control = stage/'witness'
        control.mkdir(mode=0o700)
        for path,body in [(stage/'events.sqlite',raw_database),(control/'witness.json',raw_witness),
                          (control/'witness.key',key),(control/'journal.lock',b'0')]:
            atomic(path,body)
            path.chmod(0o600)
        restored = WebEvidenceLedger(stage/'events.sqlite',control,capacity=self.ledger.capacity)
        with restored._transaction(now) as (db,_,records,head):
            witness = decode(restored._read(control/'witness.json',8192))
            high = datetime.fromisoformat(witness['state']['observed_until'])
            require(Head.model_validate(head) == manifest.snapshot.head
                    and high == datetime.fromisoformat(manifest.snapshot.observed_until),'web_backup_snapshot_mismatch')
            check_anchor(db,records,head,high,checkpoint)
            public_head = Head.model_validate(head).model_dump(mode='json')
        self._phase('before_restore_publish')
        require(not (output/'state').exists(),'web_backup_state_collision')
        stage.rename(output/'state')
        receipt = {'schema':'zt-web-ledger-restore-1','manifest_sha256':expected_manifest_sha256,
            'checkpoint_sha256':expected_checkpoint_sha256,'head':public_head,'restored_at':now.isoformat(),
            'capacity':self.ledger.capacity,'automatic_activation_allowed':False}
        raw_receipt = canonical(receipt)+b'\n'
        atomic(output/'restore.json',raw_receipt)
        self._phase('after_restore_publish')
        return {'receipt_sha256':sha(raw_receipt),'head':public_head,'activated':False}

    @bounded
    def open_restored(self, output, expected_receipt_sha256, checkpoint_path, expected_checkpoint_sha256,
                      principal, *, now=None):
        self._authorize(principal)
        output = Path(output).absolute()
        require(output.is_dir() and not output.is_symlink() and (output/'state').is_dir()
                and not (output/'state').is_symlink(),'web_backup_restore_not_published')
        receipt = decode(pinned(output/'restore.json',expected_receipt_sha256,16384))
        require(set(receipt) == {'schema','manifest_sha256','checkpoint_sha256','head','restored_at','capacity','automatic_activation_allowed'}
                and receipt['schema'] == 'zt-web-ledger-restore-1' and receipt['capacity'] == self.ledger.capacity
                and receipt['checkpoint_sha256'] == expected_checkpoint_sha256
                and receipt['automatic_activation_allowed'] is False,'web_backup_restore_publication')
        cp_path = self._external(checkpoint_path,output)
        ledger = CheckpointedWebLedger(output/'state/events.sqlite',output/'state/witness',cp_path,
            expected_checkpoint_sha256,capacity=self.ledger.capacity)
        now = ledger._now(datetime.now(UTC) if now is None else now)
        with ledger._transaction(now) as (db,_,records,head):
            initial = Head.model_validate(receipt['head'])
            minimum = Checkpoint(schema_version='zt-web-external-checkpoint-1',head=initial,
                observed_until=receipt['restored_at'],issued_at=receipt['restored_at'])
            witness = decode(ledger._read(ledger.control/'witness.json',8192))
            check_anchor(db,records,head,datetime.fromisoformat(witness['state']['observed_until']),minimum)
        return ledger
