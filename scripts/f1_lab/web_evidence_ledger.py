"""Bounded local web verification journal with authenticated recovery witness."""

import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Literal

from pydantic import Field, StrictBool

from app.config import get_settings
from app.models import StrictModel
from app.security import Principal, Role
from scripts.ca_recovery_state import atomic, locked
from scripts.f1_lab.native_jsonl import decode
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.web_verified_context import SHA, WebRequest, digest

ZERO = '0'*64
APPLICATION_ID = 1515475538
TABLE = 'CREATE TABLE web_records (seq INTEGER PRIMARY KEY, body TEXT NOT NULL, previous_hash TEXT NOT NULL, record_hash TEXT NOT NULL)'
MAX_BODY, MAX_DATABASE = 8192, 64*1024**2


class LedgerUnavailable(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise LedgerUnavailable(code)


def bounded(operation):
    @wraps(operation)
    def call(*args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except LedgerUnavailable:
            raise
        except (sqlite3.Error, ValueError, TypeError, OSError, KeyError, AttributeError, OverflowError):
            raise LedgerUnavailable('web_ledger_unavailable') from None
    return call


class RecordedDecision(StrictModel):
    baseline_score: float = Field(strict=True, ge=0, le=1, allow_inf_nan=False)
    score: float = Field(strict=True, ge=0, le=1, allow_inf_nan=False)
    alert: StrictBool
    review: StrictBool
    reason: str = Field(pattern=r'^[a-z0-9_]{1,128}$')
    state: Literal['baseline_only', 'adverse', 'consistent', 'review', 'incomplete', 'unavailable']
    evidence_sha256: SHA | None

    @classmethod
    def capture(cls, value):
        require(value.automatic_enforcement_allowed is False, 'web_ledger_advisory_only')
        result = cls(baseline_score=value.baseline_score, score=value.score, alert=value.alert,
            review=value.review, reason=value.reason, state=getattr(value, 'evidence_state', 'baseline_only'),
            evidence_sha256=getattr(value, 'evidence_sha256', None))
        require(result.state != 'adverse' or result.alert and result.review and result.score == 1.
                and result.evidence_sha256 is not None, 'web_ledger_adverse_shape')
        return result


@dataclass(frozen=True)
class Attempt:
    request_key: str
    request_sha256: str
    owner_sha256: str
    nonce_sha256: str
    duplicate: bool


class WebEvidenceLedger:
    def __init__(self, database, control, *, capacity=2000):
        require(type(capacity) is int and 2 <= capacity <= 10000, 'web_ledger_capacity_config')
        self.database, self.control, self.capacity = Path(database).absolute(), Path(control).absolute(), capacity
        self.config = digest({'schema':'zt-web-evidence-ledger-1', 'capacity':capacity,
            'policy':'exact-request-owner; retain-max-alert-review; no-auto-resolution'})

    def _local(self):
        require(get_settings().app_environment in {'local','test'}, 'web_ledger_local_test_only')
        require(not self.database.is_symlink() and not self.control.is_symlink(), 'web_ledger_path')

    @staticmethod
    def _identity(request, principal):
        require(isinstance(request, WebRequest) and isinstance(principal, Principal)
                and principal.tenant_id == request.tenant_id and bool(principal.subject.strip())
                and principal.auth_method in {'api_key','oidc'} and Role.ANALYST in principal.effective_roles,
                'web_ledger_operator')
        return {'request_key':digest([request.tenant_id,request.server_id,request.request_id]),
            'request_sha256':digest(request.model_dump(mode='json')),
            'owner_sha256':digest([principal.tenant_id,principal.subject]), 'case_id':request.case_id}

    @staticmethod
    def _now(now):
        require(isinstance(now, datetime) and now.tzinfo is not None and now.utcoffset() is not None,
                'web_ledger_clock')
        return now.astimezone(UTC)

    def _read(self, path, maximum):
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum, 'web_ledger_file')
        with path.open('rb') as stream:
            raw = stream.read(maximum+1)
        require(len(raw) <= maximum, 'web_ledger_file_bound')
        return raw

    @contextmanager
    def _locked(self):
        if os.name != 'nt':
            with locked(self.control):
                yield
            return
        import msvcrt
        path = self.control/'journal.lock'
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == 1, 'web_ledger_lock')
        with path.open('r+b') as stream:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)

    def _save(self, value, key):
        body = {'schema':'zt-web-evidence-witness-1', 'state':value}
        tag = hmac.new(key,canonical(body),hashlib.sha256).hexdigest()
        atomic(self.control/'witness.json',canonical({**body,'hmac_sha256':tag}))

    @bounded
    def initialize(self):
        self._local()
        require(not self.database.exists() and not self.control.exists(), 'web_ledger_fresh_storage')
        self.database.parent.mkdir(parents=True,exist_ok=True)
        self.control.mkdir(parents=True,mode=0o700)
        with (self.control/'journal.lock').open('xb') as stream:
            stream.write(b'0')
            stream.flush()
            os.fsync(stream.fileno())
        key = secrets.token_bytes(32)
        atomic(self.control/'witness.key',key)
        (self.control/'witness.key').chmod(0o600)
        self.database.open('xb').close()
        self.database.chmod(0o600)
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA application_id='+str(APPLICATION_ID))
            db.execute('PRAGMA user_version=1')
            db.execute(TABLE)
        head = {'store_id':secrets.token_hex(16),'configuration':self.config,'seq':0,'hash':ZERO,'last_now':None}
        self._save({'current':head,'pending':None,'observed_until':None},key)
        return {'store_id':head['store_id'],'configuration':self.config}

    def _connect(self):
        require(self.database.is_file() and not self.database.is_symlink()
                and self.database.stat().st_size <= MAX_DATABASE, 'web_ledger_database')
        return sqlite3.connect(self.database.as_uri()+'?mode=rw',uri=True,timeout=5)

    def _recover(self, db, key):
        require(db.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID
                and db.execute('PRAGMA user_version').fetchone()[0] == 1
                and db.execute('SELECT type,name,sql FROM sqlite_schema').fetchall() == [('table','web_records',TABLE)]
                and db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'web_ledger_database_identity')
        witness = decode(self._read(self.control/'witness.json',8192))
        require(set(witness) == {'schema','state','hmac_sha256'} and witness['schema'] == 'zt-web-evidence-witness-1',
                'web_ledger_witness_schema')
        body = {k:witness[k] for k in ('schema','state')}
        require(isinstance(witness['hmac_sha256'], str)
                and hmac.compare_digest(witness['hmac_sha256'],hmac.new(key,canonical(body),hashlib.sha256).hexdigest()),
                'web_ledger_witness_authentication')
        state = witness['state']
        require(set(state) == {'current','pending','observed_until'}, 'web_ledger_witness_state')
        for head in (state['current'],state['pending']):
            if head is not None:
                require(set(head) == {'store_id','configuration','seq','hash','last_now'}
                        and head['configuration'] == self.config and type(head['seq']) is int
                        and 0 <= head['seq'] <= self.capacity, 'web_ledger_configuration')
        high = self._now(datetime.fromisoformat(state['observed_until'])) if state['observed_until'] else None
        records, previous = [], ZERO
        rows = db.execute('SELECT seq,body,previous_hash,record_hash FROM web_records ORDER BY seq').fetchmany(self.capacity+1)
        require(len(rows) <= self.capacity, 'web_ledger_capacity')
        for expected,(seq,text,prior,current) in enumerate(rows,1):
            require(seq == expected and isinstance(text,str) and len(text.encode()) <= MAX_BODY and prior == previous
                    and current == hashlib.sha256(previous.encode()+b'.'+text.encode()).hexdigest(), 'web_ledger_chain')
            record = decode(text.encode())
            require(canonical(record).decode() == text and set(record) == {'store_id','accepted_at','identity',
                    'nonce_sha256','kind','decision','deadline'}, 'web_ledger_record_shape')
            identity = record['identity']
            require(set(identity) == {'request_key','request_sha256','owner_sha256','case_id'}
                    and all(isinstance(v,str) and len(v) == 64 and set(v) <= set('0123456789abcdef')
                            for v in [*identity.values(),record['nonce_sha256']]), 'web_ledger_record_identity')
            require(record['kind'] in {'started','completed','interrupted'}, 'web_ledger_record_kind')
            if record['kind'] != 'interrupted':
                RecordedDecision.model_validate(record['decision'])
            else:
                require(record['decision'] is None, 'web_ledger_interrupted_not_verified')
            accepted = self._now(datetime.fromisoformat(record['accepted_at']))
            require(high is not None and accepted <= high, 'web_ledger_record_clock')
            self._now(datetime.fromisoformat(record['deadline']))
            records.append(record)
            previous = current
        actual = {'seq':len(rows),'hash':previous,'last_now':records[-1]['accepted_at'] if records else None}
        def same(head):
            return all(head[k] == v for k,v in actual.items()) and all(r['store_id'] == head['store_id'] for r in records)
        head, pending = state['current'],state['pending']
        if pending is not None:
            require(pending['store_id'] == head['store_id'] and pending['seq'] == head['seq']+1, 'web_ledger_pending_head')
            if same(pending):
                head = pending
            else:
                require(same(head), 'web_ledger_pending_database_conflict')
            self._save({'current':head,'pending':None,'observed_until':state['observed_until']},key)
        else:
            require(same(head), 'web_ledger_rollback_or_witness_mismatch')
        self._reduce(records)  # Validate the entire lifecycle, never trust a mutable summary column.
        return records,head,high

    def _reduce(self, records):
        requests, nonces = {}, {}
        for record in records:
            identity, nonce = record['identity'],record['nonce_sha256']
            item = requests.setdefault(identity['request_key'],{'identity':identity,'attempts':{},
                'score':0.,'alert':False,'review':False,'verified_adverse':False,'interrupted':False})
            require(item['identity'] == identity, 'web_ledger_request_identity_conflict')
            require(nonce not in nonces or nonces[nonce] == identity['request_key'], 'web_ledger_nonce_scope_conflict')
            nonces[nonce] = identity['request_key']
            if record['kind'] == 'started':
                require(nonce not in item['attempts'], 'web_ledger_duplicate_start')
                item['attempts'][nonce] = {'state':'pending','deadline':record['deadline']}
            else:
                require(nonce in item['attempts'] and item['attempts'][nonce]['state'] == 'pending'
                        and item['attempts'][nonce]['deadline'] == record['deadline'], 'web_ledger_attempt_transition')
                item['attempts'][nonce]['state'] = record['kind']
            if record['decision'] is not None:
                decision = RecordedDecision.model_validate(record['decision'])
                require(decision.state != 'adverse' or record['kind'] == 'completed', 'web_ledger_adverse_must_complete')
                item['score'] = max(item['score'],decision.score)
                item['alert'] |= decision.alert
                item['review'] |= decision.review
                item['verified_adverse'] |= decision.state == 'adverse'
            item['interrupted'] |= record['kind'] == 'interrupted'
        return requests

    @contextmanager
    def _transaction(self, now):
        self._local()
        require(self.control.is_dir(), 'web_ledger_control_missing')
        with self._locked(),closing(self._connect()) as db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            try:
                key = self._read(self.control/'witness.key',32)
                require(len(key) == 32,'web_ledger_witness_key')
                records,head,high = self._recover(db,key)
                require(high is None or now >= high,'web_ledger_clock_rollback')
                yield db,key,records,head
                db.commit()
                self._save({'current':head,'pending':None,'observed_until':now.isoformat()},key)
            except BaseException:
                db.rollback()
                raise

    def _phase(self, _point):
        """Fault-injection boundary for process-exit tests only."""

    def _append(self, db, key, records, head, record, now):
        require(len(records) < self.capacity,'web_ledger_capacity')
        record = {'store_id':head['store_id'],'accepted_at':now.isoformat(),**record}
        raw = canonical(record)
        require(len(raw) <= MAX_BODY,'web_ledger_record_bound')
        self._reduce([*records,record])
        next_head = {**head,'seq':head['seq']+1,'hash':hashlib.sha256(head['hash'].encode()+b'.'+raw).hexdigest(),
                     'last_now':now.isoformat()}
        self._save({'current':head,'pending':next_head,'observed_until':now.isoformat()},key)
        self._phase('after_prepare')
        db.execute('INSERT INTO web_records VALUES (?,?,?,?)',(next_head['seq'],raw.decode(),head['hash'],next_head['hash']))
        self._phase('before_db_commit')
        db.commit()
        self._phase('after_db_commit')
        self._save({'current':next_head,'pending':None,'observed_until':now.isoformat()},key)
        self._phase('after_publish')
        records.append(record)
        head.update(next_head)

    @bounded
    def begin(self, request, principal, nonce_sha256, baseline, *, deadline, now=None):
        identity = self._identity(request,principal)
        now, deadline = self._now(datetime.now(UTC) if now is None else now),self._now(deadline)
        require(now < deadline and (deadline-now).total_seconds() <= 30,'web_ledger_attempt_deadline')
        require(isinstance(nonce_sha256,str) and len(nonce_sha256) == 64
                and set(nonce_sha256) <= set('0123456789abcdef'),'web_ledger_nonce_shape')
        decision = RecordedDecision.capture(baseline)
        require(decision.state == 'baseline_only','web_ledger_begin_requires_baseline')
        with self._transaction(now) as (db,key,records,head):
            for record in records:
                if record['identity']['request_key'] == identity['request_key']:
                    require(record['identity'] == identity,'web_ledger_request_identity_conflict')
                if record['nonce_sha256'] == nonce_sha256:
                    require(record['identity'] == identity,'web_ledger_nonce_scope_conflict')
                    return Attempt(identity['request_key'],identity['request_sha256'],identity['owner_sha256'],nonce_sha256,True)
            requests = self._reduce(records)
            pending = sum(a['state'] == 'pending' for item in requests.values() for a in item['attempts'].values())
            require(len(records)+pending+2 <= self.capacity,'web_ledger_capacity')
            self._append(db,key,records,head,{'identity':identity,'nonce_sha256':nonce_sha256,'kind':'started',
                'decision':decision.model_dump(mode='json'),'deadline':deadline.isoformat()},now)
        return Attempt(identity['request_key'],identity['request_sha256'],identity['owner_sha256'],nonce_sha256,False)

    @bounded
    def finish(self, request, principal, attempt, result, *, now=None):
        identity, now = self._identity(request,principal),self._now(datetime.now(UTC) if now is None else now)
        require(isinstance(attempt,Attempt) and (attempt.request_key,attempt.request_sha256,attempt.owner_sha256) ==
                (identity['request_key'],identity['request_sha256'],identity['owner_sha256']), 'web_ledger_attempt_binding')
        decision = RecordedDecision.capture(result)
        with self._transaction(now) as (db,key,records,head):
            matches = [r for r in records if r['nonce_sha256'] == attempt.nonce_sha256]
            require(matches and all(r['identity'] == identity for r in matches),'web_ledger_attempt_missing')
            if len(matches) > 1:
                require(matches[-1]['kind'] == 'completed' and matches[-1]['decision'] == decision.model_dump(mode='json'),
                        'web_ledger_completion_conflict')
                return
            require(now < datetime.fromisoformat(matches[0]['deadline']),'web_ledger_expired_attempt')
            self._append(db,key,records,head,{'identity':identity,'nonce_sha256':attempt.nonce_sha256,'kind':'completed',
                'decision':decision.model_dump(mode='json'),'deadline':matches[0]['deadline']},now)

    @bounded
    def recover_pending(self, request, principal, *, now=None):
        identity, now = self._identity(request,principal),self._now(datetime.now(UTC) if now is None else now)
        with self._transaction(now) as (db,key,records,head):
            item = self._reduce(records).get(identity['request_key'])
            require(item is not None and item['identity'] == identity,'web_ledger_request_unavailable')
            pending = [(n,a) for n,a in item['attempts'].items() if a['state'] == 'pending']
            require(all(now >= datetime.fromisoformat(a['deadline']) for _,a in pending),'web_ledger_attempt_still_active')
            require(len(records)+len(pending) <= self.capacity,'web_ledger_capacity')
            for nonce,attempt in pending:
                self._append(db,key,records,head,{'identity':identity,'nonce_sha256':nonce,'kind':'interrupted',
                    'decision':None,'deadline':attempt['deadline']},now)
        return self.summary(request,principal,now=now)

    @bounded
    def summary(self, request, principal, *, now=None):
        identity, now = self._identity(request,principal),self._now(datetime.now(UTC) if now is None else now)
        with self._transaction(now) as (_,_,records,head):
            item = self._reduce(records).get(identity['request_key'])
            if item is None:
                return None
            require(item['identity'] == identity,'web_ledger_request_identity_conflict')
            pending = sum(a['state'] == 'pending' for a in item['attempts'].values())
            return {'schema':'zt-web-ledger-summary-1','request_key':identity['request_key'],
                'request_sha256':identity['request_sha256'],'case_id':identity['case_id'],
                'score':item['score'],'alert':item['alert'],
                'review':item['review'] or item['interrupted'] or bool(pending),
                'verified_adverse':item['verified_adverse'],'interrupted':item['interrupted'],
                'pending_attempts':pending,'attempts':len(item['attempts']),
                'events':sum(r['identity'] == identity for r in records),
                'journal_head_sha256':head['hash'],'automatic_resolution_allowed':False}
