"""Bounded local signed-event windows with a separate authenticated recovery witness.

Only operator-configured event producers may submit deltas. Session snapshots
must not be relabelled as events. This does not issue or restore access grants.
"""

import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
from contextlib import closing, contextmanager
from datetime import UTC, datetime, timedelta
from functools import wraps
from pathlib import Path

from app.config import get_settings
from app.security import Principal, Role
from app.services.trusted_signals import (
    SignalRegistryUnavailable,
    SignalRejected,
    SignalVerifier,
    canonical_signal,
)
from app.zero_trust_models import SignedSessionSignal
from scripts.ca_recovery_state import atomic, locked
from scripts.f1_lab.resource_policy import PinnedResourcePolicies, ResourcePolicyUnavailable

ZERO = '0' * 64
APPLICATION_ID = 1515475537
TABLE = 'CREATE TABLE signed_events (seq INTEGER PRIMARY KEY, body TEXT NOT NULL, previous_hash TEXT NOT NULL, record_hash TEXT NOT NULL)'
MAX_BODY = 32768
MAX_DATABASE = 64 * 1024**2
MAX_DOWNLOAD_DELTA_MB = 1_000_000_000


class TemporalUnavailable(ValueError):
    pass


def bounded(operation):
    @wraps(operation)
    def call(*args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except TemporalUnavailable:
            raise
        except (sqlite3.Error, OSError, ValueError, TypeError, KeyError, OverflowError):
            raise TemporalUnavailable('temporal_store_unavailable') from None
    return call


def require(condition, code):
    if not condition:
        raise TemporalUnavailable(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def instant(value):
    require(isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None,
            'temporal_clock_requires_timezone')
    return value.astimezone(UTC)


def read(path, limit):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit,
            'temporal_regular_bounded_file')
    with path.open('rb') as stream:
        raw = stream.read(limit+1)
    require(len(raw) <= limit, 'temporal_file_size')
    return raw


class TemporalStore:
    def __init__(self, database: Path, control: Path, verifier: SignalVerifier, event_sources, *,
                 window_seconds=600, capacity=1000, resource_policies=None):
        self.database, self.control = Path(database), Path(control)
        self.verifier = verifier
        require(resource_policies is None or isinstance(resource_policies, PinnedResourcePolicies),
                'temporal_resource_policy_contract')
        self.resource_policies = resource_policies
        self.event_sources = frozenset(event_sources)
        require(0 < len(self.event_sources) <= 100 and all(isinstance(v, tuple) and len(v) == 3
                and all(isinstance(s, str) and s for s in v) for v in self.event_sources),
                'temporal_event_producer_contract_required')
        require(type(window_seconds) is int and 30 <= window_seconds <= 3600
                and type(capacity) is int and 1 <= capacity <= 2000, 'temporal_configuration_bounds')
        self.window_seconds, self.capacity = window_seconds, capacity
        self.config_sha256 = digest(canonical({'event_producers': sorted(self.event_sources),
            'window_seconds': window_seconds, 'capacity': capacity, 'measurement': 'distinct_events_and_byte_deltas',
            'maximum_download_delta_mb': MAX_DOWNLOAD_DELTA_MB,
            'resource_policy_binding': resource_policies.configuration_binding if resource_policies is not None else None,
            'source_registry_binding': getattr(verifier, 'configuration_binding', None)}))

    def _local(self):
        require(get_settings().app_environment in {'local', 'test'}, 'temporal_local_test_only')
        require(not self.database.is_symlink() and not self.control.is_symlink(), 'temporal_path_scope')

    @bounded
    def initialize(self):
        self._local()
        require(not self.database.exists() and not self.control.exists(), 'temporal_fresh_storage_required')
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self.control.mkdir(parents=True, mode=0o700)
        # Initialize the immutable lock byte before any concurrent readers exist.
        # Windows must not read that byte before obtaining its range lock.
        with (self.control / 'journal.lock').open('xb') as stream:
            stream.write(b'0')
            stream.flush()
            os.fsync(stream.fileno())
        key = secrets.token_bytes(32)
        atomic(self.control / 'witness.key', key)
        (self.control / 'witness.key').chmod(0o600)
        with closing(sqlite3.connect(self.database)) as db, db:
            require(not db.execute("SELECT name FROM sqlite_schema").fetchall(), 'temporal_fresh_database_required')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('PRAGMA application_id='+str(APPLICATION_ID))
            db.execute('PRAGMA user_version=1')
            db.execute(TABLE)
        head = {'store_id': secrets.token_hex(16), 'configuration': self.config_sha256,
                'seq': 0, 'hash': ZERO, 'last_now': None}
        self._save({'current': head, 'pending': None, 'observed_until': None}, key)
        return {'initialized': True, 'store_id': head['store_id'], 'config_sha256': self.config_sha256}

    def _key(self):
        key = read(self.control / 'witness.key', 32)
        require(len(key) == 32, 'temporal_witness_key_shape')
        return key

    @contextmanager
    def _locked(self):
        if os.name != 'nt':
            with locked(self.control):
                yield
            return
        import msvcrt

        path = self.control / 'journal.lock'
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == 1,
                'temporal_lock_file_identity')
        with path.open('r+b') as stream:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)

    def _save(self, value, key):
        body = {'schema': 'f1-temporal-witness-2', 'state': value}
        tag = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
        atomic(self.control / 'witness.json', canonical({**body, 'hmac_sha256': tag}))

    def _witness(self, key):
        raw = json.loads(read(self.control / 'witness.json', 4096))
        require(set(raw) == {'schema', 'state', 'hmac_sha256'} and raw['schema'] == 'f1-temporal-witness-2',
                'temporal_witness_contract')
        require(isinstance(raw['hmac_sha256'], str) and len(raw['hmac_sha256']) == 64,
                'temporal_witness_tag_shape')
        body = {k: raw[k] for k in ('schema', 'state')}
        require(hmac.compare_digest(hmac.new(key, canonical(body), hashlib.sha256).hexdigest(),
                                    raw['hmac_sha256']), 'temporal_witness_authentication')
        value = raw['state']
        require(set(value) == {'current', 'pending', 'observed_until'}, 'temporal_witness_state')
        for head in (value['current'], value['pending']):
            if head is None:
                continue
            require(set(head) == {'store_id', 'configuration', 'seq', 'hash', 'last_now'} and
                    head['configuration'] == self.config_sha256 and type(head['seq']) is int
                    and 0 <= head['seq'] <= self.capacity and isinstance(head['hash'], str)
                    and len(head['hash']) == 64, 'temporal_witness_head')
        high_water = value['observed_until']
        require(high_water is None or isinstance(high_water, str), 'temporal_clock_high_water')
        parsed_high_water = instant(datetime.fromisoformat(high_water)) if high_water is not None else None
        for head in (value['current'], value['pending']):
            if head is not None and head['last_now'] is not None:
                require(parsed_high_water is not None
                        and parsed_high_water >= instant(datetime.fromisoformat(head['last_now'])),
                        'temporal_clock_high_water')
        return value

    def _rows(self, db):
        require(db.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID
                and db.execute('PRAGMA user_version').fetchone()[0] == 1
                and db.execute("SELECT type,name,sql FROM sqlite_schema").fetchall() == [('table', 'signed_events', TABLE)],
                'temporal_database_identity')
        require(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'temporal_database_integrity')
        rows = db.execute('SELECT seq,body,previous_hash,record_hash FROM signed_events ORDER BY seq').fetchmany(self.capacity+1)
        require(len(rows) <= self.capacity, 'temporal_capacity')
        entries, previous = [], ZERO
        for expected, (seq, body, prior, current) in enumerate(rows, 1):
            require(seq == expected and isinstance(body, str) and len(body.encode()) <= MAX_BODY
                    and prior == previous and current == digest(previous.encode()+b'.'+body.encode()),
                    'temporal_journal_chain')
            record = json.loads(body)
            require(canonical(record).decode() == body and set(record) == {'store_id', 'operator', 'tenant',
                'session', 'input_sha256', 'source_digest', 'accepted_at', 'signal'}, 'temporal_journal_record')
            entries.append(record)
            previous = current
        return entries, {'seq': len(rows), 'hash': previous,
                         'last_now': entries[-1]['accepted_at'] if entries else None}

    def _recover(self, db, key):
        witness = self._witness(key)
        entries, actual = self._rows(db)
        current, pending = witness['current'], witness['pending']

        def same(head):
            return all(head[k] == v for k, v in actual.items()) and all(
                row['store_id'] == head['store_id'] for row in entries)

        if pending is not None:
            require(pending['store_id'] == current['store_id'] and pending['seq'] == current['seq']+1,
                    'temporal_pending_identity')
            if same(pending):
                current = pending
            else:
                require(same(current), 'temporal_pending_database_conflict')
            self._save({'current': current, 'pending': None, 'observed_until': witness['observed_until']}, key)
        else:
            require(same(current), 'temporal_database_rollback_or_witness_mismatch')
        return entries, current, witness['observed_until']

    def _clock(self, high_water, now):
        require(high_water is None or now >= datetime.fromisoformat(high_water), 'temporal_clock_rollback')

    def _connect(self):
        read(self.database, MAX_DATABASE)
        return sqlite3.connect(self.database, timeout=5)

    def _phase(self, _name):
        """Test fault boundary; default has no effects."""

    def _authorize(self, principal):
        require(isinstance(principal, Principal) and Role.ANALYST in principal.effective_roles
                and principal.auth_method != 'disabled' and bool(principal.subject.strip()),
                'temporal_authenticated_analyst_required')

    @bounded
    def observe(self, signal: SignedSessionSignal, principal: Principal, *, now=None):
        self._local()
        self._authorize(principal)
        now = instant(datetime.now(UTC) if now is None else now)
        require(isinstance(signal, SignedSessionSignal), 'temporal_signed_event_required')
        require((principal.tenant_id, signal.source_id, signal.key_id) in self.event_sources,
                'temporal_source_is_not_event_producer')
        try:
            proof = self.verifier.verify(signal, principal, now)
            source = self.verifier._sources()[(principal.tenant_id, signal.source_id)]
            key_record = next(k for k in source.keys if k.key_id == signal.key_id)
            require(signal.issued_at >= key_record.not_before, 'temporal_key_issued_before_activation')
        except (SignalRejected, SignalRegistryUnavailable, KeyError, StopIteration):
            raise TemporalUnavailable('temporal_source_rejected') from None
        event = signal.event
        require(timedelta(0) <= now-instant(event.timestamp) <= timedelta(seconds=60)
                and math.isfinite(event.behavior.download_volume_mb)
                and event.behavior.download_volume_mb <= MAX_DOWNLOAD_DELTA_MB, 'temporal_observation_freshness')
        input_sha256 = digest(canonical_signal(signal))
        with self._locked(), closing(self._connect()) as db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            key = self._key()
            entries, head, high_water = self._recover(db, key)
            try:
                current_digest = self.verifier.source_digest(principal.tenant_id, signal.source_id, signal.key_id, now)
            except SignalRegistryUnavailable:
                raise TemporalUnavailable('temporal_current_authority_unavailable') from None
            require(current_digest == proof.source_digest, 'temporal_authority_changed_during_intake')
            self._clock(high_water, now)
            owned = [r for r in entries if r['tenant'] == principal.tenant_id and r['session'] == signal.session_id]
            if owned:
                first = SignedSessionSignal.model_validate(owned[0]['signal'])
                require(owned[0]['operator'] == principal.subject and first.event.user.user_id == event.user.user_id
                        and first.event.device.device_id == event.device.device_id, 'temporal_session_binding')
            duplicate = next((r for r in entries if r['tenant'] == principal.tenant_id
                              and r['signal']['event']['event_id'] == event.event_id), None)
            if duplicate is not None:
                require(duplicate['operator'] == principal.subject and duplicate['input_sha256'] == input_sha256,
                        'temporal_event_identity_conflict')
                result = self._summary(entries, head, signal.session_id, principal, now, duplicate=True)
                db.commit()
                self._save({'current': head, 'pending': None, 'observed_until': now.isoformat()}, key)
                return result
            require(len(entries) < self.capacity, 'temporal_capacity')
            record = {'store_id': head['store_id'], 'operator': principal.subject, 'tenant': principal.tenant_id,
                'session': signal.session_id, 'input_sha256': input_sha256, 'source_digest': proof.source_digest,
                'accepted_at': now.isoformat(), 'signal': signal.model_dump(mode='json')}
            raw = canonical(record)
            require(len(raw) <= MAX_BODY, 'temporal_record_size')
            next_head = {**head, 'seq': head['seq']+1, 'hash': digest(head['hash'].encode()+b'.'+raw),
                         'last_now': now.isoformat()}
            self._save({'current': head, 'pending': next_head, 'observed_until': now.isoformat()}, key)
            self._phase('after_prepare')
            db.execute('INSERT INTO signed_events VALUES (?,?,?,?)',
                       (next_head['seq'], raw.decode(), head['hash'], next_head['hash']))
            self._phase('before_db_commit')
            db.commit()
            self._phase('after_db_commit')
            self._save({'current': next_head, 'pending': None, 'observed_until': now.isoformat()}, key)
            self._phase('after_publish')
            return self._summary([*entries, record], next_head, signal.session_id, principal, now)

    @bounded
    def summary(self, session_id, principal: Principal, *, now=None):
        self._local()
        self._authorize(principal)
        now = instant(datetime.now(UTC) if now is None else now)
        with self._locked(), closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            key = self._key()
            entries, head, high_water = self._recover(db, key)
            self._clock(high_water, now)
            result = self._summary(entries, head, session_id, principal, now)
            db.commit()
            self._save({'current': head, 'pending': None, 'observed_until': now.isoformat()}, key)
            return result

    def _summary(self, entries, head, session_id, principal, now, *, duplicate=False):
        owned = [r for r in entries if r['tenant'] == principal.tenant_id and r['session'] == session_id]
        require(owned and all(r['operator'] == principal.subject for r in owned), 'temporal_session_unavailable')
        try:
            current_sources = self.verifier.current_source_digests(now)
        except SignalRegistryUnavailable:
            raise TemporalUnavailable('temporal_current_authority_unavailable') from None
        selected, excluded = [], 0
        start = now-timedelta(seconds=self.window_seconds)
        for record in owned:
            signal = SignedSessionSignal.model_validate(record['signal'])
            if not start < signal.event.timestamp <= now:
                continue
            identity = signal.tenant_id, signal.source_id, signal.key_id
            if current_sources.get(identity) != record['source_digest']:
                excluded += 1
                continue
            selected.append((record, signal.event))
        events = [event for _, event in selected]
        sensitivities, policy_unavailable, policy_denied = [], 0, 0
        policy_snapshot = None
        if self.resource_policies is not None:
            try:
                policy_snapshot = self.resource_policies.snapshot(now=now)
            except ResourcePolicyUnavailable:
                pass
        for event in events:
            if self.resource_policies is None:
                sensitivities.append(event.resource.sensitivity)
            else:
                try:
                    if policy_snapshot is None:
                        raise ResourcePolicyUnavailable('resource_policy_unavailable')
                    policy = policy_snapshot.resolve(event, principal.tenant_id)
                    sensitivities.append(policy.effective_sensitivity)
                    policy_denied += not policy.role_and_action_allowed
                except ResourcePolicyUnavailable:
                    # Keep received download deltas, never a healthy zero from
                    # an unknown resource. Incomplete authority cannot be approved.
                    sensitivities.append('critical')
                    policy_unavailable += 1
        first = SignedSessionSignal.model_validate(owned[0]['signal']).event
        facts = sorted((event.timestamp.isoformat(), event.event_id, record['input_sha256'], record['source_digest'])
                       for record, event in selected)
        result = {'schema': 'f1-temporal-summary-1', 'store_id': head['store_id'], 'tenant_id': principal.tenant_id,
            'operator': principal.subject, 'session_id': session_id, 'user_id': first.user.user_id,
            'device_id': first.device.device_id, 'as_of': now.isoformat(), 'window_seconds': self.window_seconds,
            'duplicate': duplicate, 'event_count': len(events), 'authority_excluded_events': excluded,
            'complete': excluded == 0 and policy_unavailable == 0 and bool(events),
            'resource_policy_unavailable_events': policy_unavailable,
            'resource_policy_denied_events': policy_denied,
            'resource_policy_binding': self.resource_policies.configuration_binding if self.resource_policies is not None else None,
            'collection_completeness_proven': False,
            'coverage_scope': 'authenticated_received_events_only',
            'failed_login_events': sum(e.action == 'LOGIN' and
                e.auth_context.authentication_result == 'failure' for e in events),
            'sensitive_download_mb': sum(e.behavior.download_volume_mb for e, sensitivity in zip(events, sensitivities)
                if e.action == 'DOWNLOAD' and sensitivity in {'high', 'critical'}),
            'distinct_resources': len({e.resource.resource_id for e in events}),
            'resource_ids': sorted({e.resource.resource_id for e in events}),
            'actions': sorted({e.action.value for e in events}),
            'event_ids': sorted({e.event_id for e in events}),
            'saw_compromised': any(e.device.security_posture == 'compromised' for e in events),
            'saw_at_risk': any(e.device.security_posture == 'at_risk' for e in events),
            'saw_inactive': any(not e.user.active for e in events),
            'saw_rejected_mfa': any(e.auth_context.mfa == 'failed' for e in events),
            'journal_head_sha256': head['hash'],
            'evidence_sha256': digest(canonical({'schema': 'f1-authenticated-window-facts-1',
                'configuration': self.config_sha256,
                'session': [principal.tenant_id, principal.subject, session_id, first.user.user_id, first.device.device_id],
                'events': facts, 'excluded': excluded, 'resource_policy_unavailable': policy_unavailable}))}
        return result
