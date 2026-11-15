"""Private, bounded admission ledger for verified PAM observations.

One journal cursor is one observed event, including across explicit signer key
rotation. This is neither a threat detector nor human authentication. The local
OS, owner, clock and complete database remain trusted; whole-store rollback or
an administrator rewriting a consistent database is not prevented.
"""

import hashlib
import os
import re
import sqlite3
import stat
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path

from scripts.f1_lab.collector_freshness import CollectorScope
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.pam_journal import PamCapture, verify
from scripts.f1_lab.pam_journal_native import private_parent

APPLICATION_ID = 1515475539
MAX_DATABASE = 64*1024**2
TABLES = {
    'metadata': 'CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), config BLOB NOT NULL, checked TEXT, issued TEXT, latest TEXT, window_end INTEGER)',
    'captures': 'CREATE TABLE captures (sha TEXT PRIMARY KEY, body BLOB NOT NULL, admitted TEXT NOT NULL, new_events INTEGER NOT NULL, duplicates INTEGER NOT NULL)',
    'events': 'CREATE TABLE events (id TEXT PRIMARY KEY, body BLOB NOT NULL, sha TEXT NOT NULL, first_capture TEXT NOT NULL REFERENCES captures(sha))',
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def event_body(capture, record):
    # journalctl can serialize the same trusted fields in another JSON order.
    # Each signed capture retains its export hash; event identity compares the
    # semantic fields, including original message hash/times/PID/invocation.
    return canonical({'boot_id': capture.boot_id, 'invocation_id': capture.invocation_id,
        'record': record.model_dump(mode='json', exclude={'exported_projection_sha256'})})


class PamObservationLedger:
    def __init__(self, directory, scope, *, capacity=1000, event_capacity=10000):
        require(os.name == 'posix', 'pam_ledger_linux_only')
        require(type(capacity) is int and 1 <= capacity <= 1000
            and type(event_capacity) is int and 1 <= event_capacity <= 10000, 'pam_ledger_capacity')
        self.directory = Path(directory)
        self.scope = CollectorScope.model_validate(scope.model_dump())
        # A new explicitly approved key for the same source must not reset
        # cursor deduplication. No key is automatically selected or enrolled.
        self.identity = self.scope.model_dump(mode='json', exclude={'key_id'})
        self.config = canonical({'schema': 'zt-pam-observation-ledger-1', 'source': self.identity,
            'capacity': capacity, 'event_capacity': event_capacity})
        self.capacity, self.event_capacity = capacity, event_capacity
        self.path = self.directory/'observations.sqlite3'

    def initialize(self):
        private_parent(self.directory.parent)
        require(not self.directory.exists() and not self.directory.is_symlink(), 'pam_ledger_fresh_directory')
        self.directory.mkdir(mode=0o700)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(self.path, timeout=5)) as con, con:
            con.execute('PRAGMA page_size=4096')
            con.execute('PRAGMA application_id='+str(APPLICATION_ID))
            con.execute('PRAGMA user_version=1')
            for sql in TABLES.values():
                con.execute(sql)
            con.execute('INSERT INTO metadata VALUES (1,?,NULL,NULL,NULL,NULL)', (self.config,))
        self._sync_directory()

    def _sync_directory(self):
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _file(self, path, *, optional=False):
        if optional and not path.exists() and not path.is_symlink():
            return
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_nlink == 1
            and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size <= MAX_DATABASE, 'pam_ledger_private_file')

    @contextmanager
    def _connect(self):
        private_parent(self.directory)
        self._file(self.path)
        self._file(self.path.with_name(self.path.name+'-journal'), optional=True)
        require(all(not self.path.with_name(self.path.name+suffix).exists()
            and not self.path.with_name(self.path.name+suffix).is_symlink() for suffix in ('-wal', '-shm')),
            'pam_ledger_rollback_journal_required')
        con = sqlite3.connect(self.path, timeout=5)
        try:
            con.execute('PRAGMA trusted_schema=OFF')
            con.execute('PRAGMA foreign_keys=ON')
            con.execute('PRAGMA synchronous=FULL')
            con.execute('PRAGMA max_page_count=16384')
            require(con.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID
                and con.execute('PRAGMA user_version').fetchone()[0] == 1
                and con.execute('PRAGMA journal_mode').fetchone()[0] == 'delete'
                and con.execute('PRAGMA quick_check').fetchall() == [('ok',)], 'pam_ledger_database')
            schema = dict(con.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"))
            require(schema == TABLES and not con.execute("SELECT 1 FROM sqlite_master WHERE type IN ('trigger','view')").fetchone(),
                    'pam_ledger_schema')
            with con:
                con.execute('BEGIN IMMEDIATE')
                meta = con.execute('SELECT config FROM metadata WHERE id=1').fetchone()
                require(meta == (self.config,), 'pam_ledger_scope_or_config')
                yield con
            self._file(self.path)
        finally:
            con.close()

    def admit(self, capture, pinned, *, boot, invocation, now=None, clock=lambda: datetime.now(UTC)):
        real_clock = now is None
        now = clock() if now is None else now
        capture = PamCapture.model_validate(capture.model_dump())
        verify(capture, self.scope, pinned, boot=boot, invocation=invocation, now=now)
        registry = pinned.current(now)
        raw = canonical(capture.model_dump(mode='json'))
        require(len(raw) <= 4*1024**2, 'pam_ledger_capture_bound')
        capture_sha = digest(raw)
        self.inventory()
        with self._connect() as con:
            checked, issued, _latest, window_end = con.execute(
                'SELECT checked,issued,latest,window_end FROM metadata WHERE id=1').fetchone()
            require(checked is None or now >= datetime.fromisoformat(checked), 'pam_ledger_clock_regression')
            old = con.execute('SELECT body FROM captures WHERE sha=?', (capture_sha,)).fetchone()
            if old:
                require(old[0] == raw, 'pam_ledger_capture_changed')
                new_count = duplicate_count = 0
            else:
                require(issued is None or capture.issued_at > datetime.fromisoformat(issued), 'pam_ledger_capture_regression')
                require(window_end is None or capture.window_end_us >= window_end, 'pam_ledger_window_regression')
                require(con.execute('SELECT count(*) FROM captures').fetchone()[0] < self.capacity,
                        'pam_ledger_capture_capacity')
                additions, duplicate_count = [], 0
                for record in capture.records:
                    event_id = digest(canonical([self.identity, capture.boot_id, record.cursor_sha256]))
                    body = event_body(capture, record)
                    existing = con.execute('SELECT body,sha FROM events WHERE id=?', (event_id,)).fetchone()
                    if existing:
                        require(existing == (body, digest(body)), 'pam_ledger_cursor_conflict')
                        duplicate_count += 1
                    else:
                        additions.append((event_id, body, digest(body), capture_sha))
                require(con.execute('SELECT count(*) FROM events').fetchone()[0]+len(additions) <= self.event_capacity,
                        'pam_ledger_event_capacity')
                new_count = len(additions)
                con.execute('INSERT INTO captures VALUES (?,?,?,?,?)',
                    (capture_sha, raw, now.astimezone(UTC).isoformat(), new_count, duplicate_count))
                con.executemany('INSERT INTO events VALUES (?,?,?,?)', additions)
                con.execute('UPDATE metadata SET issued=?,latest=?,window_end=? WHERE id=1',
                    (capture.issued_at.astimezone(UTC).isoformat(), capture_sha, capture.window_end_us))
            finished = clock() if real_clock else now
            require(finished >= now, 'pam_ledger_completion_clock')
            verify(capture, self.scope, pinned, boot=boot, invocation=invocation, now=finished)
            require(pinned.current(finished) == registry, 'pam_ledger_trust_changed')
            con.execute('UPDATE metadata SET checked=? WHERE id=1', (finished.astimezone(UTC).isoformat(),))
            total = con.execute('SELECT count(*) FROM events').fetchone()[0]
        return {'schema': 'zt-pam-observation-admission-1', 'completed': True,
            'capture_sha256': capture_sha, 'duplicate_capture': bool(old), 'new_events': new_count,
            'overlapping_events': duplicate_count, 'unique_events_retained': total,
            'original_window_start_us': capture.window_start_us, 'original_window_end_us': capture.window_end_us,
            'human_authenticated': False, 'authorization_asserted': False,
            'automatic_enforcement_allowed': False, 'goal_qualified': False}

    def inventory(self):
        """Hash-checked retained contents, never a statement of current freshness."""
        with self._connect() as con:
            return self._inventory(con)

    def _inventory(self, con):
        captures = list(con.execute('SELECT sha,body,admitted,new_events,duplicates FROM captures ORDER BY rowid'))
        events = list(con.execute('SELECT id,body,sha,first_capture FROM events ORDER BY id'))
        require(len(captures) <= self.capacity and len(events) <= self.event_capacity, 'pam_ledger_inventory_capacity')
        originals, expected, first_captures = {}, {}, {}
        last = None
        for capture_sha, body, admitted, new_count, duplicates in captures:
            require(type(body) is bytes and len(body) <= 4*1024**2 and digest(body) == capture_sha,
                    'pam_ledger_capture_inventory')
            capture = PamCapture.model_validate(decode(body))
            require(capture.scope.model_dump(mode='json', exclude={'key_id'}) == self.identity, 'pam_ledger_inventory_scope')
            originals[capture_sha] = capture
            admitted_at = datetime.fromisoformat(admitted)
            require(admitted_at.tzinfo is not None and admitted_at >= capture.issued_at
                and type(new_count) is int and type(duplicates) is int
                and new_count >= 0 and duplicates >= 0 and new_count+duplicates == len(capture.records),
                'pam_ledger_admission_inventory')
            if last is not None:
                require(capture.issued_at > last.issued_at and capture.window_end_us >= last.window_end_us,
                        'pam_ledger_sequence_inventory')
            original_count = len(expected)
            for record in capture.records:
                event_id = digest(canonical([self.identity, capture.boot_id, record.cursor_sha256]))
                value = event_body(capture, record)
                require(event_id not in expected or expected[event_id] == value, 'pam_ledger_inventory_conflict')
                first_captures.setdefault(event_id, capture_sha)
                expected[event_id] = value
            require(len(expected)-original_count == new_count, 'pam_ledger_duplicate_inventory')
            last = capture
        require(len(expected) == len(events), 'pam_ledger_inventory_population')
        for event_id, body, body_sha, first in events:
            require(first in originals and first_captures[event_id] == first and event_id in expected and expected[event_id] == body
                and digest(body) == body_sha, 'pam_ledger_event_inventory')
        checked, issued, latest, window_end = con.execute(
            'SELECT checked,issued,latest,window_end FROM metadata WHERE id=1').fetchone()
        if last is None:
            require((checked, issued, latest, window_end) == (None, None, None, None), 'pam_ledger_empty_metadata')
        else:
            require(latest == captures[-1][0] and issued == last.issued_at.astimezone(UTC).isoformat()
                and window_end == last.window_end_us and datetime.fromisoformat(checked) >= last.issued_at,
                'pam_ledger_latest_inventory')
        return {'schema': 'zt-pam-observation-inventory-1', 'completed': True,
            'captures': len(captures), 'unique_events': len(events), 'current_freshness_verified': False,
            'human_authenticated': False, 'authorization_asserted': False,
            'automatic_enforcement_allowed': False, 'goal_qualified': False}

    def checkpoint(self, expected_sha256=None):
        """Bind one locked historical inventory to an externally retained pin.

        This does not reverify current signing authority or freshness. The pin
        must be stored independently by the operator; keeping it beside this
        DB does not protect against an administrator rolling both back.
        """
        require(expected_sha256 is None or (type(expected_sha256) is str
            and re.fullmatch(r'[a-f0-9]{64}', expected_sha256)), 'pam_checkpoint_pin')
        with self._connect() as con:
            inventory = self._inventory(con)
            content = hashlib.sha256(b'zt-pam-observation-content-1\x00')

            def append(kind, row):
                encoded = canonical([kind, list(row)])
                content.update(len(encoded).to_bytes(8, 'big'))
                content.update(encoded)

            # Config binds logical source and capacity, independent of the
            # currently selected signer key_id. SHA fields cover validated raw
            # capture/event bodies; admission order and original times remain.
            append('config', [digest(self.config)])
            for row in con.execute('SELECT checked,issued,latest,window_end FROM metadata WHERE id=1'):
                append('metadata', row)
            for row in con.execute('SELECT sha,admitted,new_events,duplicates FROM captures ORDER BY rowid'):
                append('capture', row)
            for row in con.execute('SELECT id,sha,first_capture FROM events ORDER BY id'):
                append('event', row)
            result = {'schema': 'zt-pam-observation-checkpoint-1', 'completed': True,
                'configuration_sha256': digest(self.config), 'contents_sha256': content.hexdigest(),
                'captures': inventory['captures'], 'unique_events': inventory['unique_events'],
                'current_freshness_verified': False, 'human_authenticated': False,
                'authorization_asserted': False, 'automatic_enforcement_allowed': False,
                'goal_qualified': False}
            checkpoint_sha = digest(canonical(result))
            require(expected_sha256 is None or checkpoint_sha == expected_sha256,
                    'pam_checkpoint_mismatch')
        return {**result, 'checkpoint_sha256': checkpoint_sha,
                'external_pin_matched': expected_sha256 is not None}
