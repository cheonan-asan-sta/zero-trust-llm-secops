"""Typed, quiesced execution recovery snapshot. No keys, argv or activation.

The single-tenant app DB and single-unit broker DB are administrator-selected.
Cooperative intent/broker/app locks fence new dispatch. Any launching request
refuses the snapshot; a completed broker without a seal remains indeterminate.
"""

import base64
import os
import sqlite3
import tempfile
import time
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from app.services import policy_journal
from scripts.f1_lab.capture_archive import ArchiveScope
from scripts.f1_lab.capture_backup import private_directory, private_file, reader, sha
from scripts.f1_lab.capture_store import capture_store_lock
from scripts.f1_lab.collector_freshness import MAX_CAPTURE
from scripts.f1_lab.exec_intent import ExecutionIntent, verify_intent
from scripts.f1_lab.exec_recovery_inventory import intent_runs
from scripts.f1_lab.managed_exec_capture import ManagedExecCapture, verify_managed
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.service_caller_identity import CallerReceipt, ServiceRequest
from scripts.f1_lab.shared_execution_evidence import digest

MAX_DB = 16 * 1024**2
MAX_BODY = 64 * 1024**2
MAX_RUNS = 10000


def database_snapshot(con, path, validate, expected):
    raw = con.serialize()
    require(0 < len(raw) <= MAX_DB, 'exec_bundle_database_snapshot_bound')
    if raw[18:20] == b'\x02\x02':
        # An in-memory deserialize cannot use a serialized WAL-mode header.
        # A separate read connection can copy committed pages while the
        # original BEGIN IMMEDIATE fence prevents any writer. Let SQLite
        # produce a standalone DB rather than editing its header by hand.
        # Use a private, short-lived file copy: an in-memory pager may retain
        # the WAL header even after requesting MEMORY mode. Only this owned
        # copy changes journal mode; source configuration is untouched.
        with tempfile.TemporaryDirectory(prefix='zt-exec-bundle-copy-') as temporary:
            descriptor, name = tempfile.mkstemp(dir=temporary)
            os.close(descriptor)
            copied_path = Path(name)
            with reader(path=path) as source, closing(sqlite3.connect(copied_path)) as copy:
                require(source.execute('PRAGMA page_count').fetchone()[0]
                        * source.execute('PRAGMA page_size').fetchone()[0] <= MAX_DB,
                        'exec_bundle_database_page_bound')
                deadline = time.monotonic()+10

                def progress(_status, _remaining, _total):
                    require(time.monotonic() < deadline, 'exec_bundle_database_copy_deadline')

                source.backup(copy, pages=128, progress=progress, sleep=0.005)
                require(copy.execute('PRAGMA journal_mode=DELETE').fetchone() == ('delete',),
                        'exec_bundle_database_copy_standalone_mode')
                require(validate(copy) == expected, 'exec_bundle_database_logical_snapshot')
            raw = private_file(copied_path, MAX_DB)
    require(0 < len(raw) <= MAX_DB and raw[18:20] == b'\x01\x01',
            'exec_bundle_database_standalone_snapshot')
    return raw


def encoded(raw):
    return base64.b64encode(raw).decode('ascii')


def unencoded(value, maximum):
    require(type(value) is str and 0 < len(value) <= 4*((maximum+2)//3), 'exec_bundle_base64_bound')
    raw = base64.b64decode(value, validate=True)
    require(0 < len(raw) <= maximum and encoded(raw) == value, 'exec_bundle_base64_canonical')
    return raw


def database_shape(con, tables, indexes):
    require(con.execute('PRAGMA quick_check').fetchall() == [('ok',)], 'exec_bundle_database_integrity')
    inventory = con.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema').fetchall()
    require({r[1] for r in inventory if r[0] == 'table'} == tables
            and {r[1] for r in inventory if r[0] == 'index'} == indexes
            and all((kind == 'table' and name in tables and table == name
                     and type(sql) is str and sql.upper().startswith('CREATE TABLE '))
                    or (kind == 'index' and name in indexes and table in tables
                        and (sql is None or sql.upper().startswith('CREATE UNIQUE INDEX ')))
                    for kind, name, table, sql in inventory), 'exec_bundle_database_schema')


def app_state(con, limits, tenant):
    database_shape(con, {'journal', 'journal_archive_segments', 'journal_storage_metadata'},
                   {'sqlite_autoindex_journal_archive_segments_1',
                    'sqlite_autoindex_journal_archive_segments_2'})
    txn = policy_journal._load(con, limits)
    entries = txn[1]
    require(all((e.get('session') or e).get('tenant_id') == tenant for e in entries),
            'exec_bundle_single_tenant_app')
    return entries, txn[2]


def broker_state(con, scope):
    database_shape(con, {'requests', 'clock'}, {'sqlite_autoindex_requests_1', 'launching_scope'})
    require(con.execute('SELECT count(*) FROM requests').fetchone()[0] <= MAX_RUNS,
            'exec_bundle_broker_capacity')
    rows = con.execute('SELECT id,body,scope,state,receipt FROM requests ORDER BY id').fetchall()
    result = {}
    for rid, body, binding, state, receipt in rows:
        require(type(body) is str and len(body.encode()) <= MAX_CAPTURE
                and state in {'pending', 'launching', 'uncertain', 'bound'}, 'exec_bundle_broker_row')
        request = ServiceRequest.model_validate(decode(body.encode()))
        require(request.request_id == rid and binding == digest([scope.tenant_id, scope.server_id, scope.unit])
                and (request.tenant_id, request.server_id, request.unit)
                == (scope.tenant_id, scope.server_id, scope.unit), 'exec_bundle_single_unit_broker')
        require((state == 'bound') == (receipt is not None), 'exec_bundle_broker_receipt_state')
        if receipt is not None:
            require(type(receipt) is str and len(receipt.encode()) <= MAX_CAPTURE,
                    'exec_bundle_receipt_bound')
            CallerReceipt.model_validate(decode(receipt.encode()))
        result[rid] = (request, state, receipt)
    clocks = con.execute('SELECT singleton,observed FROM clock').fetchall()
    require(len(clocks) <= 1 and (not clocks or clocks[0][0] == 1), 'exec_bundle_broker_clock')
    if clocks:
        when = datetime.fromisoformat(clocks[0][1])
        require(when.tzinfo is not None and when.utcoffset().total_seconds() == 0,
                'exec_bundle_broker_clock_utc')
    return result


def completed_binding(intent, capture, row, entries, caller):
    request, state, receipt = row
    matches = [e for e in entries if e['kind'] == 'access'
               and e.get('execution_request_sha256') == request.authentication_nonce]
    require(len(matches) == 1, 'exec_bundle_access_count')
    app = matches[0]
    require(capture.request == request == intent.request and state == 'bound'
            and receipt is not None and decode(receipt.encode()) == capture.caller_receipt.model_dump(mode='json')
            and app['allowed'] is True and app['reason_code'] == 'ACCESS_GRANTED'
            and app['tenant_id'] == request.tenant_id
            and digest([caller.issuer, app['tenant_id'], app['operator_id']])
            == capture.caller_receipt.caller_ref_sha256 == intent.proposed_caller_ref_sha256
            and digest([app['tenant_id'], app['session_id']])
            == capture.app_use.session_ref_sha256 == intent.session_ref_sha256
            and digest(app) == capture.app_use.access_record_sha256
            and app['session_version'] == capture.app_use.session_version
            and (app['resource_id'], app['action']) == (intent.resource_id, intent.action)
            == (capture.app_use.resource_id, capture.app_use.action)
            and intent.policy_sha256 == capture.app_use.policy_sha256
            and intent.created_at <= capture.event.observed_at <= capture.sealed_at,
            'exec_bundle_completed_binding')


def take_snapshot(journal, broker, operations, scope, worker_directories):
    scope = ArchiveScope.model_validate(scope.model_dump())
    workers = {str(private_directory(p)) for p in worker_directories}
    require(0 < len(workers) <= 16, 'exec_bundle_worker_allowlist')
    intents = private_directory(journal.directory)
    for db in (broker.path, operations.path):
        private_directory(db.parent)
        private_file(db, MAX_DB)
    start = time.monotonic()
    service_pin, caller_pin = journal.service_pin, journal.caller_pin
    now = datetime.now(UTC)
    service, caller = service_pin.current(now), caller_pin.current(now)
    require(broker.registry.sha256 == caller_pin.sha256
            and broker.joiner.registry.expected_sha256 == service_pin.expected_sha256
            and operations.policy_digest == service.policy_sha256, 'exec_bundle_current_configuration')
    with capture_store_lock(intents), broker.connect() as con:
        con.execute('BEGIN IMMEDIATE')
        rows = broker_state(con, scope)
        require(not any(row[1] == 'launching' for row in rows.values()), 'exec_bundle_execution_in_flight')
        with operations._transaction() as transaction:
            # The cut time follows both DB fences, so prior lock contention
            # cannot give the snapshot a time older than included app state.
            now = datetime.now(UTC)
            require(service_pin.current(now) == service and caller_pin.current(now) == caller,
                    'exec_bundle_snapshot_cut_pins')
            entries, head = app_state(transaction[0], operations.journal_limits, scope.tenant_id)
            require(entries == transaction[1] and head == transaction[2], 'exec_bundle_app_snapshot_binding')
            app_raw = database_snapshot(transaction[0], operations.path,
                lambda candidate: app_state(candidate, operations.journal_limits, scope.tenant_id),
                (entries, head))
            broker_raw = database_snapshot(con, broker.path,
                lambda candidate: broker_state(candidate, scope), rows)
            require(0 < len(app_raw) <= MAX_DB and 0 < len(broker_raw) <= MAX_DB,
                    'exec_bundle_snapshot_database_bound')
            ids = intent_runs(intents)
            runs = []
            total = len(encoded(app_raw)) + len(encoded(broker_raw))
            for rid in ids:
                require(time.monotonic()-start < 20, 'exec_bundle_snapshot_deadline')
                intent = journal.load(rid, now=now)
                require(rid in rows and rows[rid][0] == intent.request
                        and intent.policy_sha256 == operations.policy_digest
                        and intent.worker_directory in workers, 'exec_bundle_request_snapshot_binding')
                run = intents/rid
                raw_intent = private_file(run/'intent.json', MAX_CAPTURE)
                target = run/'capture.json'
                raw = private_file(target, MAX_CAPTURE) if target.exists() or target.is_symlink() else None
                if raw is not None:
                    capture = verify_managed(ManagedExecCapture.model_validate(decode(raw)),
                                             service_pin, caller_pin, now=now)
                    require(capture.runtime_proof.source_id == scope.source_id,
                            'exec_bundle_capture_source')
                    completed_binding(intent, capture, rows[rid], entries, caller)
                worker = private_directory(intent.worker_directory)/'capture.json'
                observed = private_file(worker, 16384) if worker.exists() or worker.is_symlink() else None
                state = 'missing' if observed is None else 'present' if decode(observed).get(
                    'request_sha256') == intent.request.authentication_nonce else 'reused'
                record = {'id': rid, 'intent': encoded(raw_intent),
                          'capture': encoded(raw) if raw is not None else None,
                          'worker_state': state, 'worker': encoded(observed) if state == 'present' else None}
                total += len(canonical(record))
                require(total <= MAX_BODY-16384, 'exec_bundle_snapshot_body_bound')
                runs.append(record)
            require(intent_runs(intents) == ids and time.monotonic()-start < 20,
                    'exec_bundle_snapshot_inventory_changed')
            require(service_pin.current(datetime.now(UTC)) == service
                    and caller_pin.current(datetime.now(UTC)) == caller, 'exec_bundle_snapshot_pins_changed')
    value = {'schema': 'zt-exec-recovery-snapshot-1', 'scope': scope.model_dump(),
             'created_at': now.isoformat(), 'service_pin': service_pin.expected_sha256,
             'caller_pin': caller_pin.sha256, 'policy_sha256': operations.policy_digest,
             'app_limits': vars(operations.journal_limits), 'app_head': head,
             'app_entries': len(entries), 'app_database': encoded(app_raw),
             'broker_requests': len(rows), 'broker_database': encoded(broker_raw), 'runs': runs}
    raw = canonical(value)+b'\n'
    require(len(raw) <= MAX_BODY, 'exec_bundle_snapshot_final_bound')
    return raw


def validate_snapshot(raw, scope, service_pin, caller_pin, *, now=None):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BODY, 'exec_bundle_snapshot_bytes')
    real_clock = now is None
    now = datetime.now(UTC) if now is None else now
    value = decode(raw)
    require(type(value) is dict and set(value) == {'schema', 'scope', 'created_at', 'service_pin',
            'caller_pin', 'policy_sha256', 'app_limits', 'app_head', 'app_entries', 'app_database',
            'broker_requests', 'broker_database', 'runs'} and value['schema'] == 'zt-exec-recovery-snapshot-1'
            and value['scope'] == scope.model_dump() and value['service_pin'] == service_pin.expected_sha256
            and value['caller_pin'] == caller_pin.sha256, 'exec_bundle_snapshot_shape')
    when = datetime.fromisoformat(value['created_at'])
    require(when.tzinfo is not None and when.utcoffset().total_seconds() == 0 and when <= now,
            'exec_bundle_snapshot_time')
    service, caller = service_pin.current(now), caller_pin.current(now)
    require(value['policy_sha256'] == service.policy_sha256, 'exec_bundle_snapshot_policy')
    limits = policy_journal.JournalLimits(**value['app_limits'])
    app_raw, broker_raw = [unencoded(value[k+'_database'], MAX_DB) for k in ('app', 'broker')]
    with closing(sqlite3.connect(':memory:')) as app, closing(sqlite3.connect(':memory:')) as broker:
        app.deserialize(app_raw)
        broker.deserialize(broker_raw)
        entries, head = app_state(app, limits, scope.tenant_id)
        rows = broker_state(broker, scope)
    require(not any(row[1] == 'launching' for row in rows.values())
            and type(value['app_entries']) is int and value['app_entries'] == len(entries)
            and type(value['broker_requests']) is int and value['broker_requests'] == len(rows)
            and value['app_head'] == head, 'exec_bundle_snapshot_database_binding')
    require(type(value['runs']) is list and len(value['runs']) <= MAX_RUNS,
            'exec_bundle_snapshot_runs')
    verified, sealed, unknown, worker_present = [], 0, 0, 0
    for record in value['runs']:
        require(type(record) is dict and set(record) == {'id', 'intent', 'capture', 'worker_state', 'worker'}
                and record['worker_state'] in {'present', 'missing', 'reused'}, 'exec_bundle_snapshot_record')
        intent_raw = unencoded(record['intent'], MAX_CAPTURE)
        intent = verify_intent(ExecutionIntent.model_validate(decode(intent_raw)), service_pin, caller_pin, now=now)
        rid = record['id']
        require(rid == intent.request.request_id and rid in rows and rows[rid][0] == intent.request
                and (intent.request.tenant_id, intent.request.server_id, intent.request.unit)
                == (scope.tenant_id, scope.server_id, scope.unit)
                and intent.policy_sha256 == value['policy_sha256'], 'exec_bundle_snapshot_intent_binding')
        capture_raw = unencoded(record['capture'], MAX_CAPTURE) if record['capture'] is not None else None
        if capture_raw is None:
            unknown += 1
        else:
            capture = verify_managed(ManagedExecCapture.model_validate(decode(capture_raw)),
                                     service_pin, caller_pin, now=now)
            require(capture.runtime_proof.source_id == scope.source_id, 'exec_bundle_snapshot_capture_source')
            completed_binding(intent, capture, rows[rid], entries, caller)
            sealed += 1
        require((record['worker_state'] == 'present') == (record['worker'] is not None),
                'exec_bundle_snapshot_worker_state')
        worker_raw = unencoded(record['worker'], 16384) if record['worker'] is not None else None
        if worker_raw is not None:
            worker = decode(worker_raw)
            require(type(worker) is dict and set(worker) == {'request_sha256', 'event', 'proof', 'exit_code'}
                    and worker['request_sha256'] == intent.request.authentication_nonce,
                    'exec_bundle_snapshot_worker_binding')
            # Presence is not authorization or independent execution proof.
            worker_present += 1
        verified.append((rid, intent_raw, capture_raw, worker_raw))
    ids = [r[0] for r in verified]
    checked_at = datetime.now(UTC) if real_clock else now
    require(ids == sorted(set(ids)) and checked_at >= now and service_pin.current(checked_at) == service
            and caller_pin.current(checked_at) == caller, 'exec_bundle_snapshot_final_binding')
    return value, verified, app_raw, broker_raw, {'intents': len(ids), 'sealed': sealed,
        'indeterminate': unknown, 'worker_artifacts': worker_present, 'app_entries': len(entries),
        'broker_requests': len(rows), 'snapshot_sha256': sha(raw),
        'automatic_execution_allowed': False, 'authorization_asserted': False}
