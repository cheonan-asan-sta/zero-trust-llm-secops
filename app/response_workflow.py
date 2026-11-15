"""Local-only, two-person approval for immutable simulated response plans.

This ledger never calls an external responder or changes a Zero Trust session.
"""

import hashlib
import json
import sqlite3
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field

from app.models import AnalysisResult, StrictModel
from app.security import Principal, Role, require_roles


class PlanRequest(StrictModel):
    event_id: str = Field(min_length=1, max_length=128)
    analysis_id: str = Field(min_length=1, max_length=128)
    request_key: str = Field(pattern=r'^[a-zA-Z0-9._-]{1,128}$')


class TransitionRequest(StrictModel):
    expected_version: int = Field(ge=1)
    note: str = Field(min_length=3, max_length=500)


class WorkflowConflict(ValueError):
    pass


class ResponseWorkflow:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def transaction(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path, timeout=10)) as db, db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            application = db.execute('PRAGMA application_id').fetchone()[0]
            tables = {r[0] for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            if application == 0 and not tables:
                db.execute('PRAGMA application_id=1515475536')
            elif application != 1515475536 or tables != {'response_plans'}:
                raise sqlite3.DatabaseError('response ledger identity rejected')
            db.execute('CREATE TABLE IF NOT EXISTS response_plans ('
                       'tenant TEXT NOT NULL, id TEXT NOT NULL, request_key TEXT NOT NULL,'
                       'body TEXT NOT NULL, PRIMARY KEY(tenant,id), UNIQUE(tenant,request_key))')
            yield db

    @staticmethod
    def authorize(principal, role):
        if role not in principal.effective_roles:
            raise PermissionError('response role required')

    @staticmethod
    def load(db, tenant, ident):
        row = db.execute('SELECT body FROM response_plans WHERE tenant=? AND id=?',
                         (tenant, ident)).fetchone()
        if row is None:
            raise LookupError('plan missing')
        return json.loads(row[0])

    def create(self, record: AnalysisResult, request: PlanRequest, principal: Principal,
               *, now: float | None = None):
        self.authorize(principal, Role.ANALYST)
        if (record.tenant_id != principal.tenant_id or record.event_id != request.event_id
                or record.analysis_id != request.analysis_id):
            raise LookupError('analysis missing')
        decision = record.policy_decision
        if not decision.allowed or decision.action.value not in {
                'REQUIRE_MFA', 'REDUCE_PRIVILEGE', 'ISOLATE_SESSION', 'HOLD_FOR_REVIEW'}:
            raise WorkflowConflict('no approved simulation action')
        now = datetime.now(UTC).timestamp() if now is None else now
        binding = {'analysis_id': record.analysis_id, 'event_id': record.event_id,
                   'action': decision.action.value, 'assessment': record.assessment.model_dump(mode='json')}
        digest = hashlib.sha256(json.dumps(binding, sort_keys=True).encode()).hexdigest()
        with self.transaction() as db:
            old = db.execute('SELECT body FROM response_plans WHERE tenant=? AND request_key=?',
                             (principal.tenant_id, request.request_key)).fetchone()
            if old:
                plan = json.loads(old[0])
                if plan['binding_sha256'] != digest or plan['requested_by'] != principal.subject:
                    raise WorkflowConflict('request key conflict')
                return plan
            if db.execute('SELECT count(*) FROM response_plans').fetchone()[0] >= 10000:
                raise WorkflowConflict('ledger capacity reached')
            plan = {'id': uuid4().hex, 'tenant_id': principal.tenant_id, 'mode': 'simulation',
                    'event_id': record.event_id, 'analysis_id': record.analysis_id,
                    'action': decision.action.value, 'binding_sha256': digest,
                    'requested_by': principal.subject, 'approved_by': None, 'executed_by': None,
                    'state': 'PENDING', 'version': 1, 'expires_at': now + 300,
                    'history': [{'state': 'PENDING', 'actor': principal.subject, 'at': now}],
                    'result': None}
            db.execute('INSERT INTO response_plans VALUES (?,?,?,?)',
                       (principal.tenant_id, plan['id'], request.request_key, json.dumps(plan)))
            return plan

    def get(self, ident, principal):
        self.authorize(principal, Role.VIEWER)
        with self.transaction() as db:
            return self.load(db, principal.tenant_id, ident)

    def transition(self, ident, operation, request, principal, *, now=None):
        self.authorize(principal, Role.RESPONDER)
        now = datetime.now(UTC).timestamp() if now is None else now
        with self.transaction() as db:
            plan = self.load(db, principal.tenant_id, ident)
            # An exact executor retry returns its original receipt, even after expiry.
            if (operation == 'execute' and plan['state'] == 'SIMULATED'
                    and plan['executed_by'] == principal.subject
                    and request.expected_version == plan['version'] - 1
                    and request.note == plan['history'][-1]['note']):
                return plan
            if (now >= plan['expires_at'] or request.expected_version != plan['version']
                    or principal.subject == plan['requested_by']):
                raise WorkflowConflict('expired, stale or self-approved plan')
            if operation in {'approve', 'reject'} and plan['state'] == 'PENDING':
                plan['state'] = 'APPROVED' if operation == 'approve' else 'REJECTED'
                plan['approved_by'] = principal.subject if operation == 'approve' else None
            elif operation == 'execute' and plan['state'] == 'APPROVED':
                plan['state'] = 'SIMULATED'
                plan['executed_by'] = principal.subject
                plan['result'] = {'mode': 'simulation', 'external_calls': 0,
                                  'session_changes': 0, 'action': plan['action']}
            else:
                raise WorkflowConflict('invalid transition')
            plan['version'] += 1
            plan['history'].append({'state': plan['state'], 'actor': principal.subject,
                                    'at': now, 'note': request.note})
            db.execute('UPDATE response_plans SET body=? WHERE tenant=? AND id=?',
                       (json.dumps(plan), principal.tenant_id, ident))
            return plan


Analyst = Annotated[Principal, Depends(require_roles(Role.ANALYST))]
Responder = Annotated[Principal, Depends(require_roles(Role.RESPONDER))]
Viewer = Annotated[Principal, Depends(require_roles(Role.VIEWER))]


def response_router(settings, audit_store):
    router = APIRouter(prefix='/response/plans', tags=['local-response-approval'])
    service = ResponseWorkflow(settings.response_workflow_db_path)

    def call(fn, *args):
        if settings.app_environment == 'production':
            raise HTTPException(404, 'Local workflow unavailable')
        try:
            return fn(*args)
        except LookupError as exc:
            raise HTTPException(404, 'Plan or analysis not found') from exc
        except PermissionError as exc:
            raise HTTPException(403, 'Responder authority required') from exc
        except WorkflowConflict as exc:
            raise HTTPException(409, 'Plan state, scope, expiry or version conflict') from exc
        except (sqlite3.Error, OSError, ValueError, KeyError, TypeError) as exc:
            raise HTTPException(503, 'Response ledger unavailable') from exc

    @router.post('', status_code=201)
    def create(request: PlanRequest, principal: Analyst):
        if settings.app_environment == 'production':
            raise HTTPException(404, 'Local workflow unavailable')
        if audit_store.integrity().get('ok') is not True:
            raise HTTPException(503, 'Analysis evidence unavailable')
        record = audit_store.get(request.event_id, principal.tenant_id)
        if record is None:
            raise HTTPException(404, 'Analysis not found')
        return call(service.create, record, request, principal)

    @router.get('/{ident}')
    def get(ident: str, principal: Viewer):
        return call(service.get, ident, principal)

    @router.post('/{ident}/{operation}')
    def transition(ident: str, operation: str, request: TransitionRequest, principal: Responder):
        if operation not in {'approve', 'reject', 'execute'}:
            raise HTTPException(404, 'Unknown transition')
        return call(service.transition, ident, operation, request, principal)

    return router
