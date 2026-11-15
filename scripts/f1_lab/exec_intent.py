"""Durable proposed execution and immutable completed bytes; never restart work.

A proposed intent is not authentication, authorization or proof of execution.
Without a complete original managed seal, reconciliation stays indeterminate.
"""

import base64
from datetime import UTC, datetime
from itertools import islice
from pathlib import Path
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, field_validator

from app.models import StrictModel
from scripts.f1_lab.capture_archive import MAX_SCAN
from scripts.f1_lab.capture_backup import fresh_file, private_directory, private_file, reserve
from scripts.f1_lab.capture_store import capture_store_lock
from scripts.f1_lab.collector_freshness import MAX_CAPTURE
from scripts.f1_lab.exec_outbox import bounded_entries, distinct
from scripts.f1_lab.managed_exec_capture import ManagedExecCapture, verify_managed
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.service_caller_identity import ServiceRequest
from scripts.f1_lab.shared_execution_evidence import digest
from scripts.f1_lab.web_verified_context import SHA, Identifier, Window, public_bytes


class ExecutionIntent(StrictModel):
    schema_version: Literal['zt-managed-exec-intent-1'] = 'zt-managed-exec-intent-1'
    request: ServiceRequest
    caller_registry_sha256: SHA
    service_registry_sha256: SHA
    proposed_caller_ref_sha256: SHA
    session_ref_sha256: SHA
    resource_id: Identifier
    action: Literal['READ']
    policy_sha256: SHA
    worker_directory: str = Field(min_length=1, max_length=4096)
    created_at: datetime
    signature: str = Field(pattern=r'^[A-Za-z0-9_-]{86}$', repr=False)

    @field_validator('created_at')
    @classmethod
    def aware(cls, value):
        return Window.aware(value)


def intent_bytes(intent):
    return canonical(intent.model_dump(mode='json', exclude={'signature'}))


def verify_intent(intent, service_pin, caller_pin, *, now):
    intent = ExecutionIntent.model_validate(intent.model_dump())
    Window.aware(now)
    caller, service = caller_pin.current(now), service_pin.current(now)
    require(intent.caller_registry_sha256 == caller_pin.sha256
            and intent.service_registry_sha256 == service_pin.expected_sha256
            and intent.policy_sha256 == service.policy_sha256
            and intent.request.issued_at <= intent.created_at < intent.request.expires_at
            and intent.created_at <= now
            and caller_pin.current(intent.created_at) == caller
            and service_pin.current(intent.created_at) == service,
            'exec_intent_trust_binding')
    signed = base64.urlsafe_b64decode(intent.signature+'==')
    require(base64.urlsafe_b64encode(signed).decode().rstrip('=') == intent.signature,
            'exec_intent_signature_encoding')
    Ed25519PublicKey.from_public_bytes(public_bytes(caller.broker_public_key)).verify(signed, intent_bytes(intent))
    require(caller_pin.current(now) == caller and service_pin.current(now) == service,
            'exec_intent_pin_changed')
    return intent


class ExecIntentJournal:
    def __init__(self, directory, service_pin, caller_pin):
        self.directory = private_directory(directory)
        self.service_pin, self.caller_pin = service_pin, caller_pin

    def load(self, request_id, *, now=None):
        now = datetime.now(UTC) if now is None else now
        require(isinstance(request_id, str) and len(request_id) == 32
                and set(request_id) <= set('0123456789abcdef'), 'exec_intent_request_id')
        run = private_directory(self.directory/request_id)
        require({p.name for p in islice(run.iterdir(),3)} <= {'intent.json','capture.json'}, 'exec_intent_run_inventory')
        intent = ExecutionIntent.model_validate(decode(private_file(run/'intent.json', MAX_CAPTURE)))
        require(intent.request.request_id == request_id, 'exec_intent_directory_binding')
        return verify_intent(intent, self.service_pin, self.caller_pin, now=now)

    def prepare(self, gate, launcher, root, outbox):
        from scripts.f1_lab.app_execution_gate import AppExecutionGate

        require(isinstance(gate, AppExecutionGate) and not gate.used, 'exec_intent_unused_gate')
        root, outbox, worker = [private_directory(p) for p in (root,outbox,launcher.directory)]
        distinct(self.directory, root, outbox, worker)
        now = datetime.now(UTC)
        caller = gate.broker.trust(now)
        require(gate.broker.registry.sha256 == self.caller_pin.sha256
                and gate.broker.joiner.registry.expected_sha256 == self.service_pin.expected_sha256,
                'exec_intent_gate_pins')
        intent = ExecutionIntent(
            request=gate.request, caller_registry_sha256=self.caller_pin.sha256,
            service_registry_sha256=self.service_pin.expected_sha256,
            proposed_caller_ref_sha256=digest([caller.issuer,gate.principal.tenant_id,gate.principal.subject]),
            session_ref_sha256=digest([gate.request.tenant_id,gate.access.session_id]),
            resource_id=gate.target.resource_id, action=gate.target.action,
            policy_sha256=gate.operations.policy_digest, worker_directory=str(worker),
            created_at=now, signature='A'*86)
        intent = intent.model_copy(update={'signature':base64.urlsafe_b64encode(
            gate.broker.key.sign(intent_bytes(intent))).decode().rstrip('=')})
        verify_intent(intent,self.service_pin,self.caller_pin,now=now)
        # No token/grant/argv is stored. An exclusive directory permanently
        # reserves the request; an interrupted partial write is not reusable.
        run = reserve(self.directory/gate.request.request_id, capacity=MAX_SCAN)
        fresh_file(run/'intent.json',canonical(intent.model_dump(mode='json'))+b'\n')
        return intent

    def complete(self, intent, raw, *, now=None):
        now = datetime.now(UTC) if now is None else now
        require(type(raw) is bytes and 0 < len(raw) <= MAX_CAPTURE, 'exec_intent_capture_bytes')
        with capture_store_lock(self.directory):
            stored = self.load(intent.request.request_id,now=now)
            require(stored == intent, 'exec_intent_original_changed')
            capture = verify_managed(ManagedExecCapture.model_validate(decode(raw)),
                                     self.service_pin,self.caller_pin,now=now)
            require(capture.request == intent.request
                    and capture.caller_receipt.caller_ref_sha256 == intent.proposed_caller_ref_sha256
                    and capture.app_use.session_ref_sha256 == intent.session_ref_sha256
                    and (capture.app_use.resource_id,capture.app_use.action,capture.app_use.policy_sha256)
                    == (intent.resource_id,intent.action,intent.policy_sha256)
                    and intent.created_at <= capture.event.observed_at <= capture.sealed_at,
                    'exec_intent_completed_binding')
            target = self.directory/intent.request.request_id/'capture.json'
            if target.exists() or target.is_symlink():
                require(private_file(target,MAX_CAPTURE) == raw, 'exec_intent_capture_collision')
            else:
                fresh_file(target,raw)
        return capture

    def reconcile(self, request_id, broker, operations, root, outbox, *, resume=False, now=None):
        """Read original app/broker/worker facts. Only sealed bytes can resume.

        No issue/authorize/dispatch/launch/access method is called. The request
        remains consumed/uncertain, and missing proof is never re-signed here.
        """
        from scripts.f1_lab.managed_exec_retention import publish_sealed

        now = datetime.now(UTC) if now is None else now
        require(type(resume) is bool, 'exec_intent_resume_flag')
        root, outbox = private_directory(root), private_directory(outbox)
        distinct(self.directory,root,outbox)
        with capture_store_lock(self.directory):
            intent = self.load(request_id,now=now)
            require(broker.registry.sha256 == self.caller_pin.sha256
                    and broker.joiner.registry.expected_sha256 == self.service_pin.expected_sha256
                    and operations.policy_digest == intent.policy_sha256, 'exec_intent_reconcile_pins')
            with broker.connect() as con:
                row = con.execute('SELECT body,state,receipt FROM requests WHERE id=?',(request_id,)).fetchone()
            require(row is not None and ServiceRequest.model_validate(decode(row[0].encode())) == intent.request
                    and row[1] in {'pending','launching','uncertain','bound'}, 'exec_intent_broker_binding')
            with operations._transaction() as (_,entries,_):
                linked = [e for e in entries if e['kind'] == 'access'
                          and e.get('execution_request_sha256') == intent.request.authentication_nonce]
            require(len(linked) <= 1, 'exec_intent_app_record_count')
            app = linked[0] if linked else None
            if app is not None:
                require(app['tenant_id'] == intent.request.tenant_id
                        and digest([self.caller_pin.current(now).issuer,app['tenant_id'],app['operator_id']])
                        == intent.proposed_caller_ref_sha256
                        and digest([app['tenant_id'],app['session_id']]) == intent.session_ref_sha256
                        and (app['resource_id'],app['action']) == (intent.resource_id,intent.action),
                        'exec_intent_app_scope')
            run = self.directory/request_id
            target = run/'capture.json'
            complete = target.exists() or target.is_symlink()
            report = {'completed':True,'state':'indeterminate','sealed_original_available':complete,
                      'broker_state':row[1], 'app_access_record_present':app is not None,
                      'app_grant_consumed':bool(app and app['allowed'] is True
                                                and app['reason_code'] == 'ACCESS_GRANTED'),
                      'publication_resumed':False,'automatic_execution_allowed':False,
                      'authorization_asserted':False,'command_reexecuted':False,'grant_refunded':False}
            if not complete:
                # File presence is only a reported artifact, not proof that a
                # command ran. Unknown/reused/missing worker bytes stay unknown.
                worker = private_directory(Path(intent.worker_directory))
                distinct(self.directory,root,outbox,worker)
                p = worker/'capture.json'
                report['worker_artifact_present'] = p.exists() or p.is_symlink()
                if report['worker_artifact_present']:
                    value = decode(private_file(p,16384))
                    require(value.get('request_sha256') == intent.request.authentication_nonce,
                            'exec_intent_worker_request')
                return report
            raw = private_file(target,MAX_CAPTURE)
            capture = verify_managed(ManagedExecCapture.model_validate(decode(raw)),
                                     self.service_pin,self.caller_pin,now=now)
            require(capture.request == intent.request and row[1] == 'bound'
                    and row[2] is not None and decode(row[2].encode()) == capture.caller_receipt.model_dump(mode='json')
                    and app is not None and report['app_grant_consumed']
                    and digest(app) == capture.app_use.access_record_sha256
                    and capture.app_use.session_ref_sha256 == intent.session_ref_sha256
                    and capture.app_use.session_version == app['session_version']
                    and (capture.app_use.resource_id,capture.app_use.action,capture.app_use.policy_sha256)
                    == (intent.resource_id,intent.action,intent.policy_sha256)
                    and intent.created_at <= capture.event.observed_at <= capture.sealed_at
                    and capture.caller_receipt.caller_ref_sha256 == intent.proposed_caller_ref_sha256,
                    'exec_intent_reconciliation_incomplete')
            report['state'] = 'sealed_original_verified'
            if resume:
                with capture_store_lock(outbox):
                    require(len(bounded_entries(outbox)) < MAX_SCAN, 'exec_intent_outbox_capacity')
                    pending = outbox/(request_id+'.json')
                    if pending.exists() or pending.is_symlink():
                        require(private_file(pending,MAX_CAPTURE) == raw, 'exec_intent_outbox_collision')
                    else:
                        fresh_file(pending,raw)
                publish_sealed(raw,root,self.service_pin,self.caller_pin,now=now)
                report['publication_resumed'] = True
            return report
