"""Local ASGI request capture into signed web facts and the durable ledger."""

import asyncio
import base64
import hashlib
import ipaddress
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from starlette.responses import JSONResponse

from app.config import get_settings
from app.security import Principal
from scripts.ca_recovery_state import atomic
from scripts.f1_lab.operation_context import canonical, core_features
from scripts.f1_lab.raw_semantics import semantic_observations
from scripts.f1_lab.web_durable_risk import DurableWebRisk
from scripts.f1_lab.web_evidence_ledger import require
from scripts.f1_lab.web_residual import build_evidence, encoded_argv_request
from scripts.f1_lab.web_verified_context import (
    Authentication,
    Authorization,
    Runtime,
    ServerProof,
    WebBundle,
    WebRequest,
    digest,
    digest_raw,
    proof_bytes,
)

STATE_KEY = 'secops_server_observation'


@dataclass(frozen=True)
class ServerObservation:
    principal: Principal | None
    session_id: str | None
    session_version: int | None
    resource_id: str | None
    authentication: Authentication
    authorization: Authorization | None
    runtime: Runtime | None
    execution_scope: str = 'local_fixed_fixture_only'


@dataclass(frozen=True)
class Capture:
    request_id: str
    method: str
    target_sha256: str
    raw_target: str | None = field(repr=False)
    body_sha256: str | None
    body_bytes: int
    body_complete: bool
    peer_ip: str | None
    status: int
    observed_at: datetime
    observation: ServerObservation | None
    capture_state: str


class RequestCaptureMiddleware:
    def __init__(self, app, sink, *, max_body_bytes=1048576, max_chunks=1024, receive_seconds=5.):
        require(get_settings().app_environment in {'local','test'},'web_capture_local_test_only')
        require(type(max_body_bytes) is int and 1 <= max_body_bytes <= 1048576
                and type(max_chunks) is int and 1 <= max_chunks <= 4096
                and type(receive_seconds) in {int,float} and .01 <= receive_seconds <= 30,
                'web_capture_limits')
        self.app,self.sink = app,sink
        self.max_body,self.max_chunks,self.seconds = max_body_bytes,max_chunks,receive_seconds

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            await self.app(scope,receive,send)
            return
        require(get_settings().app_environment in {'local','test'},'web_capture_local_test_only')
        request_id = secrets.token_hex(16)
        scope.setdefault('state',{})['secops_capture_id'] = request_id
        raw_path,query = scope.get('raw_path'),scope.get('query_string',b'')
        valid_target = isinstance(raw_path,bytes) and isinstance(query,bytes)
        raw = raw_path+(b'?'+query if query else b'') if valid_target else b''
        target = None
        try:
            if valid_target and 0 < len(raw) <= 16384:
                value = raw.decode('ascii')
                if value.startswith('/') and all(32 < ord(c) < 127 and c != '"' for c in value):
                    target = value
        except UnicodeError:
            pass
        peer = None
        try:
            peer = str(ipaddress.ip_address(scope['client'][0]))
        except (ValueError,TypeError,KeyError,IndexError):
            pass
        chunks,hashed,size,complete = [],hashlib.sha256(),0,False
        failure,status = 'complete',200
        try:
            async with asyncio.timeout(self.seconds):
                for _ in range(self.max_chunks):
                    message = await receive()
                    if not isinstance(message,dict):
                        failure,status = 'invalid_body_stream',400
                        break
                    if message['type'] == 'http.disconnect':
                        failure,status = 'disconnected',400
                        break
                    if (message['type'] != 'http.request' or not isinstance(message.get('body',b''),bytes)
                            or type(message.get('more_body',False)) is not bool):
                        failure,status = 'invalid_body_stream',400
                        break
                    body = message.get('body',b'')
                    size += len(body)
                    if size > self.max_body:
                        failure,status = 'body_limit',413
                        break
                    chunks.append({'type':'http.request','body':body,'more_body':bool(message.get('more_body',False))})
                    hashed.update(body)
                    if not message.get('more_body',False):
                        complete = True
                        break
                else:
                    failure,status = 'chunk_limit',413
        except TimeoutError:
            failure,status = 'body_timeout',408
        if target is None and complete:
            failure,status = 'invalid_raw_target',400
        delivered = False
        aborted = False
        def capture(code):
            context = scope['state'].get(STATE_KEY)
            return Capture(request_id,scope['method'],hashlib.sha256(raw).hexdigest(),target,
                hashed.hexdigest() if complete else None,size,complete,peer,code,datetime.now(UTC),
                context if isinstance(context,ServerObservation) else None,failure)
        async def unavailable():
            await JSONResponse({'detail':'Capture unavailable'},status_code=503)(scope,receive,send)
        if not complete or target is None:
            try:
                self.sink(capture(status))
            except (ValueError,OSError):
                await unavailable()
                return
            await JSONResponse({'detail':failure},status_code=status,
                headers={'X-Capture-Id':request_id})(scope,receive,send)
            return
        cursor = 0
        async def replay():
            nonlocal cursor
            if cursor < len(chunks):
                message = chunks[cursor]
                cursor += 1
                return message
            return await receive()
        async def observed_send(message):
            nonlocal delivered,aborted
            if aborted:
                return
            if message['type'] == 'http.response.start':
                require(not delivered,'web_capture_response_started_twice')
                try:
                    self.sink(capture(message['status']))
                except (ValueError,OSError):
                    aborted = True
                    await unavailable()
                    return
                delivered = True
                message = {**message,'headers':[(k,v) for k,v in message.get('headers',[])
                    if k.lower() != b'x-capture-id']+[(b'x-capture-id',request_id.encode())]}
            await send(message)
        try:
            await self.app(scope,replay,observed_send)
        except Exception:
            if delivered or aborted:
                raise
            failure = 'application_error'
            try:
                self.sink(capture(500))
            except (ValueError,OSError):
                await unavailable()
                return
            await JSONResponse({'detail':'Application failed'},status_code=500,
                headers={'X-Capture-Id':request_id})(scope,receive,send)


class WebCapturePipeline:
    """Single-process receipt spool. Authoritative risk remains in the ledger."""

    def __init__(self, model, operator, directory, *, server_id, keys, source_ids, max_records=1000):
        require(isinstance(model,DurableWebRisk) and type(max_records) is int and 1 <= max_records <= 1000
                and set(keys) == set(source_ids) == {'authentication','authorization','runtime'}
                and all(isinstance(k,Ed25519PrivateKey) for k in keys.values()),'web_capture_pipeline_config')
        directory = Path(directory)
        require(not directory.exists() and not directory.is_symlink(),'web_capture_fresh_spool')
        directory.mkdir(parents=True,mode=0o700)
        self.model,self.operator,self.directory,self.server_id = model,operator,directory,server_id
        self.keys,self.sources,self.maximum = dict(keys),dict(source_ids),max_records
        self.lock = RLock()
        self._requests = {}

    def request_for(self, request_id, principal):
        with self.lock:
            request = self._requests.get(request_id)
            require(request is not None,'web_capture_request_unavailable')
            self.model.verified.bridge._authorize(principal,request.tenant_id,self.operator.subject)
            return request.model_copy(deep=True)

    def __call__(self, value):
        require(get_settings().app_environment in {'local','test'} and isinstance(value,Capture),'web_capture_local_only')
        with self.lock:
            require(len(list(self.directory.iterdir())) < self.maximum,'web_capture_spool_capacity')
            require(len(value.request_id) == 32 and set(value.request_id) <= set('0123456789abcdef'), 'web_capture_id')
            record = {'schema':'zt-web-request-capture-1','request_id':value.request_id,'method':value.method,
                'target_sha256':value.target_sha256,'body_sha256':value.body_sha256,'body_bytes':value.body_bytes,
                'body_complete':value.body_complete,'status':value.status,'observed_at':value.observed_at.isoformat(),
                'capture_state':value.capture_state,'context_state':'unavailable','decision':None,
                'source_kind':'local_asgi_projection','independent_malicious_label':None}
            observation = value.observation
            request = None
            usable = (value.body_complete and value.raw_target is not None and value.peer_ip is not None
                and isinstance(observation,ServerObservation) and isinstance(observation.principal,Principal)
                and observation.session_id is not None and observation.session_version is not None
                and observation.resource_id is not None and observation.authorization is not None and observation.runtime is not None)
            if usable:
                # This is an explicit server projection, not a publisher's raw
                # log. '-' marks unavailable response bytes/referer/agent.
                moment = value.observed_at
                months = ('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec')
                stamp = f'{moment.day:02}/{months[moment.month-1]}/{moment.year}:{moment:%H:%M:%S} +0000'
                raw_line = f'{value.peer_ip} - - [{stamp}] "{value.method} {value.raw_target} HTTP/1.1" {value.status} - "-" "-"\n'
                record['identity_sha256'] = digest([observation.principal.tenant_id,observation.principal.subject,
                    observation.session_id,observation.session_version])
                record['execution_scope'] = observation.execution_scope
                if encoded_argv_request(raw_line):
                    evidence = next(iter(build_evidence([(1,None,raw_line)],'access',digest_raw(raw_line)).values()))
                    request = WebRequest(tenant_id=observation.principal.tenant_id,server_id=self.server_id,
                        request_id=value.request_id,case_id=evidence.case_id,subject_id=observation.principal.subject,
                        session_id=observation.session_id,session_version=observation.session_version,
                        resource_id=observation.resource_id,method=value.method,target_sha256=value.target_sha256,
                        body_sha256=value.body_sha256,raw_line_sha256=digest_raw(raw_line),observed_at=moment)
                    challenge = self.model.verified.bridge.issue(request,self.operator,now=moment)
                    proofs = []
                    for observed in (observation.authentication,observation.authorization,observation.runtime):
                        source,key_id = self.sources[observed.kind]
                        proof = ServerProof(schema_version='zt-web-server-proof-1',tenant_id=request.tenant_id,
                            source_id=source,key_id=key_id,request_sha256=challenge.sha256,observed_at=moment,
                            issued_at=moment,expires_at=moment+timedelta(seconds=30),observation=observed,signature='A'*86)
                        signature = base64.urlsafe_b64encode(self.keys[observed.kind].sign(proof_bytes(proof))).decode().rstrip('=')
                        proofs.append(proof.model_copy(update={'signature':signature}))
                    result = self.model.decide(request,{**core_features(raw_line),**semantic_observations(raw_line)},
                        request.case_id,evidence=evidence,nonce=challenge.nonce,bundle=WebBundle(proofs=proofs),
                        raw_line=raw_line,principal=self.operator,now=moment)
                    record['context_state'] = result.evidence_state
                    record['case_id'] = request.case_id
                    record['decision'] = {'score':result.score,'alert':result.alert,'review':result.review,
                        'verified_adverse':result.verified_adverse,'journal_head_sha256':result.journal_head_sha256}
                else:
                    record['context_state'] = 'outside_encoded_command_scope'
            path = self.directory/(value.request_id+'.json')
            require(not path.exists(),'web_capture_duplicate_server_id')
            atomic(path,canonical(record)+b'\n')
            path.chmod(0o600)
            if request is not None:
                self._requests[value.request_id] = request.model_copy(deep=True)
